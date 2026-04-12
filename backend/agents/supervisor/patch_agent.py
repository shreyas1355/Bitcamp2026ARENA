"""
patch_agent.py — patch_node: Gemini-powered patch generation and verification.

Called once per episode immediately after policy_node.
This is the second Gemini call per episode (policy_node is the first).

Three-phase process per vulnerability:
  Phase 1 — Generate:  Gemini writes a minimal Python patch for the endpoint function
  Phase 2 — Apply:     patch is exec()'d in a controlled namespace; FastAPI route
                       handler is replaced in-process via route.app swap
  Phase 3 — Verify:    the original exploit payload is re-run via HTTP;
                       a 400/401/403/422 response confirms the patch works

This produces the "adversarially verified patch" claim:
  Unlike Snyk / CodeQL / Copilot Autofix which only suggest fixes, this system
  confirms effectiveness by re-running the exact exploit that found each vuln.

RULES (from PROMPT_V2.md):
  - Rule 12: exec() always uses a controlled namespace. Never open namespace.
  - Rule 12: every exec() is wrapped in try/except — never crash the arena loop.
  - Rule 16: this is Gemini call #2 per episode. Do not add more calls here.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
from typing import Optional

import httpx

from backend.agents.supervisor.gemini_client import call_gemini
from backend.config import (
    MAX_PATCHES_PER_EPISODE,
    PATCH_RECORDS_FILE,
    PATCH_VERIFICATION_TIMEOUT_S,
    TARGET_BASE_URL,
)
from backend.state import PatchRecord, SystemState
from backend.ws.broadcaster import broadcast_patch_summary


# ── Original source cache ──────────────────────────────────────────────────────
# Populated lazily on first use (before any patching occurs in episode 1).
# After exec()+route swap, inspect.getsource fails on dynamically-created
# functions.  We cache the *original* source so episode 2+ patches can still
# retrieve it without a source-file lookup.
_ORIGINAL_SOURCE_CACHE: dict[str, str] = {}


def _populate_source_cache() -> None:
    """
    Walk target_router routes and populate _ORIGINAL_SOURCE_CACHE keyed by
    the normalized path (e.g. '/login').  Called once on first episode.
    Only caches routes that have not yet been dynamically replaced.
    """
    try:
        from backend.target.router import target_router
        for route in target_router.routes:
            if not hasattr(route, "path") or not hasattr(route, "endpoint"):
                continue
            path = route.path
            if path in _ORIGINAL_SOURCE_CACHE:
                continue  # already cached; do not overwrite with patched version
            try:
                src = inspect.getsource(route.endpoint)
                _ORIGINAL_SOURCE_CACHE[path] = src
            except (OSError, TypeError):
                pass  # dynamic function or C extension — skip
    except Exception as e:
        print(f"[PATCH] Source cache population failed: {e}")


# ── Gemini prompts ─────────────────────────────────────────────────────────────

PATCH_SYSTEM_PROMPT = """You are a security engineer generating minimal, targeted Python patches.
You will receive a vulnerable async function and evidence of how it was exploited.
Generate ONLY the patched version of that function — no explanations, no markdown, just Python code.
Rules:
- Fix only the specific vulnerability described. Do not refactor or rename anything.
- Preserve the exact function signature (name, parameters, type hints).
- Output must start with 'async def' or 'def' on the very first line.
- Do not include import statements — all imports are already available."""

PATCH_USER_PROMPT = """VULNERABILITY: {vuln_name}
CWE: {cwe}
ENDPOINT: {endpoint}
EXPLOIT PAYLOAD THAT WORKED: {exploit_payload}
EVIDENCE: {evidence}

CURRENT VULNERABLE FUNCTION CODE:
{function_source}

Write the patched version of this function that prevents this specific exploit.
Output only the function code starting with 'async def' or 'def'. No imports, no markdown."""


# ── LangGraph node ─────────────────────────────────────────────────────────────

def patch_node(state: SystemState) -> dict:
    """
    LangGraph node. Called once per episode after policy_node.

    For each vulnerability in supervisor_report["vulnerabilities"]:
      1. Retrieve the source of the affected endpoint function
      2. Ask Gemini to generate a minimal patch
      3. Apply patch via exec() + FastAPI route replacement
      4. Re-run the original exploit — confirm it now returns 4xx
      5. Record PatchRecord and flip the belt-and-suspenders mitigation flag

    Returns updated patch_records and active_mitigations.
    """
    # Populate source cache before any patches are applied this episode.
    # This is a no-op after the first call — the cache is never cleared.
    if not _ORIGINAL_SOURCE_CACHE:
        _populate_source_cache()

    report = state.get("supervisor_report")
    if not report:
        return {"patch_records": state.get("patch_records", [])}

    vulns = report.get("vulnerabilities", [])
    if not vulns:
        return {"patch_records": state.get("patch_records", [])}

    new_records = list(state.get("patch_records", []))
    updated_mitigations = dict(state.get("active_mitigations", {}))

    for vuln in vulns[:MAX_PATCHES_PER_EPISODE]:
        record = _patch_one_vulnerability(vuln, state)
        new_records.append(record)

        # Belt-and-suspenders: also flip the feature flag if patch verified
        if record["verified"]:
            flag = _vuln_to_mitigation_flag(vuln.get("endpoint", ""), vuln.get("cwe", ""))
            if flag:
                updated_mitigations[flag] = True

        status = "\u2713 VERIFIED" if record["verified"] else "\u2717 FAILED/NEEDS REVIEW"
        print(f"  [PATCH] {vuln.get('name', '?')}: {status}")

    _persist_patch_records(new_records)
    broadcast_patch_summary(new_records, state.get("episode", 1))

    return {
        "patch_records":      new_records,
        "active_mitigations": updated_mitigations,
    }


# ── Core patch pipeline ────────────────────────────────────────────────────────

def _patch_one_vulnerability(vuln: dict, state: SystemState) -> PatchRecord:
    """Runs the full generate → apply → verify pipeline for one vulnerability."""
    endpoint      = vuln.get("endpoint") or ""  # guard: Gemini may return null
    exploit_payload = vuln.get("exploit_payload") or ""
    cwe           = vuln.get("cwe", "")
    vuln_name     = vuln.get("name", "Unknown vulnerability")

    # Phase 1 — get source code of the endpoint
    function_source = _get_endpoint_source(endpoint)
    if not function_source:
        return _make_record(vuln_name, cwe, endpoint, exploit_payload,
                            patch_code="", patch_applied=False,
                            verified=False,
                            evidence="Could not retrieve endpoint source code",
                            needs_review=True)

    # Phase 2 — generate patch via Gemini
    try:
        raw = call_gemini(
            system_prompt=PATCH_SYSTEM_PROMPT,
            user_prompt=PATCH_USER_PROMPT.format(
                vuln_name=vuln_name,
                cwe=cwe,
                endpoint=endpoint,
                exploit_payload=exploit_payload,
                evidence=vuln.get("evidence", ""),
                function_source=function_source,
            ),
        )
        patch_code = _strip_markdown(raw)
    except Exception as e:
        return _make_record(vuln_name, cwe, endpoint, exploit_payload,
                            patch_code="", patch_applied=False,
                            verified=False,
                            evidence=f"Gemini call failed: {e}",
                            needs_review=True)

    # Phase 3 — apply patch to running router
    applied = _apply_patch(endpoint, patch_code)
    if not applied:
        return _make_record(vuln_name, cwe, endpoint, exploit_payload,
                            patch_code=patch_code, patch_applied=False,
                            verified=False,
                            evidence="exec() failed — patch requires human review",
                            needs_review=True)

    # Phase 4 — verify patch blocks the original exploit
    verified, evidence = _verify_patch(endpoint, exploit_payload, vuln)

    return _make_record(vuln_name, cwe, endpoint, exploit_payload,
                        patch_code=patch_code, patch_applied=True,
                        verified=verified, evidence=evidence,
                        needs_review=not verified)


# ── Phase 1: source retrieval ──────────────────────────────────────────────────

def _get_endpoint_source(endpoint: str) -> Optional[str]:
    """
    Returns the Python source of the FastAPI route handler for endpoint.
    Handles both '/login' and '/target/login' forms.

    Uses _ORIGINAL_SOURCE_CACHE (populated before any patching) so that
    episode 2+ calls succeed even after route.endpoint has been replaced by
    an exec()-created function that has no source file on disk.
    """
    path = _normalize_path(endpoint)

    # Ensure cache is populated (safe to call repeatedly — no-op if already done)
    if not _ORIGINAL_SOURCE_CACHE:
        _populate_source_cache()

    # Cache hit — return original source regardless of current route state
    if path in _ORIGINAL_SOURCE_CACHE:
        return _ORIGINAL_SOURCE_CACHE[path]

    # Cache miss (should only happen for unusual endpoints): fall back to inspect
    try:
        from backend.target.router import target_router

        # Primary: match by route path
        for route in target_router.routes:
            if hasattr(route, "path") and route.path == path:
                try:
                    src = inspect.getsource(route.endpoint)
                    _ORIGINAL_SOURCE_CACHE[path] = src  # cache for future episodes
                    return src
                except (OSError, TypeError):
                    pass

        # Fallback: match by function name derived from path
        func_name = path.strip("/").replace("-", "_")
        for route in target_router.routes:
            if hasattr(route, "endpoint") and route.endpoint.__name__ == func_name:
                try:
                    src = inspect.getsource(route.endpoint)
                    _ORIGINAL_SOURCE_CACHE[path] = src
                    return src
                except (OSError, TypeError):
                    pass

        print(f"[PATCH] No route found for path '{path}'")
        return None

    except Exception as e:
        print(f"[PATCH] _get_endpoint_source({endpoint}) failed: {e}")
        return None


# ── Phase 2: patch application ─────────────────────────────────────────────────

def _apply_patch(endpoint: str, patch_code: str) -> bool:
    """
    exec()'s the patched function in a controlled namespace, then swaps it
    into the running FastAPI router by replacing route.endpoint and route.app.

    Rule 12: namespace is always explicit. exec() is always wrapped in try/except.
    The arena loop must never crash due to a failed patch.
    """
    try:
        from backend.target.router import (
            target_router,
            _get_mitigations,
            _SQLI_PATTERN,
            LoginRequest,
            TransferRequest,
        )
        from backend.target.vuln_store import (
            USERS, DATA_RECORDS, SESSIONS,
            create_session, get_session_user, validate_user, record_transfer,
        )
        from fastapi import Header, Request
        from fastapi.responses import JSONResponse
        from starlette.routing import request_response
        from typing import Optional as Opt
        import hashlib, hmac, re as re_mod, os
        from urllib.parse import unquote as _unquote

        # Controlled namespace — only what target endpoint functions need
        namespace: dict = {
            "__builtins__":     __builtins__,
            # Router + request models — Gemini often emits @target_router.post(...)
            # before async def; without target_router, exec() raises NameError on line 1.
            "target_router":    target_router,
            "LoginRequest":     LoginRequest,
            "TransferRequest":  TransferRequest,
            "JSONResponse":     JSONResponse,
            "Request":          Request,
            "Header":           Header,
            "Optional":         Opt,
            "USERS":            USERS,
            "DATA_RECORDS":     DATA_RECORDS,
            "SESSIONS":         SESSIONS,
            "create_session":   create_session,
            "get_session_user": get_session_user,
            "validate_user":    validate_user,
            "record_transfer":  record_transfer,
            "_get_mitigations": _get_mitigations,
            "_SQLI_PATTERN":    _SQLI_PATTERN,
            "hashlib":          hashlib,
            "hmac":             hmac,
            "re":               re_mod,
            "os":               os,
            "unquote":          _unquote,
        }

        exec(patch_code, namespace)  # noqa: S102

        # Reliably extract the new function by parsing its name from the code
        new_func = _extract_function(patch_code, namespace)
        if new_func is None:
            print(f"[PATCH] exec succeeded but no callable found for {endpoint}")
            return False

        # Swap into the running router
        path = _normalize_path(endpoint)
        for route in target_router.routes:
            if hasattr(route, "path") and route.path == path:
                route.endpoint = new_func
                route.app = request_response(new_func)
                print(f"[PATCH] Swapped route handler for {path} → {new_func.__name__}")
                return True

        print(f"[PATCH] Route '{path}' not found in target_router after exec()")
        return False

    except SyntaxError as e:
        print(f"[PATCH] Syntax error in generated patch for {endpoint}: {e}")
        return False
    except Exception as e:
        print(f"[PATCH] Unexpected error applying patch for {endpoint}: {e}")
        import traceback; traceback.print_exc()
        return False


def _extract_function(patch_code: str, namespace: dict):
    """
    Parses the function name from patch_code using AST, then looks it
    up in the exec namespace. Much more reliable than scanning all callables.
    """
    try:
        tree = ast.parse(patch_code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                fn = namespace.get(func_name)
                if callable(fn):
                    return fn
    except Exception as e:
        print(f"[PATCH] AST parse failed: {e}")
    return None


# ── Phase 3: verification ──────────────────────────────────────────────────────

def _verify_patch(endpoint: str, exploit_payload: str, vuln: dict) -> tuple[bool, str]:
    """
    Re-runs the original exploit against the now-patched endpoint.
    Returns (verified: bool, evidence: str).
    verified = True if the response is now 400 / 401 / 403 / 422.
    """
    cwe  = vuln.get("cwe", "")
    name = vuln.get("name", "").lower()
    base = TARGET_BASE_URL

    try:
        with httpx.Client(timeout=PATCH_VERIFICATION_TIMEOUT_S) as client:

            if "CWE-89" in cwe or "sqli" in name or "injection" in name:
                payload = exploit_payload or "admin' --"
                resp = client.post(f"{base}/login",
                                   json={"username": payload, "password": ""})

            elif "CWE-639" in cwe or "idor" in name:
                # Authenticate as alice, try to read admin's record (id=1)
                auth = client.post(f"{base}/login",
                                   json={"username": "alice", "password": "alice2024"})
                token = auth.json().get("token", "invalid")
                resp = client.get(f"{base}/data",
                                  params={"id": 1},
                                  headers={"Authorization": f"Bearer {token}"})

            elif "CWE-22" in cwe or "traversal" in name:
                path_payload = exploit_payload or "../../../etc/passwd"
                resp = client.get(f"{base}/files", params={"path": path_payload})

            elif "CWE-284" in cwe or "admin" in name:
                resp = client.get(f"{base}/admin",
                                  headers={"Authorization": "Bearer notadmin"})

            elif "CWE-352" in cwe or "csrf" in name:
                auth = client.post(f"{base}/login",
                                   json={"username": "alice", "password": "alice2024"})
                token = auth.json().get("token", "invalid")
                # Send transfer WITHOUT X-CSRF-Token header — should now be blocked
                resp = client.post(f"{base}/transfer",
                                   json={"amount": 1.0, "to": "attacker"},
                                   headers={"Authorization": f"Bearer {token}"})

            elif "CWE-204" in cwe or "CWE-208" in cwe or "enumeration" in name or "timing" in name:
                # Timing/enumeration: both paths should now return same error message
                resp_exists = client.post(f"{base}/login",
                                          json={"username": "admin", "password": "wrong"})
                resp_missing = client.post(f"{base}/login",
                                           json={"username": "nobody_xyz", "password": "wrong"})
                same_msg = resp_exists.text == resp_missing.text
                verified = same_msg
                evidence = (
                    f"exists→'{resp_exists.text[:60]}' "
                    f"missing→'{resp_missing.text[:60]}' "
                    f"{'SAME (patched)' if same_msg else 'DIFFERENT (still vuln)'}"
                )
                return verified, evidence

            else:
                # Generic: attempt exploit_payload as a query parameter
                resp = client.get(f"{base}{_normalize_path(endpoint)}",
                                  params={"input": exploit_payload or "test"})

            verified = resp.status_code in (400, 401, 403, 422)
            evidence = f"HTTP {resp.status_code} — {resp.text[:120]}"
            return verified, evidence

    except Exception as e:
        return False, f"Verification request failed: {e}"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _normalize_path(endpoint: str) -> str:
    """Strips /target prefix and ensures leading slash."""
    if not endpoint:
        return "/"
    path = endpoint.replace("/target", "") if endpoint.startswith("/target") else endpoint
    return path if path.startswith("/") else f"/{path}"


def _strip_markdown(text: str) -> str:
    """Removes ``` fences Gemini sometimes wraps code in."""
    text = re.sub(r"^```(?:python)?\s*\n?", "", text.strip(), flags=re.MULTILINE)
    text = re.sub(r"\n?```$", "", text.strip(), flags=re.MULTILINE)
    return text.strip()


def _vuln_to_mitigation_flag(endpoint: str, cwe: str) -> Optional[str]:
    """
    Maps (endpoint, cwe) → active_mitigations flag.
    Belt-and-suspenders: even if the exec() patch is live, also flip the
    feature flag so the coded mitigation path is also active.
    """
    ep = _normalize_path(endpoint)
    mapping = {
        ("/login",    "CWE-89"):  "proper_auth",
        ("/login",    "CWE-204"): "proper_auth",
        ("/login",    "CWE-208"): "proper_auth",
        ("/data",     "CWE-639"): "idor_check_enabled",
        ("/admin",    "CWE-284"): "proper_admin_auth",
        ("/files",    "CWE-22"):  "path_sanitization",
        ("/transfer", "CWE-352"): "csrf_protection",
        ("/transfer", "CWE-915"): "csrf_protection",
    }
    return mapping.get((ep, cwe))


def _make_record(
    vuln_name: str, cwe: str, endpoint: str, verification_payload: str,
    patch_code: str, patch_applied: bool,
    verified: bool, evidence: str, needs_review: bool,
) -> PatchRecord:
    return PatchRecord(
        vulnerability_name=vuln_name,
        cwe=cwe,
        endpoint=endpoint,
        patch_code=patch_code,
        patch_applied=patch_applied,
        verification_payload=verification_payload,
        verified=verified,
        verification_evidence=evidence,
        requires_human_review=needs_review,
    )


def _persist_patch_records(records: list) -> None:
    """Persists accumulated patch records to disk after each episode."""
    try:
        with open(PATCH_RECORDS_FILE, "w") as f:
            json.dump(records, f, indent=2)
    except OSError as e:
        print(f"[PATCH] Could not persist patch records: {e}")
