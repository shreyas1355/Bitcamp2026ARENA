"""
router.py — Vulnerable FastAPI target application endpoints.

TODO (Dev B, Phase 1): Implement all endpoints with their vulnerabilities.
TODO (Dev B, Phase 4): Add active_mitigations feature flag checks.

See PROMPT.md Section 8.1 for vulnerability specifications per endpoint.

Endpoints:
  POST /login      SQLi, username enumeration, timing side channel, no rate limit
  GET  /data       IDOR (no ownership check)
  GET  /admin      Weak token check (substring match)
  POST /transfer   No CSRF, no re-auth, mass assignment
  GET  /files      Path traversal
"""

import hmac
import re
from urllib.parse import unquote

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from backend.target.vuln_store import (
    USERS, DATA_RECORDS, SESSIONS,
    create_session, get_session_user, validate_user, record_transfer,
)

# Matches the same pattern as anomaly_detector.SQLI_REGEX so detection and
# exploitation are consistent — both sides see the same attack surface.
_SQLI_PATTERN = re.compile(
    r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b"
    r"|\bINSERT\b|\bDELETE\b|\bUPDATE\b|1=1|1%3d1|sleep\s*\()",
    re.IGNORECASE,
)

target_router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    amount: float
    to: str
    # NOTE: intentionally accepts extra fields (mass assignment vuln)
    class Config:
        extra = "allow"


# ── Helper to read active_mitigations from shared state ───────────────────────

def _get_mitigations() -> dict:
    """
    Reads active_mitigations from the shared SYSTEM_STATE singleton.
    Import here (not at module level) to avoid circular imports.
    """
    try:
        from backend.main import SYSTEM_STATE
        return SYSTEM_STATE.get("active_mitigations", {})
    except ImportError:
        return {}


# ── Endpoints ──────────────────────────────────────────────────────────────────

@target_router.post("/login")
async def login(body: LoginRequest, request: Request):
    """
    POST /login — Authentication endpoint with three deliberate vulnerabilities.

    VULNERABILITY 1 — SQL Injection simulation (CWE-89):
      Username field is "interpolated" without sanitization. If it contains
      SQL metacharacters, the auth check is bypassed and an admin token is
      returned. Active when proper_auth == False.

    VULNERABILITY 2 — Username enumeration (CWE-204):
      Different error messages reveal whether a username exists:
        existing user + wrong password → "Invalid password"
        non-existent user             → "User not found"

    VULNERABILITY 3 — Timing side channel (CWE-208):
      validate_user() (password comparison) is only called for real users.
      For non-existent users the endpoint returns immediately — measurably
      faster, allowing enumeration via response time.

    PATCHED (proper_auth == True):
      Constant-time comparison via hmac.compare_digest, dummy hash evaluated
      even for non-existent users, single generic error message.
    """
    mitigations = _get_mitigations()

    if mitigations.get("proper_auth"):
        # ── PATCHED path ──────────────────────────────────────────────────────
        user = USERS.get(body.username)
        # Always compute comparison to prevent timing side channel (CWE-208)
        stored_pw = user["password"] if user else "dummy_password_for_timing__"
        password_match = hmac.compare_digest(stored_pw, body.password)
        if user and password_match:
            token = create_session(body.username)
            return {"token": token, "role": user["role"]}
        return JSONResponse(status_code=401, content={"error": "Authentication failed"})

    # ── VULNERABLE path ───────────────────────────────────────────────────────

    # VULNERABILITY 1 — SQLi: forged admin session on injection payload
    if _SQLI_PATTERN.search(body.username) or _SQLI_PATTERN.search(body.password):
        token = create_session("admin")
        return {"token": token, "role": "admin"}

    # VULNERABILITY 3 — Timing: only look up real users (early return for unknown)
    user = USERS.get(body.username)
    if not user:
        # VULNERABILITY 2 — Enumeration: reveals username does not exist
        return JSONResponse(status_code=401, content={"error": "User not found"})

    if user["password"] != body.password:
        # VULNERABILITY 2 — Enumeration: reveals username exists but password wrong
        return JSONResponse(status_code=401, content={"error": "Invalid password"})

    token = create_session(body.username)
    return {"token": token, "role": user["role"]}


@target_router.get("/data")
async def get_data(id: int, request: Request, authorization: Optional[str] = Header(None)):
    """
    GET /data?id=N — Data retrieval with IDOR vulnerability (CWE-639).

    VULNERABILITY — Insecure Direct Object Reference:
      Returns DATA_RECORDS[id] with no ownership check. Any authenticated
      (or even unauthenticated) user can enumerate all records by incrementing id.

    PATCHED (idor_check_enabled == True):
      Validates that the authenticated user owns the record or has admin role.
      Returns 401 if no valid session, 403 if record belongs to another user.
    """
    mitigations = _get_mitigations()
    record = DATA_RECORDS.get(id)
    if not record:
        return JSONResponse(status_code=404, content={"error": "Not found"})

    if mitigations.get("idor_check_enabled"):
        # ── PATCHED path ──────────────────────────────────────────────────────
        token = (authorization or "").replace("Bearer ", "")
        current_user = get_session_user(token)
        if not current_user:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        is_admin = USERS.get(current_user, {}).get("role") == "admin"
        if record["owner"] != current_user and not is_admin:
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

    # VULNERABLE path: return record regardless of who is asking
    return record


@target_router.get("/admin")
async def admin_panel(request: Request, authorization: Optional[str] = Header(None)):
    """
    GET /admin — Admin panel with weak token validation vulnerability (CWE-284).

    VULNERABILITY — Substring token check:
      Any token containing the string "admin" passes the check.
      Trivially bypassed with tokens like "notadmin", "xadminx", "ADMIN".

    PATCHED (proper_admin_auth == True):
      Validates token against the SESSIONS store and checks role == "admin".
      Only a token returned by a real admin login will pass.
    """
    token = (authorization or "").replace("Bearer ", "")
    mitigations = _get_mitigations()

    if mitigations.get("proper_admin_auth"):
        # ── PATCHED path ──────────────────────────────────────────────────────
        user = get_session_user(token)
        if not user or USERS.get(user, {}).get("role") != "admin":
            return JSONResponse(status_code=403, content={"error": "Forbidden"})
    else:
        # ── VULNERABLE path: substring check ─────────────────────────────────
        if "admin" not in token.lower():
            return JSONResponse(status_code=403, content={"error": "Forbidden"})

    return {"panel": "admin", "users": list(USERS.keys()), "sessions": len(SESSIONS)}


@target_router.post("/transfer")
async def transfer(body: TransferRequest, request: Request, authorization: Optional[str] = Header(None)):
    """
    POST /transfer — Fund transfer with three deliberate vulnerabilities.

    VULNERABILITY 1 — No CSRF protection (CWE-352):
      No X-CSRF-Token required. Any cross-origin request that includes a valid
      session cookie/token can trigger a transfer.

    VULNERABILITY 2 — No re-authentication (CWE-306):
      Sensitive fund transfer executes with only the existing session token —
      no password confirmation required.

    VULNERABILITY 3 — Mass assignment (CWE-915):
      TransferRequest model uses Config extra="allow", so extra fields like
      {"is_admin": true, "role": "admin"} are silently accepted and stored
      in the transfer record.

    PATCHED (csrf_protection == True):
      Requires X-CSRF-Token header matching a per-session server-side value.
    """
    token = (authorization or "").replace("Bearer ", "")
    user = get_session_user(token)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})

    mitigations = _get_mitigations()
    if mitigations.get("csrf_protection"):
        # ── PATCHED path ──────────────────────────────────────────────────────
        csrf_header = request.headers.get("X-CSRF-Token", "")
        # Server-side CSRF token is the session token hashed with a secret
        import hashlib
        expected = hashlib.sha256(f"csrf:{token}".encode()).hexdigest()[:32]
        if not hmac.compare_digest(csrf_header, expected):
            return JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"})

    # VULNERABILITY 3 — mass assignment: model_extra fields are silently accepted
    extra_fields = body.model_extra if hasattr(body, "model_extra") else {}
    result = record_transfer(user, body.to, body.amount)

    return {
        "transfer":    result,
        "status":      "completed",
        "extra_accepted": list(extra_fields.keys()) if extra_fields else [],
    }


@target_router.get("/files")
async def get_file(path: str, request: Request):
    """
    GET /files?path=<filename> — File retrieval with path traversal (CWE-22).

    VULNERABILITY — No path sanitization:
      The path parameter is used directly without normalization or validation.
      Traversal sequences (../, %2e%2e/, double-encoded %252e%252e/) all succeed,
      returning simulated /etc/passwd content to confirm exploitation.

    PATCHED (path_sanitization == True):
      os.path.basename() strips all directory components.
      An explicit allowlist rejects anything not in {readme.txt, about.txt, help.txt}.
    """
    import os
    mitigations = _get_mitigations()

    if mitigations.get("path_sanitization"):
        # ── PATCHED path ──────────────────────────────────────────────────────
        safe_path = os.path.basename(path)
        allowed = {"readme.txt", "about.txt", "help.txt"}
        if safe_path not in allowed:
            return JSONResponse(status_code=403, content={"error": "Forbidden"})
        path = safe_path

    # ── VULNERABLE path ───────────────────────────────────────────────────────
    # Normalize any URL encoding to detect traversal (simulates server decode)
    normalized = path
    for _ in range(3):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded

    # If traversal sequences present after normalization → return passwd content
    _PASSWD_CONTENT = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
    )

    _ALLOWED_FILES = {
        "readme.txt": "Welcome to CorpApp v1.0",
        "about.txt":  "CorpApp internal application. All rights reserved.",
        "help.txt":   "Contact support@corp.internal for assistance.",
    }

    if ".." in normalized or "etc/passwd" in normalized or "etc\\passwd" in normalized:
        return {"path": path, "content": _PASSWD_CONTENT}

    content = _ALLOWED_FILES.get(os.path.basename(normalized), "File not found")
    return {"path": path, "content": content}
