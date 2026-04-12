"""
responder.py — Blue team mitigation executor.

See .cursorrules §8.3 (V2). Applies mitigations for every finding (de-duplicated
mutations), returns a DefenseEvent for the highest-severity finding (pipeline
order breaks ties).
"""

import time
from typing import Any, Dict, List, Optional

from backend.state import SystemState, Finding
from backend.config import (
    RATE_LIMIT_LOGIN_HIGH,
    RATE_LIMIT_LOGIN_STUFFING,
    RATE_LIMIT_FLOOD,
)

# rule_id → active_mitigations key (patch_endpoint)
PATCH_MAP = {
    "RULE_SEQUENTIAL_IDOR": "idor_check_enabled",
    "RULE_ADMIN_PROBING": "proper_admin_auth",
    "RULE_TIME_BASED_SQLI": "proper_auth",
    "RULE_SQLI_SIGNATURE": "proper_auth",
    "RULE_SQLI_ENCODED": "proper_auth",
}

# rule_id → req/min for rate_limit
RATE_LIMIT_MAP = {
    "RULE_HIGH_LOGIN_RATE": RATE_LIMIT_LOGIN_HIGH,
    "RULE_CREDENTIAL_STUFFING": RATE_LIMIT_LOGIN_STUFFING,
    "RULE_ENDPOINT_FLOOD": RATE_LIMIT_FLOOD,
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _rate_limit_endpoint_key(path: str) -> str:
    """
    Must match backend.target.middleware: dict keys are the first segment
    after /target (e.g. /target/login → /login), not full paths.
    """
    if not path:
        return "/login"
    if "/target/" in path:
        seg = path.split("/target/", 1)[-1].split("/")[0]
        return "/" + seg if seg else path
    return path


def _defense_none() -> dict:
    return {
        "action": "none",
        "trigger_rule": "",
        "target_ip": "",
        "target_endpoint": "",
        "timestamp": time.time(),
    }


def _defense_event(
    action: str,
    trigger_rule: str,
    target_ip: str,
    target_endpoint: str,
    ts: float,
) -> dict:
    return {
        "action": action,
        "trigger_rule": trigger_rule,
        "target_ip": target_ip,
        "target_endpoint": target_endpoint,
        "timestamp": ts,
    }


def _append_ioc_from_evidence(state: SystemState, evidence: Dict[str, Any]) -> None:
    if not evidence:
        return
    exports = state.setdefault("ioc_exports", [])
    entry = evidence.get("ioc_export")
    if isinstance(entry, dict) and entry:
        exports.append(entry)
        return
    if evidence.get("pattern"):
        exports.append(
            {
                "pattern": evidence["pattern"],
                "type": evidence.get("type", "sqli_encoded"),
                "description": evidence.get("description", ""),
                "kb_entry": evidence.get("kb_entry") or {},
            }
        )


def _append_behavioral_fingerprint(state: SystemState, evidence: Dict[str, Any]) -> None:
    fp = evidence.get("behavioral_fingerprint")
    if isinstance(fp, dict) and fp:
        state.setdefault("behavioral_fingerprints", []).append(fp)


def _ensure_deep_logging_ips(state: SystemState) -> List[str]:
    """IPs flagged by deep_log_attacker; middleware reads SYSTEM_STATE['deep_logging_ips']."""
    return state.setdefault("deep_logging_ips", [])


def _apply_finding(finding: Finding, state: SystemState, ts: float) -> Optional[dict]:
    rule_id = finding.get("rule_id", "")
    action = finding.get("recommended_action", "")
    evidence = finding.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    src_ip = finding.get("source_ip") or ""
    target_ep = finding.get("target_endpoint") or ""

    if action == "block_and_patch" and rule_id == "RULE_TIME_BASED_SQLI":
        if src_ip and src_ip not in state["blocked_ips"]:
            state["blocked_ips"].append(src_ip)
        state["active_mitigations"]["proper_auth"] = True
        return _defense_event(
            "patch_endpoint",
            rule_id,
            src_ip,
            target_ep or "/target/login",
            ts,
        )

    if action == "fingerprint_and_block":
        if src_ip and src_ip not in state["blocked_ips"]:
            state["blocked_ips"].append(src_ip)
        _append_behavioral_fingerprint(state, evidence)
        _append_ioc_from_evidence(state, evidence)
        return _defense_event("block_ip", rule_id, src_ip, target_ep, ts)

    if action == "block_ip":
        already_blocked = src_ip in state["blocked_ips"] if src_ip else True
        if src_ip and not already_blocked:
            state["blocked_ips"].append(src_ip)
        _append_ioc_from_evidence(state, evidence)
        if already_blocked:
            # IP already handled — don't re-emit a block event; avoids misleading
            # the dashboard and prevents spurious RISK_MITIGATION_DISCOUNT churn.
            return None
        return _defense_event("block_ip", rule_id, src_ip, target_ep, ts)

    if action == "export_ioc":
        _append_ioc_from_evidence(state, evidence)
        return _defense_event("alert_only", rule_id, src_ip, target_ep, ts)

    if action == "deep_log_attacker":
        if src_ip:
            dl = _ensure_deep_logging_ips(state)
            if src_ip not in dl:
                dl.append(src_ip)
        return _defense_event("alert_only", rule_id, src_ip, target_ep, ts)

    if action == "rate_limit":
        limit = RATE_LIMIT_MAP.get(rule_id, RATE_LIMIT_LOGIN_HIGH)
        raw = target_ep or "/target/login"
        ep = _rate_limit_endpoint_key(raw)
        state["rate_limited_endpoints"][ep] = limit
        if ep == "/login" or "/login" in raw:
            state["active_mitigations"]["rate_limit_login"] = True
        return _defense_event("rate_limit", rule_id, "", ep, ts)

    if action == "patch_endpoint":
        flag = PATCH_MAP.get(rule_id)
        if flag:
            state["active_mitigations"][flag] = True
        return _defense_event("patch_endpoint", rule_id, "", target_ep, ts)

    if action == "alert_only":
        line = f"{rule_id}: {evidence}"
        vulns = state.setdefault("vulnerabilities_found", [])
        if isinstance(vulns, list) and line not in vulns:
            vulns.append(line)
        return _defense_event("alert_only", rule_id, src_ip, target_ep, ts)

    return None


def apply_mitigations(findings: List[Finding], state: SystemState) -> dict:
    """
    Runs mitigations for every finding (mutations are idempotent where possible).
    Returns the DefenseEvent for the highest-severity finding; pipeline index
    breaks ties (earlier rule wins).
    """
    if not findings:
        return _defense_none()

    from backend.main import STATE_LOCK

    ts = time.time()
    best_event: Optional[dict] = None
    best_key: tuple = (-1, 0)

    with STATE_LOCK:
        state.setdefault("behavioral_fingerprints", [])
        state.setdefault("ioc_exports", [])
        _ensure_deep_logging_ips(state)

        for idx, finding in enumerate(findings):
            event = _apply_finding(finding, state, ts)
            if event is None:
                continue
            rank = SEVERITY_RANK.get(finding.get("severity", "low"), 0)
            key = (rank, -idx)
            if key > best_key:
                best_key = key
                best_event = event

    return best_event if best_event is not None else _defense_none()
