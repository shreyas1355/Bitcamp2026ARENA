"""
responder.py — Blue team mitigation executor.

TODO (Dev C, Phase 4): Implement this file.
See PROMPT.md Section 8.3 for action implementations.

Actions:
  block_ip        → append IP to state["blocked_ips"] (middleware enforces)
  rate_limit      → add endpoint to state["rate_limited_endpoints"] with threshold
  patch_endpoint  → set flag in state["active_mitigations"]
  alert_only      → append to vulnerabilities_found, no enforcement
  none            → no findings, no action
"""

import time
from typing import List
from backend.state import SystemState, Finding
from backend.config import (
    RATE_LIMIT_LOGIN_HIGH,
    RATE_LIMIT_LOGIN_STUFFING,
    RATE_LIMIT_FLOOD,
)

# Maps rule_id → which active_mitigations flag to enable
PATCH_MAP = {
    "RULE_SEQUENTIAL_IDOR":  "idor_check_enabled",
    "RULE_ADMIN_PROBING":    "proper_admin_auth",
    "RULE_TIME_BASED_SQLI":  "proper_auth",
    "RULE_SQLI_SIGNATURE":   "proper_auth",
}

# Maps rule_id → rate limit threshold (req/min)
RATE_LIMIT_MAP = {
    "RULE_HIGH_LOGIN_RATE":      RATE_LIMIT_LOGIN_HIGH,
    "RULE_CREDENTIAL_STUFFING":  RATE_LIMIT_LOGIN_STUFFING,
    "RULE_ENDPOINT_FLOOD":       RATE_LIMIT_FLOOD,
}


def apply_mitigations(findings: List[Finding], state: SystemState) -> dict:
    """
    TODO (Dev C): Process findings and apply the highest-severity mitigation.

    Processes the first (highest-priority by rule pipeline order) finding.
    Modifies state in-place for blocked_ips, rate_limited_endpoints,
    active_mitigations. Uses STATE_LOCK from main.py for thread safety on writes.

    Returns a DefenseEvent dict representing what action was taken.
    Returns action="none" DefenseEvent if findings is empty.
    """
    if not findings:
        return {
            "action":          "none",
            "trigger_rule":    "",
            "target_ip":       "",
            "target_endpoint": "",
            "timestamp":       time.time(),
        }

    # STUB — return alert_only for all findings until implemented
    finding = findings[0]
    return {
        "action":          "alert_only",
        "trigger_rule":    finding.get("rule_id", ""),
        "target_ip":       finding.get("source_ip", ""),
        "target_endpoint": finding.get("target_endpoint", ""),
        "timestamp":       time.time(),
    }
