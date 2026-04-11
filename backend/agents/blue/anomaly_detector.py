"""
anomaly_detector.py — Rule-based threat detection engine.

TODO (Dev C, Phase 4): Implement all rules.
See PROMPT.md Section 8.3 for the complete rule specifications.

Rules (in execution order — stop after first critical finding):
  RULE_SQLI_SIGNATURE         critical  block_ip
  RULE_PATH_TRAVERSAL         high      block_ip
  RULE_TIME_BASED_SQLI        high      block_ip + patch_endpoint
  RULE_SEQUENTIAL_IDOR        high      patch_endpoint
  RULE_ADMIN_PROBING          high      patch_endpoint
  RULE_CREDENTIAL_STUFFING    high      rate_limit
  RULE_SLOW_SCRIPTED_PROBE    medium    block_ip
  RULE_HIGH_LOGIN_RATE        medium    rate_limit
  RULE_ENDPOINT_FLOOD         medium    rate_limit
  RULE_IP_RECON_SWEEP         low       alert_only
  RULE_LARGE_GET_PAYLOAD      low       alert_only
"""

import re
from typing import Optional
from backend.state import SystemState, Finding
from backend.config import (
    ANOMALY_LOGIN_RATE_THRESHOLD,
    ANOMALY_FLOOD_THRESHOLD,
    ANOMALY_RECON_ENDPOINT_THRESHOLD,
    ANOMALY_TIMING_CV_THRESHOLD,
    ANOMALY_IDOR_SEQ_THRESHOLD,
    ANOMALY_STUFFING_USERNAMES,
    ANOMALY_STUFFING_SUCCESS_RATE,
    ANOMALY_ADMIN_PROBE_THRESHOLD,
)

# ── Detection regexes ──────────────────────────────────────────────────────────

SQLI_REGEX = re.compile(
    r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b"
    r"|\bINSERT\b|\bDELETE\b|\bUPDATE\b|1=1|1%3d1|sleep\s*\()",
    re.IGNORECASE,
)

TRAVERSAL_REGEX = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)",
    re.IGNORECASE,
)

# ── Rule functions (each returns Optional[Finding]) ───────────────────────────

def rule_sqli_signature(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["sqli_patterns_detected"] > 0. Severity: critical."""
    return None  # STUB

def rule_path_traversal(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["path_traversal_detected"] > 0. Severity: high."""
    return None  # STUB

def rule_time_based_sqli(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["max_response_ms"] > 2500 AND slow req was /login."""
    return None  # STUB

def rule_sequential_idor(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on same IP requesting /data?id= with 3+ consecutive integers."""
    return None  # STUB

def rule_admin_probing(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["admin_probe_count"] > ANOMALY_ADMIN_PROBE_THRESHOLD."""
    return None  # STUB

def rule_credential_stuffing(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on unique_usernames > threshold AND success_rate < threshold."""
    return None  # STUB

def rule_slow_scripted_probe(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on regular inter-arrival times (CV < threshold) from one IP."""
    return None  # STUB

def rule_high_login_rate(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["failed_logins"] > ANOMALY_LOGIN_RATE_THRESHOLD."""
    return None  # STUB

def rule_endpoint_flood(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on any endpoint exceeding ANOMALY_FLOOD_THRESHOLD reqs."""
    return None  # STUB

def rule_ip_recon_sweep(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on single IP hitting > ANOMALY_RECON_ENDPOINT_THRESHOLD endpoints."""
    return None  # STUB

def rule_large_get_payload(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """TODO (Dev C): Trigger on obs["large_payload_count"] > 3."""
    return None  # STUB


# ── Rule pipeline ──────────────────────────────────────────────────────────────

RULE_PIPELINE = [
    rule_sqli_signature,
    rule_path_traversal,
    rule_time_based_sqli,
    rule_sequential_idor,
    rule_admin_probing,
    rule_credential_stuffing,
    rule_slow_scripted_probe,
    rule_high_login_rate,
    rule_endpoint_flood,
    rule_ip_recon_sweep,
    rule_large_get_payload,
]


def run_anomaly_detection(
    obs: dict,
    logs: list,
    state: SystemState,
) -> list:
    """
    Runs all rules in RULE_PIPELINE order.
    Returns list of Finding dicts (may be empty).

    TODO (Dev C): Rules currently all return None (stubs).
    Implement each rule function above.
    """
    findings = []
    for rule_fn in RULE_PIPELINE:
        finding = rule_fn(obs, logs, state)
        if finding is not None:
            findings.append(finding)
    return findings
