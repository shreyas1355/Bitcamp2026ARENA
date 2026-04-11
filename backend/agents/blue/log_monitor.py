"""
log_monitor.py — blue_node: parse logs.jsonl → raw_observation dict.

TODO (Dev C, Phase 4): Implement this file.
See PROMPT.md Section 8.3 for the complete observation dict schema
(all keys, all types, expected values).

This is the LangGraph node function for the blue team. It orchestrates:
  log parsing → anomaly detection → mitigation response

All observation values must be float for the SEMA structural entropy pruner.
"""

import time
from backend.state import SystemState
from backend.config import LOG_FILE, LOG_WINDOW_SECONDS, MAX_LOG_LINES
from backend.agents.blue.anomaly_detector import run_anomaly_detection
from backend.agents.blue.responder import apply_mitigations


def build_raw_observation(recent_logs: list) -> dict:
    """
    TODO (Dev C): Parse recent log entries into the observation dict.

    Returns dict with exactly these keys (always present, 0.0 if not applicable):
    total_requests, unique_ips, requests_login, requests_data, requests_admin,
    requests_files, requests_transfer, rate_401, rate_403, rate_429, rate_500,
    rate_200, top_ip_request_fraction, max_ip_requests, avg_response_ms,
    max_response_ms, failed_logins, successful_logins, unique_usernames_tried,
    login_success_rate, sqli_patterns_detected, path_traversal_detected,
    large_payload_count, sequential_id_requests, admin_probe_count,
    blocked_ip_count, rate_limited_endpoint_count, active_mitigation_count
    """
    # STUB — return zeroed observation
    return {k: 0.0 for k in [
        "total_requests", "unique_ips", "requests_login", "requests_data",
        "requests_admin", "requests_files", "requests_transfer",
        "rate_401", "rate_403", "rate_429", "rate_500", "rate_200",
        "top_ip_request_fraction", "max_ip_requests",
        "avg_response_ms", "max_response_ms",
        "failed_logins", "successful_logins", "unique_usernames_tried",
        "login_success_rate", "sqli_patterns_detected", "path_traversal_detected",
        "large_payload_count", "sequential_id_requests", "admin_probe_count",
        "blocked_ip_count", "rate_limited_endpoint_count", "active_mitigation_count",
    ]}


def read_recent_logs(filepath: str, window_s: float, max_lines: int) -> list:
    """
    TODO (Dev C): Read the tail of logs.jsonl, return entries within window_s seconds.

    - If file does not exist: return []
    - Read last max_lines lines efficiently (seek from end)
    - Parse each line as JSON
    - Filter to entries where timestamp >= time.time() - window_s
    """
    return []  # STUB


def blue_node(state: SystemState) -> dict:
    """
    TODO (Dev C): Implement the full blue team node.

    1. read_recent_logs()
    2. build_raw_observation()
    3. run_anomaly_detection()
    4. apply_mitigations()
    5. Return updated state fields
    """
    # STUB
    return {
        "raw_observation": build_raw_observation([]),
        "last_defense": {
            "action":          "none",
            "trigger_rule":    "",
            "target_ip":       "",
            "target_endpoint": "",
            "timestamp":       time.time(),
        },
        "current_findings": [],
    }
