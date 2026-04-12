import json
import time
from collections import defaultdict

from backend.state import SystemState
from backend.config import LOG_FILE, LOG_WINDOW_SECONDS, MAX_LOG_LINES
from backend.agents.blue.anomaly_detector import (
    run_anomaly_detection,
    SQLI_REGEX,
    TRAVERSAL_REGEX,
    _normalize_for_detection,
    _build_behavioral_signature,
)
from backend.agents.blue.responder import apply_mitigations


def _entry_line_has_sqli_raw(entry: dict) -> bool:
    """Must match rule_sqli_signature (raw only); encoded-only is rule_sqli_encoded."""
    params = entry.get("query_params") or {}
    payload = entry.get("payload") or {}
    for v in {**params, **payload}.values():
        if SQLI_REGEX.search(str(v)):
            return True
    return False


def _entry_line_has_path_traversal(entry: dict) -> bool:
    params = entry.get("query_params") or {}
    payload = entry.get("payload") or {}
    for v in {**params, **payload}.values():
        raw = str(v)
        if TRAVERSAL_REGEX.search(_normalize_for_detection(raw)):
            return True
        if TRAVERSAL_REGEX.search(raw):
            return True
    return False


def _seed_fingerprints_for_new_blocks(
    state: SystemState, logs: list, findings: list
) -> None:
    """
    Store a behavioral fingerprint for blocked IPs that did not already get one
    via fingerprint_and_block (cold start for IP-rotation rule).

    NOTE: STATE_LOCK must not be held by the caller — it is acquired here.
    threading.Lock is not reentrant; wrapping blue_node (or this helper) in an
    outer ``with STATE_LOCK`` would deadlock. apply_mitigations releases the lock
    before this runs, so the current blue_node sequence is safe.
    """
    from backend.main import STATE_LOCK

    with STATE_LOCK:
        existing = {
            fp.get("ip")
            for fp in state.get("behavioral_fingerprints", [])
            if isinstance(fp, dict)
        }
        for f in findings:
            if f.get("recommended_action") == "fingerprint_and_block":
                continue
            if f.get("recommended_action") not in ("block_ip", "block_and_patch"):
                continue
            ip = f.get("source_ip") or ""
            if not ip or ip in existing:
                continue
            sig = _build_behavioral_signature(ip, logs)
            if sig:
                state.setdefault("behavioral_fingerprints", []).append(sig)
                existing.add(ip)


def read_recent_logs(
    filepath: str,
    window_s: float,
    max_lines: int,
    min_timestamp: float = 0.0,
) -> list:
    """
    Returns log entries from the last `window_s` seconds, but never older
    than `min_timestamp` (episode start time).  Passing min_timestamp prevents
    episode N-1 attack evidence from bleeding into episode N's anomaly rules.
    """
    try:
        # errors="replace" keeps the arena running if logs.jsonl was saved as UTF-16
        # or corrupted; bad lines are skipped below as JSON errors.
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-max_lines:]
    except FileNotFoundError:
        return []
    cutoff = max(time.time() - window_s, min_timestamp)
    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if entry.get("timestamp", 0) >= cutoff:
                entries.append(entry)
        except json.JSONDecodeError:
            continue
    return entries


def build_raw_observation(recent_logs: list, state: SystemState = None) -> dict:
    base = {k: 0.0 for k in [
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

    if not recent_logs:
        if state:
            base["blocked_ip_count"] = float(len(state.get("blocked_ips", [])))
            base["rate_limited_endpoint_count"] = float(
                len(state.get("rate_limited_endpoints", []))
            )
            base["active_mitigation_count"] = float(
                sum(1 for v in state.get("active_mitigations", {}).values() if v)
            )
        return base

    total = len(recent_logs)
    ip_counts = defaultdict(int)
    status_counts = defaultdict(int)
    response_times = []
    failed_logins = 0
    successful_logins = 0
    usernames = set()
    sqli_count = 0.0
    path_trav_count = 0.0
    large_payload = 0.0
    admin_probes = 0.0
    idor_ids = defaultdict(list)

    endpoint_keys = {
        "/target/login": "requests_login",
        "/target/data": "requests_data",
        "/target/admin": "requests_admin",
        "/target/files": "requests_files",
        "/target/transfer": "requests_transfer",
    }

    for entry in recent_logs:
        ip = entry.get("ip", "unknown")
        path = entry.get("path", "")
        status = entry.get("status_code", 0)
        rt = entry.get("response_time_ms", 0.0)
        params = entry.get("query_params", {})
        payload = entry.get("payload", {})

        ip_counts[ip] += 1
        status_counts[status] += 1
        response_times.append(rt)

        for endpoint, key in endpoint_keys.items():
            if path.startswith(endpoint):
                base[key] += 1.0

        if "/login" in path:
            if status == 401:
                # 401 = wrong credentials (genuine failed login attempt)
                # 403 = blocked IP — not a failed auth attempt, don't count it
                failed_logins += 1
            elif status == 200:
                successful_logins += 1
            u = (payload.get("username") or params.get("username"))
            if u:
                usernames.add(u)

        if "/admin" in path and status == 401:
            # 403 on /admin = blocked IP or access denied, not an active probe
            admin_probes += 1

        if "/data" in path and "id" in params:
            try:
                idor_ids[ip].append(int(params["id"]))
            except (ValueError, TypeError):
                pass

        if _entry_line_has_sqli_raw(entry):
            sqli_count += 1.0
        if _entry_line_has_path_traversal(entry):
            path_trav_count += 1.0
        content_len = float(entry.get("content_length", 0) or 0)
        if content_len <= 0:
            content_len = float(len(str(params)) + len(str(payload)))
        if content_len > 1024:
            large_payload += 1.0

    seq_ids = 0.0
    for ip, ids in idor_ids.items():
        if len(ids) >= 3:
            s = sorted(ids)
            for i in range(len(s) - 2):
                if s[i+1] - s[i] == 1 and s[i+2] - s[i+1] == 1:
                    seq_ids += 1.0
                    break

    max_ip = max(ip_counts.values(), default=0)

    base.update({
        "total_requests": float(total),
        "unique_ips": float(len(ip_counts)),
        "rate_401": status_counts[401] / total,
        "rate_403": status_counts[403] / total,
        "rate_429": status_counts[429] / total,
        "rate_500": status_counts[500] / total,
        "rate_200": status_counts[200] / total,
        "max_ip_requests": float(max_ip),
        "top_ip_request_fraction": max_ip / total,
        "avg_response_ms": sum(response_times) / len(response_times),
        "max_response_ms": float(max(response_times)),
        "failed_logins": float(failed_logins),
        "successful_logins": float(successful_logins),
        "unique_usernames_tried": float(len(usernames)),
        "login_success_rate": successful_logins / (failed_logins + successful_logins) if (failed_logins + successful_logins) > 0 else 0.0,
        "sqli_patterns_detected": sqli_count,
        "path_traversal_detected": path_trav_count,
        "large_payload_count": large_payload,
        "sequential_id_requests": seq_ids,
        "admin_probe_count": admin_probes,
    })

    if state:
        base["blocked_ip_count"] = float(len(state.get("blocked_ips", [])))
        base["rate_limited_endpoint_count"] = float(len(state.get("rate_limited_endpoints", [])))
        base["active_mitigation_count"] = float(sum(1 for v in state.get("active_mitigations", {}).values() if v))

    return base


def blue_node(state: SystemState) -> dict:
    episode_start = state.get("episode_start_time", 0.0)
    logs = read_recent_logs(LOG_FILE, LOG_WINDOW_SECONDS, MAX_LOG_LINES, min_timestamp=episode_start)
    obs = build_raw_observation(logs, state)
    findings = run_anomaly_detection(obs, logs, state)
    last_defense = apply_mitigations(findings, state)
    _seed_fingerprints_for_new_blocks(state, logs, findings)
    return {
        "raw_observation": obs,
        "last_defense": last_defense,
        "current_findings": findings,
    }
