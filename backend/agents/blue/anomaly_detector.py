"""
anomaly_detector.py — Rule-based threat detection engine.

See .cursorrules §8.3 (V2). Rules run in RULE_PIPELINE order; every triggered
rule is collected; responder applies mitigations and picks the highest-severity
DefenseEvent.
 """

import hashlib
import math
import re
import statistics
from collections import Counter, defaultdict
from typing import Any, Optional, Set
from urllib.parse import unquote

from backend.state import SystemState, Finding
from backend.config import (
    ANOMALY_LOGIN_RATE_THRESHOLD,
    ANOMALY_FLOOD_THRESHOLD,
    ANOMALY_RECON_ENDPOINT_THRESHOLD,
    ANOMALY_TIMING_CV_THRESHOLD,
    ANOMALY_STUFFING_USERNAMES,
    ANOMALY_STUFFING_SUCCESS_RATE,
    ANOMALY_ADMIN_PROBE_THRESHOLD,
    FINGERPRINT_SIMILARITY_THRESHOLD,
    FINGERPRINT_MIN_REQUESTS,
    ANOMALY_SUCCESS_RATE_THRESHOLD,
)

# ── Detection regexes (aligned with log_monitor where raw matching is used) ────

SQLI_REGEX = re.compile(
    r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b"
    r"|\bINSERT\b|\bDELETE\b|\bUPDATE\b|1=1|1%3d1|sleep\s*\()",
    re.IGNORECASE,
)

TRAVERSAL_REGEX = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)",
    re.IGNORECASE,
)


def _normalize_for_detection(value: str) -> str:
    """Decode URL encoding up to 3 levels (e.g. %2527 → ')."""
    normalized = value
    for _ in range(3):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return normalized


def _iter_param_values(entry: dict[str, Any]) -> list[str]:
    params = entry.get("query_params") or {}
    payload = entry.get("payload") or {}
    out: list[str] = []
    for v in {**params, **payload}.values():
        out.append(str(v))
    return out


def _param_blob(entry: dict[str, Any]) -> str:
    return " ".join(_iter_param_values(entry))


def _finding(
    rule_id: str,
    severity: str,
    source_ip: str,
    target_endpoint: str,
    evidence: dict[str, Any],
    recommended_action: str,
) -> Finding:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "source_ip": source_ip,
        "target_endpoint": target_endpoint,
        "evidence": evidence,
        "recommended_action": recommended_action,
    }


def _ua_hash_norm(user_agent: str) -> float:
    if not user_agent:
        return 0.0
    h = int(hashlib.sha256(user_agent.encode("utf-8", errors="ignore")).hexdigest()[:8], 16)
    return (h % 10007) / 10007.0


def _signature_vector(sig: dict[str, Any]) -> list[float]:
    return [
        float(sig.get("inter_arrival_mean", 0.0)),
        float(sig.get("inter_arrival_cv", 0.0)),
        float(sig.get("error_rate", 0.0)),
        float(sig.get("ua_hash", _ua_hash_norm(str(sig.get("user_agent", ""))))),
    ]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _build_behavioral_signature(ip: str, logs: list) -> Optional[dict[str, Any]]:
    rows = [e for e in logs if e.get("ip", "unknown") == ip]
    if len(rows) < FINGERPRINT_MIN_REQUESTS:
        return None
    rows.sort(key=lambda e: float(e.get("timestamp", 0) or 0))
    ts_list = [float(e.get("timestamp", 0) or 0) for e in rows]
    gaps = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
    if len(gaps) < 1:
        return None
    mean_gap = statistics.mean(gaps)
    cv = (statistics.stdev(gaps) / mean_gap) if mean_gap > 1e-9 else 0.0
    statuses = [int(e.get("status_code", 0) or 0) for e in rows]
    non_200 = sum(1 for s in statuses if s != 200)
    error_rate = non_200 / max(len(statuses), 1)
    paths = [str(e.get("path", "")) for e in rows]
    last5 = paths[-5:]
    uas = [str(e.get("user_agent", "") or "") for e in rows]
    ua = Counter(uas).most_common(1)[0][0] if uas else ""
    ua_h = _ua_hash_norm(ua)
    return {
        "inter_arrival_mean": mean_gap,
        "inter_arrival_cv": cv,
        "endpoint_sequence": last5,
        "error_rate": error_rate,
        "user_agent": ua,
        "ua_hash": ua_h,
    }


# ── Rule functions ─────────────────────────────────────────────────────────────


def rule_sqli_signature(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("sqli_patterns_detected", 0) <= 0:
        return None
    for entry in logs:
        for raw in _iter_param_values(entry):
            if SQLI_REGEX.search(raw):
                return _finding(
                    "RULE_SQLI_SIGNATURE",
                    "critical",
                    entry.get("ip", ""),
                    entry.get("path", ""),
                    {"matched": "query_params/payload", "path": entry.get("path")},
                    "block_ip",
                )
    return _finding(
        "RULE_SQLI_SIGNATURE",
        "critical",
        "",
        "",
        {"reason": "sqli_patterns_detected>0 but no log line matched"},
        "block_ip",
    )


def rule_sqli_encoded(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    for entry in logs:
        ip = entry.get("ip", "")
        path = entry.get("path", "")
        for raw in _iter_param_values(entry):
            raw_str = raw
            if SQLI_REGEX.search(raw_str):
                continue
            norm = _normalize_for_detection(raw_str)
            if SQLI_REGEX.search(norm):
                ioc_export = {
                    "pattern": raw_str[:500],
                    "type": "sqli_encoded",
                    "description": "Encoded SQLi payload detected after URL normalization",
                    "kb_entry": {
                        "id": "KB_RUNTIME_ENCODED_SQLI",
                        "pattern": "url_encoded_sqli",
                        "severity": "critical",
                    },
                }
                return _finding(
                    "RULE_SQLI_ENCODED",
                    "critical",
                    ip,
                    path,
                    {"normalized_sample": norm[:200], "ioc_export": ioc_export},
                    "block_ip",
                )
    return None


def rule_path_traversal(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    for entry in logs:
        for raw in _iter_param_values(entry):
            norm = _normalize_for_detection(raw)
            if TRAVERSAL_REGEX.search(norm):
                return _finding(
                    "RULE_PATH_TRAVERSAL",
                    "high",
                    entry.get("ip", ""),
                    entry.get("path", ""),
                    {"path": entry.get("path"), "normalized_sample": norm[:200]},
                    "block_ip",
                )
    if obs.get("path_traversal_detected", 0) <= 0:
        return None
    for entry in logs:
        if TRAVERSAL_REGEX.search(_param_blob(entry)):
            return _finding(
                "RULE_PATH_TRAVERSAL",
                "high",
                entry.get("ip", ""),
                entry.get("path", ""),
                {"path": entry.get("path")},
                "block_ip",
            )
    return _finding(
        "RULE_PATH_TRAVERSAL",
        "high",
        "",
        "",
        {"reason": "path_traversal_detected>0 but no log line matched"},
        "block_ip",
    )


def rule_time_based_sqli(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    """Slowest request in the window must be to /login and > 2.5s."""
    if not logs:
        return None
    slow = max(logs, key=lambda e: float(e.get("response_time_ms", 0) or 0))
    rt = float(slow.get("response_time_ms", 0) or 0)
    if rt <= 2500:
        return None
    if "/login" not in slow.get("path", ""):
        return None
    return _finding(
        "RULE_TIME_BASED_SQLI",
        "high",
        slow.get("ip", ""),
        slow.get("path", ""),
        {"response_time_ms": rt, "path": slow.get("path")},
        "block_and_patch",
    )


def rule_behavioral_fingerprint(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if flagged_ips is None:
        flagged_ips = set()
    blocked = set(state.get("blocked_ips") or [])
    stored = list(state.get("behavioral_fingerprints") or [])
    if not stored:
        return None

    by_ip: dict[str, list] = defaultdict(list)
    for e in logs:
        by_ip[e.get("ip", "unknown")].append(e)

    for ip, _ in by_ip.items():
        if ip in blocked or ip in flagged_ips:
            continue
        sig = _build_behavioral_signature(ip, logs)
        if sig is None:
            continue
        v_new = _signature_vector(sig)
        best = 0.0
        for fp in stored:
            v_st = _signature_vector(fp)
            sim = _cosine_similarity(v_new, v_st)
            if sim > best:
                best = sim
        if best > FINGERPRINT_SIMILARITY_THRESHOLD:
            ioc_export = {
                "pattern": ip,
                "type": "behavioral",
                "description": f"New IP behavior matches blocked attacker (cosine ~{best:.3f})",
                "kb_entry": {"id": "KB_RUNTIME_BEHAVIORAL", "pattern": "ip_rotation", "severity": "high"},
            }
            evidence = {
                "behavioral_fingerprint": sig,
                "similarity": best,
                "ioc_export": ioc_export,
            }
            return _finding(
                "RULE_BEHAVIORAL_FINGERPRINT",
                "high",
                ip,
                "",
                evidence,
                "fingerprint_and_block",
            )
    return None


def rule_sequential_idor(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("sequential_id_requests", 0) <= 0:
        return None
    return _finding(
        "RULE_SEQUENTIAL_IDOR",
        "high",
        "",
        "/target/data",
        {"sequential_id_requests": obs.get("sequential_id_requests")},
        "patch_endpoint",
    )


def rule_admin_probing(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("admin_probe_count", 0) <= ANOMALY_ADMIN_PROBE_THRESHOLD:
        return None
    return _finding(
        "RULE_ADMIN_PROBING",
        "high",
        "",
        "/target/admin",
        {"admin_probe_count": obs.get("admin_probe_count")},
        "patch_endpoint",
    )


def rule_credential_stuffing(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("unique_usernames_tried", 0) <= ANOMALY_STUFFING_USERNAMES:
        return None
    if obs.get("login_success_rate", 1.0) >= ANOMALY_STUFFING_SUCCESS_RATE:
        return None
    return _finding(
        "RULE_CREDENTIAL_STUFFING",
        "high",
        "",
        "/target/login",
        {
            "unique_usernames_tried": obs.get("unique_usernames_tried"),
            "login_success_rate": obs.get("login_success_rate"),
        },
        "rate_limit",
    )


def rule_slow_scripted_probe(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    by_ip: dict[str, list[float]] = defaultdict(list)
    for e in logs:
        by_ip[e.get("ip", "unknown")].append(float(e.get("timestamp", 0) or 0))

    for ip, ts_list in by_ip.items():
        if len(ts_list) <= 5:
            continue
        ts_list.sort()
        gaps = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
        if len(gaps) < 2:
            continue
        m = statistics.mean(gaps)
        if m < 0.5 or m > 6.0:
            continue
        cv = statistics.stdev(gaps) / m if m > 0 else 1e9
        if cv < ANOMALY_TIMING_CV_THRESHOLD:
            return _finding(
                "RULE_SLOW_SCRIPTED_PROBE",
                "medium",
                ip,
                "",
                {"mean_inter_arrival_s": m, "cv": cv},
                "block_ip",
            )
    return None


def rule_high_login_rate(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("failed_logins", 0) <= ANOMALY_LOGIN_RATE_THRESHOLD:
        return None
    if obs.get("max_ip_requests", 0) <= 8:
        return None
    return _finding(
        "RULE_HIGH_LOGIN_RATE",
        "medium",
        "",
        "/target/login",
        {
            "failed_logins": obs.get("failed_logins"),
            "max_ip_requests": obs.get("max_ip_requests"),
        },
        "rate_limit",
    )


def rule_endpoint_flood(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    counts: dict[str, int] = defaultdict(int)
    for e in logs:
        counts[e.get("path", "")] += 1
    for path, n in counts.items():
        if n > ANOMALY_FLOOD_THRESHOLD:
            return _finding(
                "RULE_ENDPOINT_FLOOD",
                "medium",
                "",
                path,
                {"request_count": n, "threshold": ANOMALY_FLOOD_THRESHOLD},
                "rate_limit",
            )
    return None


def rule_anomalous_success_rate(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if flagged_ips is None:
        flagged_ips = set()
    if obs.get("rate_401", 0) >= 0.1:
        return None
    blocked = set(state.get("blocked_ips") or [])
    counts: dict[str, int] = defaultdict(int)
    for e in logs:
        if int(e.get("status_code", 0) or 0) == 200:
            counts[e.get("ip", "unknown")] += 1
    for ip, n in counts.items():
        if ip in blocked or ip in flagged_ips:
            continue
        if n > ANOMALY_SUCCESS_RATE_THRESHOLD:
            return _finding(
                "RULE_ANOMALOUS_SUCCESS_RATE",
                "medium",
                ip,
                "",
                {"http_200_count": n, "threshold": ANOMALY_SUCCESS_RATE_THRESHOLD},
                "deep_log_attacker",
            )
    return None


def rule_ip_recon_sweep(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    by_ip: dict[str, set[str]] = defaultdict(set)
    for e in logs:
        by_ip[e.get("ip", "unknown")].add(e.get("path", ""))
    for ip, paths in by_ip.items():
        if len(paths) > ANOMALY_RECON_ENDPOINT_THRESHOLD:
            return _finding(
                "RULE_IP_RECON_SWEEP",
                "low",
                ip,
                "",
                {"distinct_endpoints": len(paths), "paths": list(paths)[:20]},
                "alert_only",
            )
    return None


def rule_large_get_payload(
    obs: dict,
    logs: list,
    state: SystemState,
    flagged_ips: Optional[Set[str]] = None,
) -> Optional[Finding]:
    if obs.get("large_payload_count", 0) <= 3:
        return None
    return _finding(
        "RULE_LARGE_GET_PAYLOAD",
        "low",
        "",
        "",
        {"large_payload_count": obs.get("large_payload_count")},
        "alert_only",
    )


RULE_PIPELINE = [
    rule_sqli_signature,
    rule_sqli_encoded,
    rule_path_traversal,
    rule_time_based_sqli,
    rule_behavioral_fingerprint,
    rule_sequential_idor,
    rule_admin_probing,
    rule_credential_stuffing,
    rule_slow_scripted_probe,
    rule_high_login_rate,
    rule_endpoint_flood,
    rule_anomalous_success_rate,
    rule_ip_recon_sweep,
    rule_large_get_payload,
]


def run_anomaly_detection(
    obs: dict,
    logs: list,
    state: SystemState,
) -> list:
    """Runs all rules in order; returns every triggered Finding."""
    findings: list[Finding] = []
    flagged_ips: set[str] = set()
    for rule_fn in RULE_PIPELINE:
        finding = rule_fn(obs, logs, state, flagged_ips)
        if finding is not None:
            findings.append(finding)
            sip = finding.get("source_ip") or ""
            if sip:
                flagged_ips.add(sip)
    return findings
