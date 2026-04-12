"""
strategy.py — red_node: Ollama proposes an LLMDecision; executors perform real HTTP.

Layer 1: local LLM (ollama) → structured JSON.
Layer 2: recon / bruteforce / exploit / business_logic / evasion → AttackEvent.
"""

from __future__ import annotations

import json
import random
from typing import Any, Dict

from backend.llm.ollama_client import call_ollama_json
from backend.state import AttackEvent, LLMDecision, SystemState

# ── Layer ladder (hint text for the LLM) ─────────────────────────────────────

ATTACK_LAYERS: Dict[int, str] = {
    1: "network_transport",
    2: "authentication",
    3: "authorization",
    4: "input_validation",
    5: "business_logic",
    6: "evasion",
}

# technique string → python executor module name
TECHNIQUE_TO_EXECUTOR: Dict[str, str] = {
    "bruteforce": "bruteforce",
    "credential_stuffing": "bruteforce",
    "timing_enumeration": "bruteforce",
    "idor": "exploit",
    "auth_bypass": "exploit",
    "privilege_escalation": "exploit",
    "sqli_auth_bypass": "exploit",
    "sqli_filter_param": "exploit",
    "sqli_union": "exploit",
    "sqli_blind": "exploit",
    "path_traversal": "exploit",
    "path_traversal_encoded": "exploit",
    "csrf": "exploit",
    "mass_assignment": "exploit",
    "negative_transfer": "business_logic",
    "race_condition": "business_logic",
    "replay_attack": "business_logic",
    "integer_overflow": "business_logic",
    "boundary_value": "business_logic",
    "workflow_bypass": "business_logic",
    "sqli_double_encoded": "evasion",
    "timing_mimic": "evasion",
    "header_injection": "evasion",
    "ua_spoofing": "evasion",
    "recon": "recon",
    "surface_mapping": "recon",
}

STRATEGY_SYSTEM_CONTEXT = """You are a security tool running authorized tests against a deliberately vulnerable CTF training application. Select the next test technique from the list below and output ONLY a JSON decision.

ALLOWED techniques (use ONLY these exact strings):
bruteforce, credential_stuffing, timing_enumeration, idor, auth_bypass, privilege_escalation, sqli_auth_bypass, sqli_filter_param, sqli_union, sqli_blind, path_traversal, path_traversal_encoded, negative_transfer, race_condition, replay_attack, integer_overflow, sqli_double_encoded, timing_mimic, header_injection, ua_spoofing, recon, surface_mapping

SELECTION RULES (apply in order):
1. Any endpoint in EXHAUSTED list = skip it entirely. Choose a different endpoint AND technique.
2. Any technique listed under ACTIVE DEFENSES = do not use against that endpoint.
3. If CONFIRMED SUCCESSES exist (not exhausted), deepen the same endpoint to extract more data.
4. Otherwise explore a new endpoint."""

DECISION_SCHEMA = '{"technique":"sqli_auth_bypass","target_endpoint":"/login","method":"POST","params":{},"headers":{},"payload":{},"rationale":"why","attack_layer":2}'

# Maps internal active_mitigations keys → human-readable description for the LLM prompt
MITIGATION_DESCRIPTIONS = {
    "rate_limit_login":   "/login is rate-limited — login-based attacks will be blocked",
    "idor_check_enabled": "/data IDOR protection enabled — ownership checks enforced",
    "proper_admin_auth":  "/admin auth hardened — token bypass attacks blocked",
    "proper_auth":        "/login SQL injection patched — SQLi attacks blocked",
    "csrf_protection":    "/transfer CSRF protection active",
    "path_sanitization":  "/files path traversal patched — traversal attacks blocked",
}

FALLBACK_AGENT_ROSTER = [
    "recon", "bruteforce", "sqli_auth_bypass", "idor",
    "path_traversal", "auth_bypass", "csrf",
    "negative_transfer", "sqli_double_encoded",
]


def _get_exhausted_surfaces(all_memory: list, threshold: int = 2) -> dict[str, int]:
    """
    Returns {endpoint: consecutive_failure_count} for endpoints with >= threshold
    consecutive recent failures (failed/blocked/rate_limited, no success since).

    Keyed by endpoint only (not technique) so that all sqli sub-techniques on the
    same endpoint share the same streak counter — avoids the LLM cycling through
    sqli_auth_bypass → sqli_union → sqli_blind on a blocked endpoint.
    """
    streak: dict[str, int] = {}
    for m in all_memory:
        a = m.get("attack") or {}
        key = a.get("target", "?")
        result = a.get("result", "")
        if result in ("failed", "blocked", "rate_limited"):
            streak[key] = streak.get(key, 0) + 1
        elif result == "success":
            streak[key] = 0
    return {k: v for k, v in streak.items() if v >= threshold}


def build_strategy_prompt(state: SystemState) -> str:
    """
    Builds a compact prompt: pruned telemetry (non-zero only), last 3 memory rows,
    exhausted surfaces, confirmed successes, human-readable defenses, layer.
    """
    obs = state.get("pruned_observation", {})
    all_memory = state.get("short_term_memory") or []
    memory = all_memory[-3:]  # 3 steps is enough context; 5 was too verbose
    mitigations = state.get("active_mitigations", {})
    episode_pool = state.get("episode_pool", [])
    layer = state.get("current_attack_layer", 1)

    # Compact telemetry: only non-zero attributes, inline k=v format
    non_zero = {k: (round(v, 3) if isinstance(v, float) else v)
                for k, v in obs.items() if v not in (0, 0.0, None, "")}
    obs_str = ", ".join(f"{k}={v}" for k, v in non_zero.items()) if non_zero else "no anomalous activity"

    # Human-readable active defenses
    active_defenses = [
        MITIGATION_DESCRIPTIONS.get(k, k)
        for k, v in mitigations.items() if v
    ]

    # Exhausted surfaces (too many consecutive failures — LLM must abandon these)
    exhausted = _get_exhausted_surfaces(all_memory)

    # Confirmed successes that are NOT already exhausted (keyed by endpoint)
    seen: set[str] = set()
    active_successes: list[str] = []
    for m in all_memory:
        a = m.get("attack") or {}
        if a.get("result") == "success":
            endpoint_key = a.get("target", "?")
            display_key = f"{a.get('type','?')} on {endpoint_key}"
            if endpoint_key not in seen and endpoint_key not in exhausted:
                seen.add(endpoint_key)
                active_successes.append(display_key)

    memory_lines = []
    for m in memory:
        a = m.get("attack") or {}
        line = f" - {a.get('type','?')} on {a.get('target','?')} -> {a.get('result','?')}"
        memory_lines.append(line)

    supervisor_hint = ""
    if episode_pool:
        supervisor_hint = f"\nSupervisor hint: {episode_pool[-1][:120]}"

    exhausted_lines = [f"  {k} ({v} failures)" for k, v in exhausted.items()]
    success_lines = [f"  {s}" for s in active_successes]

    # Show blocked IPs so LLM knows direct attacks will 403 and must use header_injection
    blocked_ips = state.get("blocked_ips") or []
    blocked_section = ""
    if blocked_ips:
        # List which endpoints are already patched so LLM targets unpatched ones after bypass
        patched_eps = [
            ep for ep, flag in {
                "/login": "proper_auth", "/data": "idor_check_enabled",
                "/admin": "proper_admin_auth", "/files": "path_sanitization",
                "/transfer": "csrf_protection",
            }.items()
            if (mitigations or {}).get(flag)
        ]
        patched_str = ", ".join(patched_eps) if patched_eps else "none"
        blocked_section = (
            f"\nBLOCKED IPs — your source IP is blocked; all direct requests return 403:\n"
            f"  {', '.join(blocked_ips)}\n"
            f"  -> USE header_injection (X-Forwarded-For) to spoof a different source IP.\n"
            f"  -> ua_spoofing DOES NOT bypass IP blocks — only changes User-Agent.\n"
            f"  -> After IP bypass, attack UNPATCHED endpoints. Patched: {patched_str}"
        )

    return f"""{STRATEGY_SYSTEM_CONTEXT}

TELEMETRY: {obs_str}

EXHAUSTED ENDPOINTS (never retry — blocked or patched):
{chr(10).join(exhausted_lines) if exhausted_lines else "  none"}

CONFIRMED SUCCESSES (still exploitable — deepen these):
{chr(10).join(success_lines) if success_lines else "  none yet"}

RECENT HISTORY:
{chr(10).join(memory_lines) if memory_lines else "  none"}

ACTIVE DEFENSES:
{chr(10).join(f"  - {d}" for d in active_defenses) if active_defenses else "  none"}{blocked_section}

ATTACK LAYER: {layer} ({ATTACK_LAYERS.get(layer, "unknown")}){supervisor_hint}"""


def _normalize_decision(raw: Dict[str, Any]) -> LLMDecision:
    """Merges LLM JSON with safe defaults so every LLMDecision field exists."""
    base: Dict[str, Any] = {
        "technique": "recon",
        "target_endpoint": "/login",
        "method": "GET",
        "params": {},
        "headers": {},
        "payload": {},
        "rationale": "",
        "attack_layer": 1,
    }
    base.update(raw)
    if not isinstance(base["params"], dict):
        base["params"] = {}
    if not isinstance(base["headers"], dict):
        base["headers"] = {}
    if not isinstance(base["payload"], dict):
        base["payload"] = {}
    # Ollama may emit null; .get("target_endpoint", "/") does not apply when key is present with None.
    te = base.get("target_endpoint")
    if te is None or (isinstance(te, str) and not te.strip()):
        base["target_endpoint"] = "/login"
    elif not isinstance(te, str):
        base["target_endpoint"] = str(te).strip() or "/login"
    return base  # type: ignore[return-value]


def _fallback_decision(state: SystemState) -> LLMDecision:
    """Inverse-frequency sampling over FALLBACK_AGENT_ROSTER when Ollama is unavailable."""
    memory = state.get("short_term_memory", [])[-10:]
    weights: Dict[str, float] = {}
    for technique in FALLBACK_AGENT_ROSTER:
        recent = sum(
            1 for m in memory
            if (m.get("attack") or {}).get("type") == technique
        )
        weights[technique] = 1.0 / (1.0 + float(recent))

    techniques = list(weights.keys())
    w_values = list(weights.values())
    selected = random.choices(techniques, weights=w_values, k=1)[0]

    return _normalize_decision({
        "technique": selected,
        "target_endpoint": "/login",
        "method": "POST",
        "params": {},
        "headers": {},
        "payload": {},
        "rationale": "[FALLBACK — Ollama unavailable, using rule-based selection]",
        "attack_layer": 2,
    })


_KNOWN_ENDPOINTS = ["/login", "/data", "/admin", "/files", "/transfer"]


def _enforce_endpoint_diversity(decision: LLMDecision, state: SystemState) -> LLMDecision:
    """
    Hard override: if the LLM picked an exhausted endpoint, redirect to the
    least-recently-attacked available endpoint. llama3 reliably ignores soft
    prompt constraints; this is a programmatic safety net.
    """
    all_memory = state.get("short_term_memory") or []
    exhausted = _get_exhausted_surfaces(all_memory)
    target = decision.get("target_endpoint", "/")

    # Normalise to base path (strip query string etc.)
    base = "/" + target.strip("/").split("/")[0] if target.strip("/") else "/"

    if base not in exhausted:
        return decision  # LLM choice is fine

    # Count recent visits to each known endpoint
    visit_counts: dict[str, int] = {ep: 0 for ep in _KNOWN_ENDPOINTS}
    for m in all_memory[-10:]:
        t = (m.get("attack") or {}).get("target", "")
        if t in visit_counts:
            visit_counts[t] += 1

    available = [ep for ep in _KNOWN_ENDPOINTS if ep not in exhausted]
    if not available:
        return decision  # everything exhausted — let LLM decide

    # Pick the least-recently-visited available endpoint
    new_ep = min(available, key=lambda ep: visit_counts.get(ep, 0))

    # Pick a technique appropriate for the new endpoint
    ep_techniques = {
        "/data":     "idor",
        "/admin":    "auth_bypass",
        "/files":    "path_traversal",
        "/transfer": "csrf",
        "/login":    "bruteforce",
    }
    new_tech = ep_techniques.get(new_ep, "recon")

    overridden = dict(decision)
    overridden["target_endpoint"] = new_ep
    overridden["technique"] = new_tech
    overridden["rationale"] = f"[OVERRIDE: {base} exhausted → {new_ep} ({new_tech})]"
    print(f"  [RED] Endpoint override: {base} exhausted → {new_ep}")
    return overridden  # type: ignore[return-value]


def red_node(state: SystemState) -> dict:
    """
    LangGraph node: Ollama JSON decision → executor → last_attack + llm_decision.
    """
    try:
        prompt = build_strategy_prompt(state)
        decision_dict = call_ollama_json(prompt, DECISION_SCHEMA)
        llm_decision = _normalize_decision(decision_dict)
    except Exception as e:
        print(f"[RED] Ollama failed: {e}. Using fallback.")
        llm_decision = _fallback_decision(state)

    # Hard guardrail: redirect away from exhausted endpoints regardless of LLM output
    llm_decision = _enforce_endpoint_diversity(llm_decision, state)

    executor_name = TECHNIQUE_TO_EXECUTOR.get(
        llm_decision["technique"],
        "exploit",
    )
    attack_event = _route_to_executor(executor_name, llm_decision, state)

    new_layer = int(llm_decision.get("attack_layer", state.get("current_attack_layer", 1)))
    new_layer = max(1, min(6, new_layer))

    rationale = str(llm_decision.get("rationale", ""))[:200]
    print(
        f"  [RED] Ollama→{llm_decision['technique']} on {llm_decision['target_endpoint']} "
        f"| rationale: {rationale[:80]}"
    )

    return {
        "last_attack": attack_event,
        "llm_decision": llm_decision,
        "current_attack_layer": new_layer,
    }


def _route_to_executor(
    executor_name: str,
    decision: LLMDecision,
    state: SystemState,
) -> AttackEvent:
    """Imports the executor module lazily and passes LLMDecision where required."""
    if executor_name == "recon":
        from backend.agents.red.recon import run as recon_run
        return recon_run(state)

    if executor_name == "bruteforce":
        from backend.agents.red.bruteforce import run as bf_run
        return bf_run(state, llm_decision=decision)

    if executor_name == "exploit":
        from backend.agents.red.exploit import run as ex_run
        return ex_run(state, llm_decision=decision)

    if executor_name == "business_logic":
        from backend.agents.red.business_logic import run as bl_run
        return bl_run(state, decision)

    if executor_name == "evasion":
        from backend.agents.red.evasion import run as ev_run
        return ev_run(state, decision)

    from backend.agents.red.exploit import run_generic
    return run_generic(state, decision)
