"""
strategy.py — red_node: Ollama proposes an LLMDecision; executors perform real HTTP.

Layer 1: local LLM (ollama) → structured JSON.
Layer 2: recon / bruteforce / exploit / business_logic / evasion → AttackEvent.
"""

from __future__ import annotations

import json
import random
from typing import Any, Dict

from backend.llm.ollama_client import call_ollama_json, check_ollama_available
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

STRATEGY_SYSTEM_CONTEXT = """You are an autonomous penetration tester targeting a web application.
Your goal is to find and exploit security vulnerabilities.

You have access to these attack capabilities:
- Authentication attacks: bruteforce, credential_stuffing, timing_enumeration
- Authorization attacks: idor, auth_bypass, privilege_escalation
- Injection attacks: sqli_auth_bypass, sqli_filter_param, sqli_union, sqli_blind, path_traversal, path_traversal_encoded
- Business logic attacks: negative_transfer, race_condition, replay_attack, integer_overflow
- Evasion techniques: sqli_double_encoded, timing_mimic, header_injection, ua_spoofing
- Reconnaissance: recon, surface_mapping

Be creative. Look for attack surfaces not in obvious places.
Consider: query parameters, request headers, HTTP methods, body fields the schema exposes.
If an endpoint has been patched, do not waste steps retrying the same technique there."""

DECISION_SCHEMA = """{
  "technique": "<technique_name from the list above>",
  "target_endpoint": "<endpoint path, e.g. /login or /data>",
  "method": "<GET|POST|PUT|DELETE>",
  "params": {"<key>": "<value>"},
  "headers": {"<key>": "<value>"},
  "payload": {"<key>": "<value>"},
  "rationale": "<one sentence: why this technique on this endpoint now>",
  "attack_layer": <integer 1-6>
}"""

FALLBACK_AGENT_ROSTER = [
    "recon", "bruteforce", "sqli_auth_bypass", "idor",
    "path_traversal", "auth_bypass", "csrf",
    "negative_transfer", "sqli_double_encoded",
]


def build_strategy_prompt(state: SystemState) -> str:
    """
    Builds a compact prompt: pruned telemetry, last 5 memory rows, mitigations, layer, supervisor hint.
    """
    obs = state.get("pruned_observation", {})
    memory = (state.get("short_term_memory") or [])[-5:]
    mitigations = state.get("active_mitigations", {})
    episode_pool = state.get("episode_pool", [])
    layer = state.get("current_attack_layer", 1)

    active_m = [k for k, v in mitigations.items() if v]

    memory_lines = []
    for m in memory:
        a = m.get("attack", {})
        d = m.get("llm_decision", {})
        line = (
            f" - {a.get('type', '?')} on {a.get('target', '?')} → {a.get('result', '?')}"
        )
        if d.get("rationale"):
            line += f" (rationale: {d.get('rationale', '')})"
        memory_lines.append(line)

    supervisor_hint = ""
    if episode_pool:
        supervisor_hint = f"\nSupervisor recommendation: {episode_pool[-1][:200]}"

    return f"""{STRATEGY_SYSTEM_CONTEXT}

CURRENT SECURITY TELEMETRY (high-signal attributes only, pre-filtered by structural entropy):
{json.dumps(obs, indent=2)}

RECENT HISTORY (last 5 steps):
{chr(10).join(memory_lines) if memory_lines else "  No history yet — first steps of episode."}

ACTIVE MITIGATIONS (patched — do not retry these):
{", ".join(active_m) if active_m else "None yet"}

CURRENT ATTACK LAYER: {layer} — {ATTACK_LAYERS.get(layer, "unknown")}
{supervisor_hint}

Decide your next attack. Choose a technique that is:
1. Not already blocked by active mitigations
2. Contextually appropriate given the telemetry above
3. Ideally from a surface or endpoint not yet fully explored"""


def _normalize_decision(raw: Dict[str, Any]) -> LLMDecision:
    """Merges LLM JSON with safe defaults so every LLMDecision field exists."""
    base: Dict[str, Any] = {
        "technique": "recon",
        "target_endpoint": "/",
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


def red_node(state: SystemState) -> dict:
    """
    LangGraph node: Ollama JSON decision → executor → last_attack + llm_decision.
    """
    ollama_ok = check_ollama_available()
    try:
        if ollama_ok:
            prompt = build_strategy_prompt(state)
            decision_dict = call_ollama_json(prompt, DECISION_SCHEMA)
            llm_decision = _normalize_decision(decision_dict)
        else:
            raise RuntimeError("Ollama not available")
    except Exception as e:
        print(f"[RED] Ollama failed: {e}. Using fallback.")
        llm_decision = _fallback_decision(state)

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
