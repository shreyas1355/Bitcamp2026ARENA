"""
risk_engine.py — risk_node for the LangGraph arena loop.

Responsibilities each step:
1. Compute new risk score from current findings + last attack result
2. Append to risk_history
3. Append step tuple to short-term memory M
4. Increment step counter
5. Set supervisor_trigger if step >= max_steps
6. Broadcast StepUpdate to WebSocket clients
"""

import time

from backend.state import SystemState
from backend.config import (
    RISK_DECAY,
    RISK_SEVERITY_WEIGHTS,
    RISK_ATTACK_SUCCESS_BONUS,
    RISK_MITIGATION_DISCOUNT,
    MAX_STEPS,
)
from backend.memory import short_term
from backend.ws.broadcaster import broadcast_step_update


def _compute_risk(state: SystemState) -> float:
    """
    Risk score formula:

      new_score = clip(
          old_score * RISK_DECAY
          + Σ(RISK_SEVERITY_WEIGHTS[finding.severity] for finding in current_findings)
          + RISK_ATTACK_SUCCESS_BONUS  (if last_attack.result == "success")
          + RISK_MITIGATION_DISCOUNT * mitigations_added_this_step,
          0.0, 1.0
      )

    The decay factor means the score naturally drifts toward 0 when no new
    findings exist — the defenses are working.
    """
    old_score = state.get("risk_score", 0.0)

    # Decay
    score = old_score * RISK_DECAY

    # Add weight for each finding this step.
    # Skip findings whose source IP is already blocked — those threats are handled;
    # re-counting them every step while they remain in the 60-second log window
    # would prevent risk from ever decaying after a successful block.
    blocked_set = set(state.get("blocked_ips") or [])
    for finding in state.get("current_findings", []):
        src_ip = finding.get("source_ip") or ""
        if src_ip and src_ip in blocked_set:
            continue
        severity = finding.get("severity", "info")
        score += RISK_SEVERITY_WEIGHTS.get(severity, 0.0)

    # Bonus for successful attack
    last_attack = state.get("last_attack")
    if last_attack and last_attack.get("result") == "success":
        score += RISK_ATTACK_SUCCESS_BONUS

    # Discount for mitigations applied this step
    last_defense = state.get("last_defense")
    if last_defense and last_defense.get("action") not in ("none", "alert_only"):
        score += RISK_MITIGATION_DISCOUNT

    return max(0.0, min(1.0, score))


def risk_node(state: SystemState) -> dict:
    new_score = _compute_risk(state)
    new_history = state.get("risk_history", []) + [round(new_score, 4)]
    new_step = state.get("step", 0) + 1
    trigger = new_step >= state.get("max_steps", MAX_STEPS)

    # Append to short-term memory M
    # V2: pass llm_decision so evaluation_agent can surface Ollama rationale
    short_term.append_step(
        obs=state.get("pruned_observation", {}),
        attack=state.get("last_attack"),
        defense=state.get("last_defense"),
        result=_build_result_string(state),
        llm_decision=state.get("llm_decision"),
    )

    # Accumulate confirmed vulnerabilities
    new_vulns = list(state.get("vulnerabilities_found", []))
    for finding in state.get("current_findings", []):
        summary = (
            f"[{finding.get('severity','?').upper()}] "
            f"{finding.get('rule_id','?')} on {finding.get('target_endpoint','?')}"
        )
        if summary not in new_vulns:
            new_vulns.append(summary)

    # Build updated state fields
    updated = {
        "risk_score":          new_score,
        "risk_history":        new_history,
        "step":                new_step,
        "supervisor_trigger":  trigger,
        "short_term_memory":   short_term.get_all(),
        "vulnerabilities_found": new_vulns,
    }

    # Broadcast to dashboard (fire-and-forget)
    broadcast_state = {**state, **updated}
    broadcast_step_update(broadcast_state)

    _log_step(state, new_score, trigger)
    return updated


def _build_result_string(state: SystemState) -> str:
    attack = state.get("last_attack")
    if not attack:
        return "no_attack"
    return f"{attack.get('type','unknown')}:{attack.get('result','unknown')}"


def _log_step(state: SystemState, new_score: float, trigger: bool):
    attack = state.get("last_attack")
    defense = state.get("last_defense")
    attack_str  = f"{attack.get('type')}→{attack.get('result')}"  if attack  else "none"
    defense_str = f"{defense.get('action')}"                       if defense else "none"
    marker = " ◄ SUPERVISOR" if trigger else ""
    print(
        f"[STEP {state.get('step'):>3}] "
        f"risk={new_score:.3f}  "
        f"attack={attack_str:<30}  "
        f"defense={defense_str}{marker}"
    )
