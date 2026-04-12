"""
reset.py — reset_node for the LangGraph arena loop.

Called after policy_node at the end of each episode.
Increments the episode counter, resets step and per-episode fields,
clears short-term memory M, and resets the supervisor trigger.
"""

import time

from backend.state import SystemState
from backend.memory.short_term import clear as clear_memory


def reset_node(state: SystemState) -> dict:
    """
    Resets all per-episode fields for the next episode.

    Fields that PERSIST across episodes (not reset):
    - episode_pool (E): grows across episodes
    - knowledge_base (K): read-only; extended at runtime via ioc_exports ingestion
    - rate_limited_endpoints: carry forward
    - active_mitigations: carry forward (patched stays patched)
    - supervisor_report: carry forward (dashboard keeps showing last report)
    - behavioral_fingerprints: V2 — fingerprints of blocked attackers, enables
      cross-episode IP-rotation detection (MUST NOT be cleared)
    - patch_records: V2 — accumulates verified patches across all episodes

    Fields reset for simulation continuity:
    - blocked_ips: CLEARED on reset. The red team always originates from
      127.0.0.1 (httpx from localhost), so a carried-forward block permanently
      defeats the red team — every step floods with 403s and risk pins at 1.000.
      Fingerprints persist to detect re-entry; the IP block itself is episode-scoped.

    Fields that RESET for each new episode:
    - step → 0
    - short_term_memory → []
    - risk_history → []
    - vulnerabilities_found → []
    - supervisor_trigger → False
    - last_attack → None
    - last_defense → None
    - current_findings → []
    - raw_observation → {}
    - pruned_observation → {}
    - retrieved_similar_step → None
    - prior_recommendation → "none"
    - llm_decision → None  (V2: fresh decision each episode start)
    - current_attack_layer → 1  (V2: restart escalation ladder)
    - ioc_exports → []  (V2: cleared after policy_agent ingests them into KB)
    """
    next_episode = state["episode"] + 1
    clear_memory()

    print(f"\n{'='*60}")
    print(f"[RESET] Episode {state['episode']} complete.")
    print(f"[RESET] Final risk score: {state['risk_score']:.3f}")
    print(f"[RESET] Vulnerabilities found: {len(state['vulnerabilities_found'])}")
    print(f"[RESET] Starting Episode {next_episode}...")
    print(f"{'='*60}\n")

    return {
        "episode":               next_episode,
        "step":                  0,
        "short_term_memory":     [],
        "risk_history":          [],
        "vulnerabilities_found": [],
        "supervisor_trigger":    False,
        "last_attack":           None,
        "last_defense":          None,
        "current_findings":      [],
        "raw_observation":       {},
        "pruned_observation":    {},
        "retrieved_similar_step": None,
        "prior_recommendation":  "none",
        # V2: reset per-episode LLM fields
        "llm_decision":          None,
        "current_attack_layer":  1,
        "ioc_exports":           [],
        # Cleared so the red team (always 127.0.0.1) can operate in the new
        # episode. Behavioral fingerprints still carry forward for detection.
        "blocked_ips":           [],
        # NOTE: behavioral_fingerprints and patch_records are NOT in this dict.
        # LangGraph only updates fields present in the return dict, so those
        # two fields carry forward automatically (Rule 14 in PROMPT_V2.md).
    }