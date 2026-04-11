"""
policy_agent.py — policy_node: post-episode Gemini call.

TODO (Dev A, Phase 5): Implement this file.

This is the ONLY node that calls Gemini. Called once per episode.
See PROMPT.md Section 8.4 for the complete prompt templates and
context window budget.
"""

import json
import time

from backend.state import SystemState
from backend.memory.episode_pool import append_summary
from backend.ws.broadcaster import broadcast_episode_report


def policy_node(state: SystemState) -> dict:
    """
    TODO (Dev A): Implement full Gemini-powered episode analysis.

    Steps:
    1. Build prompts from state (pruned_obs, attack history, defense history,
       vulnerabilities_found, episode_pool excerpts, knowledge_base snippets)
    2. Call gemini_client.call_gemini()
    3. Parse JSON response into SupervisorReport
    4. Append episode_summary to episode_pool (persist to disk)
    5. Broadcast EpisodeReport to dashboard
    6. Return {"supervisor_report": report, "episode_pool": updated_pool}
    """
    print(f"\n[SUPERVISOR] Episode {state['episode']} analysis starting...")

    # STUB — replace with real Gemini call
    stub_report = {
        "risk_score":             state.get("risk_score", 0.0),
        "vulnerabilities":        [{"name": v, "severity": "medium", "endpoint": "unknown", "cwe": "", "evidence": "rule-based detection"} for v in state.get("vulnerabilities_found", [])[:3]],
        "mitigations":            ["STUB — implement policy_agent.py for real Gemini analysis"],
        "next_episode_strategy":  "Continue with unexplored attack vectors",
        "episode_summary":        f"Episode {state['episode']} stub summary. Risk: {state.get('risk_score', 0):.2f}",
        "token_count":            0,
    }

    updated_pool = append_summary(stub_report["episode_summary"])
    broadcast_episode_report(stub_report, state["episode"])

    print(f"[SUPERVISOR] Episode {state['episode']} complete. Risk: {stub_report['risk_score']:.3f}")
    return {
        "supervisor_report": stub_report,
        "episode_pool":      updated_pool,
    }
