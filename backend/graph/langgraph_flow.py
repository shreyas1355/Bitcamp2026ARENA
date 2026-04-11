"""
langgraph_flow.py — StateGraph definition for the ACDA arena loop.

Graph topology (V2):
  red → blue → prune → evaluation → risk ──┬──► policy → patch → reset
                                            │                        │
                                            └────────────────────────┘
                                         (loop when step < max_steps)

V2 CHANGE: patch_node inserted between policy and reset.
  policy_node = Gemini call 1 (episode analysis)
  patch_node  = Gemini call 2 (patch generation + exec() + HTTP verify)
  Together = 2 Gemini calls/episode, safely under 15 RPM free tier.

DEVELOPER NOTE:
Red and blue still use stubs until agents are implemented. Prune, evaluation,
risk, policy, patch, and reset are wired to real/stub modules. Graph topology
must not change once set here.
"""

import time

from langgraph.graph import StateGraph

from backend.state import SystemState
from backend.config import STEP_DELAY_S


# ── Stub nodes (replace with real imports as agents are implemented) ──────────

def _stub_red_node(state: SystemState) -> dict:
    """
    Placeholder until Dev B implements backend/agents/red/strategy.py.
    Returns a hardcoded successful bruteforce AttackEvent.
    """
    print(f"  [RED-STUB]  episode={state['episode']} step={state['step']}")
    return {
        "last_attack": {
            "type":      "bruteforce",
            "target":    "/login",
            "payload":   "admin:password",
            "result":    "success",
            "evidence":  "HTTP 200 (STUB)",
            "cwe":       "",
            "severity":  "medium",
            "timestamp": time.time(),
        }
    }


def _stub_blue_node(state: SystemState) -> dict:
    """
    Placeholder until Dev C implements backend/agents/blue/log_monitor.py.
    Returns an empty observation and no defense action.
    """
    print(f"  [BLUE-STUB] episode={state['episode']} step={state['step']}")
    return {
        "raw_observation": {
            "total_requests":        0.0,
            "failed_logins":         1.0,
            "rate_401":              0.5,
            "top_ip_request_fraction": 1.0,
        },
        "last_defense": {
            "action":          "none",
            "trigger_rule":    "",
            "target_ip":       "",
            "target_endpoint": "",
            "timestamp":       time.time(),
        },
        "current_findings": [],
    }


# ── Real node imports ─────────────────────────────────────────────────────────

# TODO: Replace _stub_red_node with backend.agents.red.strategy.red_node
# TODO: Replace _stub_blue_node with backend.agents.blue.log_monitor.blue_node

from backend.agents.supervisor.pruner import prune_node as _real_prune_node
from backend.agents.supervisor.evaluation_agent import evaluation_node as _real_evaluation_node

from backend.scoring.risk_engine import risk_node
from backend.agents.supervisor.policy_agent import policy_node
from backend.graph.reset import reset_node


def _stub_patch_node(state) -> dict:
    """
    Placeholder until backend/agents/supervisor/patch_agent.py is implemented.
    LangGraph requires at least one field written per node, so we echo
    patch_records back unchanged.
    """
    print(f"  [PATCH-STUB] episode={state['episode']} — patch_agent not yet implemented")
    return {
        "patch_records": state.get("patch_records", []),
    }


from backend.agents.supervisor.patch_agent import patch_node as _real_patch_node

# ── Active node assignments (swap stubs for reals here) ───────────────────────

red_node        = _stub_red_node
blue_node       = _stub_blue_node
prune_node      = _real_prune_node
evaluation_node = _real_evaluation_node
patch_node      = _real_patch_node


# ── Step delay wrapper ────────────────────────────────────────────────────────

def red_node_with_delay(state: SystemState) -> dict:
    """Wraps red_node to insert the configured step delay."""
    time.sleep(STEP_DELAY_S)
    return red_node(state)


# ── Routing function ──────────────────────────────────────────────────────────

def _route_after_risk(state: SystemState) -> str:
    if state.get("supervisor_trigger", False):
        return "policy"
    return "red"


# ── Graph definition ──────────────────────────────────────────────────────────

builder = StateGraph(SystemState)

builder.add_node("red",        red_node_with_delay)
builder.add_node("blue",       blue_node)
builder.add_node("prune",      prune_node)
builder.add_node("evaluation", evaluation_node)
builder.add_node("risk",       risk_node)
builder.add_node("policy",     policy_node)
builder.add_node("patch",      patch_node)    # V2: new node
builder.add_node("reset",      reset_node)

builder.set_entry_point("red")

builder.add_edge("red",        "blue")
builder.add_edge("blue",       "prune")
builder.add_edge("prune",      "evaluation")
builder.add_edge("evaluation", "risk")
builder.add_conditional_edges(
    "risk",
    _route_after_risk,
    {"policy": "policy", "red": "red"},
)
builder.add_edge("policy", "patch")   # V2: policy → patch (was policy → reset)
builder.add_edge("patch",  "reset")   # V2: new edge
builder.add_edge("reset",  "red")

arena = builder.compile()
