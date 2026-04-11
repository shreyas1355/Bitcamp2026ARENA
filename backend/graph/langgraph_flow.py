"""
langgraph_flow.py — StateGraph definition for the ACDA arena loop.

Graph topology:
  red → blue → prune → evaluation → risk ──┬──► policy → reset
                                            │              │
                                            └──────────────┘
                                         (loop when step < max_steps)

DEVELOPER NOTE (Dev A):
Stub nodes are provided for all agents. Replace each stub with the real
import as the corresponding agent file is implemented. The graph topology
itself must not change.

Stub nodes return minimal valid dicts that satisfy the SystemState schema
so the graph can run end-to-end before real agents exist.
"""

import time

from langgraph.graph import StateGraph, END

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


def _stub_prune_node(state: SystemState) -> dict:
    """
    Placeholder until Dev A implements backend/agents/supervisor/pruner.py.
    Passes raw_observation through unchanged.
    """
    return {"pruned_observation": state.get("raw_observation", {})}


def _stub_evaluation_node(state: SystemState) -> dict:
    """
    Placeholder until Dev A implements backend/agents/supervisor/evaluation_agent.py.
    """
    return {
        "retrieved_similar_step": None,
        "prior_recommendation":   "none",
    }


# ── Real node imports (uncomment as each agent is implemented) ────────────────

# TODO (Dev B): Replace _stub_red_node
# from backend.agents.red.strategy import red_node as _real_red_node

# TODO (Dev C): Replace _stub_blue_node
# from backend.agents.blue.log_monitor import blue_node as _real_blue_node

# TODO (Dev A): Replace _stub_prune_node
# from backend.agents.supervisor.pruner import prune_node as _real_prune_node

# TODO (Dev A): Replace _stub_evaluation_node
# from backend.agents.supervisor.evaluation_agent import evaluation_node as _real_evaluation_node

# These are already implemented and imported directly:
from backend.scoring.risk_engine import risk_node
from backend.agents.supervisor.policy_agent import policy_node
from backend.graph.reset import reset_node


# ── Active node assignments (swap stubs for reals here) ───────────────────────

red_node        = _stub_red_node        # swap: _real_red_node
blue_node       = _stub_blue_node       # swap: _real_blue_node
prune_node      = _stub_prune_node      # swap: _real_prune_node
evaluation_node = _stub_evaluation_node # swap: _real_evaluation_node


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
builder.add_edge("policy", "reset")
builder.add_edge("reset",  "red")

arena = builder.compile()
