"""
langgraph_flow.py — StateGraph definition for the ACDA arena loop.

Graph topology (V2):
  red → blue → prune → evaluation → risk ──┬──► policy → patch → reset
                                            │                        │
                                            └────────────────────────┘
                                         (loop when step < max_steps)

V2: patch_node inserted between policy and reset.
  policy_node = Gemini call 1 (episode analysis)
  patch_node  = Gemini call 2 (patch generation + exec() + HTTP verify)
  Together = 2 Gemini calls/episode, safely under 15 RPM free tier.
"""

import time

from langgraph.graph import StateGraph

from backend.state import SystemState
from backend.config import STEP_DELAY_S


# ── Node imports ──────────────────────────────────────────────────────────────

from backend.agents.red.strategy import red_node
from backend.agents.blue.log_monitor import blue_node
from backend.agents.supervisor.pruner import prune_node
from backend.agents.supervisor.evaluation_agent import evaluation_node
from backend.scoring.risk_engine import risk_node
from backend.agents.supervisor.policy_agent import policy_node
from backend.agents.supervisor.patch_agent import patch_node
from backend.graph.reset import reset_node


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
