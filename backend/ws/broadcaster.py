"""
broadcaster.py — WebSocket connection manager and broadcast utilities.

The ConnectionManager is a module-level singleton. Import `manager` everywhere.
Import `broadcast_step` and `broadcast_report` from risk_engine and policy_agent.

Thread safety: broadcast() is async (runs in the FastAPI event loop).
broadcast_step_sync() is the synchronous wrapper called from LangGraph nodes
which run in a background thread. It uses asyncio bridge patterns.
"""

import asyncio
import json
from typing import Set

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active_connections.discard(ws)

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        """Called from the FastAPI lifespan to register the event loop."""
        self._loop = loop

    async def broadcast(self, data: dict):
        """
        Send JSON to all connected clients.
        Silently removes clients that have disconnected.
        """
        if not self.active_connections:
            return
        dead: Set[WebSocket] = set()
        message = json.dumps(data)
        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        self.active_connections -= dead

    def broadcast_sync(self, data: dict):
        """
        Synchronous wrapper for broadcast(). Called from LangGraph nodes
        which run in a non-async background thread.

        Uses the event loop registered via set_loop(). If no loop is
        registered yet, silently drops the broadcast (early startup).
        """
        if self._loop is None or self._loop.is_closed():
            return
        if not self.active_connections:
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self.broadcast(data),
                self._loop,
            ).result(timeout=1.0)
        except Exception as e:
            print(f"[WS] Broadcast failed: {e}")


# Module-level singleton — import this everywhere
manager = ConnectionManager()


# ── Convenience broadcast functions ──────────────────────────────────────────

def broadcast_step_update(state: dict):
    """
    Called from risk_node every step.
    Sends a StepUpdate message to all connected dashboard clients.

    Expected state fields: episode, step, risk_score, risk_history,
    last_attack, last_defense, active_mitigations, vulnerabilities_found
    """
    manager.broadcast_sync({
        "type":                 "step_update",
        "episode":              state.get("episode"),
        "step":                 state.get("step"),
        "risk_score":           state.get("risk_score"),
        "risk_history":         state.get("risk_history", []),
        "last_attack":          state.get("last_attack"),
        "last_defense":         state.get("last_defense"),
        "active_mitigations":   state.get("active_mitigations", {}),
        "vulnerabilities_found": state.get("vulnerabilities_found", []),
        "llm_decision":         state.get("llm_decision"),
    })


def broadcast_episode_report(report: dict, episode: int):
    """
    Called from policy_node after Gemini response.
    Sends an EpisodeReport message to all connected dashboard clients.
    """
    manager.broadcast_sync({
        "type":    "episode_report",
        "episode": episode,
        "report":  report,
    })


def broadcast_patch_summary(patch_records: list, episode: int):
    """
    V2: Called from patch_node after patch generation + verification.
    Sends a PatchSummary message to all connected dashboard clients.
    Only includes patches that were actually attempted (patch_applied=True).
    """
    manager.broadcast_sync({
        "type":    "patch_summary",
        "episode": episode,
        "patches": [
            {
                "vulnerability":     p["vulnerability_name"],
                "endpoint":          p["endpoint"],
                "cwe":               p["cwe"],
                "verified":          p["verified"],
                "requires_human_review": p["requires_human_review"],
                "evidence":          p["verification_evidence"],
            }
            for p in patch_records
            if p.get("patch_applied")
        ],
    })
