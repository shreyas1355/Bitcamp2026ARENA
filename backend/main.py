"""
main.py — FastAPI application entry point.

Responsibilities:
- Mounts the vulnerable target router at /target
- Registers the SecurityMiddleware (logging + enforcement)
- Exposes the WebSocket endpoint at /ws
- Exposes a REST /state endpoint for dashboard initial load
- Starts the LangGraph arena loop in a background thread on startup

DEVELOPER NOTE:
The vulnerable target app is mounted at /target with SecurityMiddleware.
The arena runs in a background thread via arena.invoke(SYSTEM_STATE) so HTTP
and LangGraph share one dict (PROMPT Rule 4). PROMPT's verify snippet uses
get_initial_state() inline; production uses this module's SYSTEM_STATE only.
"""

import asyncio
import json
import os
import threading
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# ── Shared system state singleton ─────────────────────────────────────────────
# This module-level dict is the live SystemState shared between:
#   - The LangGraph arena thread (reads + writes via node functions)
#   - The FastAPI middleware (reads blocked_ips, rate_limited_endpoints)
#   - The WebSocket broadcaster (reads for broadcast)
#
# Use STATE_LOCK for any write to blocked_ips or rate_limited_endpoints.
# Read-only access does not require the lock.

from backend.state import get_initial_state, SystemState
from backend.config import (
    ARENA_RECURSION_LIMIT,
    KNOWLEDGE_BASE_FILE,
    EPISODE_POOL_FILE,
    MAX_STEPS,
)
from backend.ws.broadcaster import manager

STATE_LOCK = threading.Lock()

def _load_knowledge_base() -> list:
    try:
        with open(KNOWLEDGE_BASE_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[WARN] {KNOWLEDGE_BASE_FILE} not found — using empty knowledge base")
        return []

def _load_episode_pool() -> list:
    try:
        with open(EPISODE_POOL_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Initialize the shared state — this is the singleton every module imports
SYSTEM_STATE: SystemState = get_initial_state(
    knowledge_base=_load_knowledge_base(),
    episode_pool=_load_episode_pool(),
    max_steps=MAX_STEPS,
)


# ── Lifespan ──────────────────────────────────────────────────────────────────

def _run_arena():
    """
    Runs the LangGraph arena in a background thread.

    Uses the process-wide SYSTEM_STATE singleton so nodes, middleware, and /state
    see the same data. The graph has no END node; LangGraph stops after
    ARENA_RECURSION_LIMIT supersteps, then we restart invoke on the same dict.
    """
    from backend.graph.langgraph_flow import arena

    try:
        from langgraph.errors import GraphRecursionError
    except ImportError:  # pragma: no cover
        GraphRecursionError = type("GraphRecursionError", (Exception,), {})

    cfg = {"recursion_limit": ARENA_RECURSION_LIMIT}
    print("[ARENA] LangGraph thread started — invoke(SYSTEM_STATE)")

    while True:
        try:
            arena.invoke(SYSTEM_STATE, cfg)
        except GraphRecursionError:
            print(
                "[ARENA] Recursion limit reached — restarting invoke "
                f"(same SYSTEM_STATE, episode={SYSTEM_STATE['episode']})"
            )
            continue
        except Exception as e:
            print(f"[ERROR] Arena invoke failed: {e}")
            import traceback

            traceback.print_exc()
            break


@asynccontextmanager
async def lifespan(app: FastAPI):
    # WebSocket broadcasts from sync graph nodes use this loop (see broadcaster.py)
    manager.set_loop(asyncio.get_running_loop())

    # Configure Gemini
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        from backend.agents.supervisor.gemini_client import configure_gemini
        configure_gemini(api_key)
        print("[STARTUP] Gemini configured")
    else:
        print("[WARN] GEMINI_API_KEY not set — supervisor will not function")

    # V2: Check Ollama availability (red team LLM — runs locally, zero API cost)
    try:
        from backend.llm.ollama_client import check_ollama_available
        if check_ollama_available():
            from backend.config import OLLAMA_MODEL
            print(f"[STARTUP] Ollama available — model: {OLLAMA_MODEL}")
        else:
            print("[WARN] Ollama not available — red team will use rule-based fallback")
            print("[WARN] To enable: `ollama serve` then `ollama pull llama3`")
    except ImportError:
        print("[WARN] ollama_client not yet implemented — red team uses fallback")

    # Start arena loop in background thread
    arena_thread = threading.Thread(target=_run_arena, daemon=True, name="arena-loop")
    arena_thread.start()
    print("[STARTUP] Arena thread launched")

    yield

    print("[SHUTDOWN] Arena thread will stop with process (daemon=True)")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ACDA — Autonomous Cyber Defense Arena",
    version="0.1.0",
    lifespan=lifespan,
)

# Allow the Vite dev server to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Middleware & target app ───────────────────────────────────────────────────
from backend.target.middleware import SecurityMiddleware
from backend.target.router import target_router

app.add_middleware(SecurityMiddleware)
app.include_router(target_router, prefix="/target", tags=["target"])


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    print(f"[WS] Client connected: {ws.client}")
    try:
        while True:
            # Keep connection alive; ignore any messages from client
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
        print(f"[WS] Client disconnected: {ws.client}")


# ── REST endpoints ─────────────────────────────────────────────────────────────

@app.get("/state")
async def get_state():
    """
    Returns current SystemState snapshot.
    Used by the dashboard on initial load to populate all components.
    """
    # Return a serializable subset (exclude non-serializable fields if any)
    return {
        "episode":               SYSTEM_STATE["episode"],
        "step":                  SYSTEM_STATE["step"],
        "risk_score":            SYSTEM_STATE["risk_score"],
        "risk_history":          SYSTEM_STATE["risk_history"],
        "blocked_ips":           SYSTEM_STATE["blocked_ips"],
        "active_mitigations":    SYSTEM_STATE["active_mitigations"],
        "vulnerabilities_found": SYSTEM_STATE["vulnerabilities_found"],
        "supervisor_report":     SYSTEM_STATE["supervisor_report"],
        # V2 additions
        "current_attack_layer":  SYSTEM_STATE.get("current_attack_layer", 1),
        "patch_records":         SYSTEM_STATE.get("patch_records", []),
        "llm_decision":          SYSTEM_STATE.get("llm_decision"),
    }

@app.get("/health")
async def health():
    return {"status": "ok", "episode": SYSTEM_STATE["episode"], "step": SYSTEM_STATE["step"]}
