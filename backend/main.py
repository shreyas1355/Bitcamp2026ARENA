"""
main.py — FastAPI application entry point.

Responsibilities:
- Mounts the vulnerable target router at /target
- Registers the SecurityMiddleware (logging + enforcement)
- Exposes the WebSocket endpoint at /ws
- Exposes a REST /state endpoint for dashboard initial load
- Starts the LangGraph arena loop in a background thread on startup

DEVELOPER NOTE:
The vulnerable target app is mounted at /target with SecurityMiddleware
(logging; enforcement phases in PROMPT). The arena loop is still commented
out — uncomment after Phase 2 (langgraph_flow).
"""

import json
import os
import threading
import time
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
    KNOWLEDGE_BASE_FILE,
    EPISODE_POOL_FILE,
    MAX_STEPS,
)

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
    Runs the LangGraph arena loop in a background thread.
    Uncomment the arena import and invoke call after Phase 2 is complete.
    """
    # TODO (Dev A, Phase 2): Uncomment after langgraph_flow.py is implemented
    # from backend.graph.langgraph_flow import arena
    # try:
    #     arena.invoke(SYSTEM_STATE)
    # except Exception as e:
    #     print(f"[ERROR] Arena loop crashed: {e}")
    #     raise

    # Placeholder: print heartbeat so you can confirm the thread starts
    print("[ARENA] Arena thread started — loop not yet wired (Phase 2)")
    while True:
        time.sleep(5)
        print(f"[ARENA] Heartbeat — episode {SYSTEM_STATE['episode']}, step {SYSTEM_STATE['step']}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Configure Gemini
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        from backend.agents.supervisor.gemini_client import configure_gemini
        configure_gemini(api_key)
        print("[STARTUP] Gemini configured")
    else:
        print("[WARN] GEMINI_API_KEY not set — supervisor will not function")

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

from backend.ws.broadcaster import manager

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
        "episode":            SYSTEM_STATE["episode"],
        "step":               SYSTEM_STATE["step"],
        "risk_score":         SYSTEM_STATE["risk_score"],
        "risk_history":       SYSTEM_STATE["risk_history"],
        "blocked_ips":        SYSTEM_STATE["blocked_ips"],
        "active_mitigations": SYSTEM_STATE["active_mitigations"],
        "vulnerabilities_found": SYSTEM_STATE["vulnerabilities_found"],
        "supervisor_report":  SYSTEM_STATE["supervisor_report"],
    }

@app.get("/health")
async def health():
    return {"status": "ok", "episode": SYSTEM_STATE["episode"], "step": SYSTEM_STATE["step"]}
