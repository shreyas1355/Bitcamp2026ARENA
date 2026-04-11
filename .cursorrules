# ACDA — Autonomous Cyber Defense Arena
## Complete Implementation Guide for Coding Agents

> **For the coding agent:** This document is the single source of truth for the entire project. Read it completely before writing a single line of code. Every architectural decision, every file, every function signature, and every data contract is specified here. Do not deviate from the file structure, the `SystemState` schema, or the LangGraph graph topology without a documented reason. Where implementation details are left to you, use the constraints in this document to make the correct choice.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [SEMA Framework — What It Is and How We Use It](#2-sema-framework)
3. [Tech Stack and Constraints](#3-tech-stack-and-constraints)
4. [System Architecture](#4-system-architecture)
5. [The LangGraph State Schema](#5-the-langgraph-state-schema)
6. [The LangGraph Graph Topology](#6-the-langgraph-graph-topology)
7. [Complete File Structure](#7-complete-file-structure)
8. [Backend — File-by-File Specification](#8-backend-file-by-file-specification)
   - 8.1 [FastAPI Target App](#81-fastapi-target-app)
   - 8.2 [Red Team Agents](#82-red-team-agents)
   - 8.3 [Blue Team Agents](#83-blue-team-agents)
   - 8.4 [Supervisor Agents](#84-supervisor-agents)
   - 8.5 [Memory System](#85-memory-system)
   - 8.6 [Scoring Engine](#86-scoring-engine)
   - 8.7 [WebSocket Broadcaster](#87-websocket-broadcaster)
9. [Frontend — Component Specification](#9-frontend-component-specification)
10. [Data Contracts and Schemas](#10-data-contracts-and-schemas)
11. [Configuration Reference](#11-configuration-reference)
12. [Startup and Execution Flow](#12-startup-and-execution-flow)
13. [Environment Setup](#13-environment-setup)
14. [Implementation Order](#14-implementation-order)
15. [Critical Rules for the Coding Agent](#15-critical-rules-for-the-coding-agent)

---

## 1. Project Overview

### What This Is

ACDA is a **continuous, autonomous cybersecurity stress-testing system**. It runs a real FastAPI web application with deliberately introduced vulnerabilities, deploys automated Red Team agents to attack it over HTTP, deploys automated Blue Team agents to detect and mitigate those attacks, and uses a Gemini-powered Supervisor to reason about the system's security posture once per episode.

The result is a **live security dashboard** showing a real cat-and-mouse dynamic: attacks land, defenses respond, risk scores shift, and the supervisor produces actionable vulnerability reports at episode boundaries.

### What This Is NOT

- Not a chatbot. No conversational interface of any kind.
- Not a pure simulation. Red team agents make real HTTP requests to a real running server.
- Not agents talking to each other. They share a `SystemState` dict through LangGraph; they do not communicate directly.
- Not LLM-heavy. Gemini is called **once per episode**, never per step or per attack. Everything else is deterministic Python.

### Core Value for a Hackathon Demo

When demoed, a judge sees:
1. Real HTTP traffic hitting a real server (visible in browser devtools or logs panel)
2. A live dashboard with a risk gauge climbing as attacks succeed
3. The blue team blocking IPs and rate-limiting endpoints in real time
4. After N steps: Gemini generates a structured vulnerability report with risk score, CVE references, and mitigation recommendations
5. The next episode's red team shifting strategy based on the supervisor's recommendation
6. A direct, citable connection to the SEMA academic paper (arXiv:2603.23875)

---

## 2. SEMA Framework

### What SEMA Is

SEMA (Self-Evolving Multi-Agent, arXiv:2603.23875) is a framework for low-latency LLM decision-making in Real-Time Strategy games (StarCraft II). It solves two problems that are directly analogous to our cybersecurity domain:

| SEMA Problem (StarCraft II) | Our Analog (Cybersecurity) |
|---|---|
| Massive game-state observation causes token overflow | Raw log data is too large to send to Gemini every step |
| LLM stochastic bias causes inconsistent decisions | Gemini called ad-hoc would give inconsistent risk assessments |
| Need real-time response under latency constraint | Attack/defense loop must run fast; LLM in the loop kills speed |

### The Three SEMA Principles We Implement

#### Principle 1 — Structural Entropy-Driven Observation Pruning (Algorithm 1 in paper)

Before any Gemini call, we do NOT dump raw logs into the prompt. We build a weighted attribute graph from the observation dictionary, score each attribute node by its structural entropy contribution, and remove the lowest-entropy nodes.

**The math (from paper Section 4.2):**

Given observations at time `t` and `t-1`, for each attribute pair `(i, j)`:
```
Δᵢ = |obs_t[i] − obs_{t-1}[i]|
Φ(Δᵢ, Δⱼ) = |Δᵢ · Δⱼ| · ln(1 + |Δᵢ · Δⱼ|)     # spatio-temporal operator (eq. 6)
wᵢⱼ = Φ(Δᵢ, Δⱼ) / ‖Wt‖∞                          # normalized edge weight (eq. 7)
```

One-dimensional structural entropy of the graph:
```
H₁(G) = −Σᵥ (dᵥ / vol(G)) · log₂(dᵥ / vol(G))    # eq. 2
```

Per-node importance score (our pruning criterion):
```
δH = α · ΔHG + β · ΔHT                               # eq. 8
```
Where `ΔHG` = change in H₁ if node is removed, `ΔHT` = change in 2D structural entropy.

Nodes with `δH < μ` (threshold) are pruning candidates. If more than `N` candidates exist, keep only the top-N by lowest `δH` for removal.

**In cybersecurity terms:** An attribute like `avg_response_ms` that has not changed between steps has low structural entropy contribution — it is not informative right now and should be pruned. An attribute like `failed_login_count_last_60s` that spiked from 0 to 47 has high contribution and must be kept.

**Why this matters:** This is the academically credible piece of the project. You can point to Algorithm 1 in the paper and show the direct implementation in `pruner.py`. It also makes Gemini calls cheaper and more focused.

#### Principle 2 — Three-Agent Role Separation (paper Section 4.3–4.5)

SEMA uses three agents with strictly separated concerns:

| SEMA Agent | Our Implementation | LLM? | Frequency |
|---|---|---|---|
| Decision Agent | Red team strategy selector | No (rule-based) | Every step |
| Evaluation Agent | Blue team + memory retrieval | No (cosine similarity) | Every step |
| Policy Agent | Supervisor (Gemini) | Yes (Gemini 1.5 Flash) | Once per episode |

The Evaluation Agent makes **no LLM calls**. It does cosine similarity between the current pruned observation vector and historical observations in short-term memory M. The matched historical action is surfaced as a prior recommendation. This is SEMA's mechanism for suppressing stochastic bias without LLM cost.

#### Principle 3 — Hierarchical Memory (paper Section 4, notation L = ⟨M, E, K⟩)

| Layer | SEMA | Our Implementation | Storage |
|---|---|---|---|
| M | Micro-memory: step-level trajectory tuples | Last 50 (obs, attack, defense, result) tuples | In-memory deque |
| E | Macro-experience: episode-level strategy summaries | Post-episode Gemini summaries | `data/episode_pool.json` |
| K | External knowledge base: static domain rules | CVE patterns, attack signatures, defense playbooks | `data/knowledge_base.json` |

The supervisor prompt is constructed from pruned M excerpts + relevant E summaries + K snippets. Never from raw logs.

---

## 3. Tech Stack and Constraints

### Backend
- **Python 3.11+** — required for `TypedDict` with `|` union syntax
- **FastAPI** — target app AND the WebSocket/REST API for the dashboard
- **LangGraph 0.2+** — `StateGraph` for orchestration. Install: `langgraph>=0.2.0`
- **`google-generativeai`** — Gemini 1.5 Flash. Free tier: 15 RPM, 1500 RPD. We call it once per episode so this is safe.
- **`httpx`** — async HTTP client for red team agents making real requests
- **`networkx`** — graph construction for structural entropy pruning
- **`numpy`** — vector math for cosine similarity and entropy calculations
- **`uvicorn`** — ASGI server
- **`python-dotenv`** — environment variable loading

### Frontend
- **React 18 + Vite** — SPA dashboard
- **TypeScript** — strict mode enabled
- **Tailwind CSS** — utility styling
- **`recharts`** — charts (LineChart for risk timeline, RadialBarChart for gauge)
- **Native WebSocket API** — no socket.io, no additional library

### LLM Usage Policy (HARD CONSTRAINT)
```
Gemini API calls: ONLY in policy_agent.py, ONLY once per episode
Local Ollama (optional): ONLY in strategy.py for strategy selection hint
NEVER: LLM calls in red agents, blue agents, prune_node, evaluation_node, or risk_node
```

Violating this constraint will exhaust the free tier and make the demo loop too slow.

---

## 4. System Architecture

### Execution Loop

```
Episode starts
│
└─► [STEP LOOP — runs MAX_STEPS times]
     │
     ├─ red_node         → Red team selects + executes one attack via real HTTP
     ├─ blue_node        → Blue team reads logs, detects anomalies, applies mitigations
     ├─ prune_node       → SEMA structural entropy pruning of observation dict
     ├─ evaluation_node  → Cosine similarity retrieval from short-term memory M
     ├─ risk_node        → Update risk score, append to M, broadcast to dashboard
     │
     └─ [if step == MAX_STEPS]
          │
          ├─ policy_node  → Single Gemini call: episode analysis → update E
          └─ reset_node   → Increment episode counter, reset step, clear M
               │
               └─► [next episode begins]
```

### Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                    LangGraph StateGraph                         │
│  red → blue → prune → evaluation → risk ──┬──► policy → reset  │
│                              ▲            │                     │
│                              └────────────┘ (loop N steps)     │
└─────────────────────────────────────────────────────────────────┘
         │                │                    │
         ▼                ▼                    ▼
   FastAPI Target    logs.jsonl          WebSocket /ws
   (real HTTP)       (append-only)       → React Dashboard
```

---

## 5. The LangGraph State Schema

This is the most critical piece of the entire project. Every node reads from and writes to this single `TypedDict`. Do not add fields without updating this spec. Do not remove fields. All fields are required unless marked Optional.

```python
# backend/state.py

from typing import TypedDict, List, Dict, Any, Literal, Optional, Deque
from collections import deque

class AttackEvent(TypedDict):
    type: str              # "recon" | "bruteforce" | "sqli" | "idor" | "path_traversal" | "auth_bypass" | "mass_assign"
    target: str            # endpoint path e.g. "/login"
    payload: str           # sanitized string representation of payload
    result: str            # "success" | "blocked" | "failed" | "rate_limited"
    evidence: str          # what the response was (status code + body snippet)
    cwe: str               # e.g. "CWE-89" or "" if not applicable
    severity: str          # "info" | "low" | "medium" | "high" | "critical"
    timestamp: float

class DefenseEvent(TypedDict):
    action: str            # "block_ip" | "rate_limit" | "patch_endpoint" | "alert_only"
    trigger_rule: str      # rule ID that triggered this e.g. "RULE_SQLI_SIGNATURE"
    target_ip: str         # IP that was acted on, or "" if endpoint-level
    target_endpoint: str   # endpoint acted on, or "" if IP-level
    timestamp: float

class Finding(TypedDict):
    rule_id: str
    severity: str          # "low" | "medium" | "high" | "critical"
    source_ip: str
    target_endpoint: str
    evidence: dict
    recommended_action: str

class SupervisorReport(TypedDict):
    risk_score: float
    vulnerabilities: List[Dict]   # [{name, severity, endpoint, cwe}]
    mitigations: List[str]
    next_episode_strategy: str
    token_count: int              # for monitoring free tier usage

class SystemState(TypedDict):
    # ── Episode and step tracking ──────────────────────────────
    episode: int
    step: int
    max_steps: int

    # ── Current step events ────────────────────────────────────
    last_attack: Optional[AttackEvent]
    last_defense: Optional[DefenseEvent]
    current_findings: List[Finding]   # findings from this step's anomaly detection

    # ── Memory layers: L = <M, E, K> ──────────────────────────
    short_term_memory: List[Dict]     # last MAX_MEMORY_SIZE (obs, attack, defense) tuples
    episode_pool: List[str]           # post-episode strategy summaries (persisted)
    knowledge_base: List[str]         # static CVE rules (loaded at startup, read-only)

    # ── Risk tracking ──────────────────────────────────────────
    risk_score: float                 # 0.0 to 1.0, updated each step
    risk_history: List[float]         # one entry per step this episode
    vulnerabilities_found: List[str]  # human-readable, accumulated this episode

    # ── Defense state (enforced by middleware) ─────────────────
    blocked_ips: List[str]
    rate_limited_endpoints: Dict[str, int]   # {endpoint: req_per_min_limit}
    active_mitigations: Dict[str, bool]      # feature flags read by target endpoints

    # ── Observation (built by log_monitor, pruned by pruner) ───
    raw_observation: Dict[str, float]     # full attribute dict from log monitor
    pruned_observation: Dict[str, float]  # after SEMA pruning — sent to Gemini

    # ── Evaluation agent output ────────────────────────────────
    retrieved_similar_step: Optional[Dict]  # most similar past step from M
    prior_recommendation: str               # action suggested by evaluation agent

    # ── Supervisor output ──────────────────────────────────────
    supervisor_report: Optional[SupervisorReport]

    # ── Routing ────────────────────────────────────────────────
    supervisor_trigger: bool   # True when step == max_steps
```

---

## 6. The LangGraph Graph Topology

```python
# backend/graph/langgraph_flow.py

from langgraph.graph import StateGraph, END
from backend.state import SystemState

# ── Node imports ─────────────────────────────────────────────────
from backend.agents.red.strategy import red_node
from backend.agents.blue.log_monitor import blue_node
from backend.agents.supervisor.pruner import prune_node
from backend.agents.supervisor.evaluation_agent import evaluation_node
from backend.scoring.risk_engine import risk_node
from backend.agents.supervisor.policy_agent import policy_node
from backend.graph.reset import reset_node

# ── Routing function ─────────────────────────────────────────────
def route_after_risk(state: SystemState) -> str:
    if state["supervisor_trigger"]:
        return "policy"
    return "red"

# ── Graph definition ─────────────────────────────────────────────
builder = StateGraph(SystemState)

builder.add_node("red",        red_node)
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
    route_after_risk,
    {"policy": "policy", "red": "red"}
)
builder.add_edge("policy", "reset")
builder.add_edge("reset",  "red")

arena = builder.compile()
```

**Node responsibility summary:**

| Node | Input reads | Output writes | LLM? |
|---|---|---|---|
| `red_node` | `active_mitigations`, `blocked_ips`, `episode_pool`, `short_term_memory` | `last_attack` | No |
| `blue_node` | reads `logs.jsonl` directly | `raw_observation`, `last_defense`, `current_findings`, `blocked_ips`, `rate_limited_endpoints`, `active_mitigations` | No |
| `prune_node` | `raw_observation`, `short_term_memory` | `pruned_observation` | No |
| `evaluation_node` | `pruned_observation`, `short_term_memory` | `retrieved_similar_step`, `prior_recommendation` | No |
| `risk_node` | `current_findings`, `last_attack`, `active_mitigations`, `risk_score` | `risk_score`, `risk_history`, `vulnerabilities_found`, `step`, `supervisor_trigger` | No |
| `policy_node` | `pruned_observation`, `short_term_memory`, `episode_pool`, `knowledge_base`, `vulnerabilities_found` | `supervisor_report`, `episode_pool` | **Yes — Gemini** |
| `reset_node` | all | `episode++`, `step=0`, `short_term_memory=[]`, `supervisor_trigger=False`, `risk_history=[]` | No |

---

## 7. Complete File Structure

```
cyber-defense-arena/
│
├── backend/
│   ├── main.py                          # FastAPI app: mounts target + WS + runs arena loop
│   ├── state.py                         # SystemState TypedDict + sub-TypedDicts
│   ├── config.py                        # All tuneable constants (see Section 11)
│   │
│   ├── target/                          # The vulnerable application being attacked
│   │   ├── __init__.py
│   │   ├── router.py                    # FastAPI router with all vulnerable endpoints
│   │   ├── vuln_store.py                # In-memory "database": users, sessions, records
│   │   └── middleware.py                # Request logger + IP blocker + rate limiter
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── red/
│   │   │   ├── __init__.py
│   │   │   ├── strategy.py              # red_node: entropy-weighted agent selector
│   │   │   ├── recon.py                 # Endpoint enumeration + fingerprinting
│   │   │   ├── bruteforce.py            # Credential spraying + stuffing
│   │   │   └── exploit.py              # SQLi, IDOR, path traversal, auth bypass, CSRF
│   │   │
│   │   └── blue/
│   │       ├── __init__.py
│   │       ├── log_monitor.py           # blue_node: parse logs → raw_observation dict
│   │       ├── anomaly_detector.py      # Rule engine → List[Finding]
│   │       └── responder.py             # Apply mitigations → update SystemState
│   │
│   ├── agents/supervisor/
│   │   ├── __init__.py
│   │   ├── pruner.py                    # prune_node: SEMA structural entropy pruning
│   │   ├── evaluation_agent.py          # evaluation_node: cosine similarity retrieval
│   │   ├── policy_agent.py              # policy_node: Gemini call + episode reflection
│   │   └── gemini_client.py             # Gemini API wrapper (rate-limit aware)
│   │
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── langgraph_flow.py            # StateGraph definition (see Section 6)
│   │   └── reset.py                     # reset_node implementation
│   │
│   ├── memory/
│   │   ├── __init__.py
│   │   ├── short_term.py                # Append/retrieve from M (capped deque)
│   │   └── episode_pool.py              # Append/retrieve/persist E to JSON
│   │
│   ├── scoring/
│   │   ├── __init__.py
│   │   └── risk_engine.py               # risk_node: risk score formula + broadcast trigger
│   │
│   └── ws/
│       ├── __init__.py
│       └── broadcaster.py               # WebSocket connection manager + broadcast()
│
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   └── src/
│       ├── main.tsx
│       ├── App.tsx                      # Layout: sidebar + main grid
│       ├── hooks/
│       │   └── useArenaSocket.ts        # WS hook → parses StepUpdate | EpisodeReport
│       └── components/
│           ├── RiskGauge.tsx            # RadialBarChart, animated, color changes with score
│           ├── AttackFeed.tsx           # Scrolling list of AttackEvent cards
│           ├── DefenseFeed.tsx          # Scrolling list of DefenseEvent cards
│           ├── EpisodeTimeline.tsx      # LineChart: risk_score over steps, multi-episode
│           ├── ActiveMitigations.tsx    # Badge grid of active_mitigations flags
│           └── ReportPanel.tsx          # Renders SupervisorReport JSON as styled panel
│
├── data/
│   ├── logs.jsonl                       # Append-only structured request log (created at runtime)
│   ├── episode_pool.json                # Persisted episode summaries (created at runtime)
│   └── knowledge_base.json             # Static knowledge base (committed, read-only)
│
├── requirements.txt
├── .env                                 # GEMINI_API_KEY (never commit)
├── .env.example                         # Template without real key
└── README.md
```

---

## 8. Backend — File-by-File Specification

### 8.1 FastAPI Target App

#### `backend/target/vuln_store.py`

In-memory store. No database. Deliberately simple.

```python
# Seed data — these are the "records" the target app serves
USERS = {
    "admin":  {"id": 1, "password": "admin123",   "role": "admin",  "email": "admin@corp.com"},
    "alice":  {"id": 2, "password": "alice2024",  "role": "user",   "email": "alice@corp.com"},
    "bob":    {"id": 3, "password": "bob2024",    "role": "user",   "email": "bob@corp.com"},
    "guest":  {"id": 4, "password": "guest",      "role": "guest",  "email": "guest@corp.com"},
}

DATA_RECORDS = {
    1: {"id": 1, "owner": "admin", "content": "CONFIDENTIAL: Q3 financials..."},
    2: {"id": 2, "owner": "alice", "content": "Alice's private notes"},
    3: {"id": 3, "owner": "bob",   "content": "Bob's private notes"},
    4: {"id": 4, "owner": "admin", "content": "CONFIDENTIAL: Employee salaries..."},
}

# Active sessions: token → username
SESSIONS: dict[str, str] = {}

# Transfer log
TRANSFERS: list[dict] = []
```

#### `backend/target/router.py`

All vulnerable endpoints. Vulnerabilities are real but controlled. Feature flags from `SystemState.active_mitigations` can enable patched behavior.

```python
# Mount with: app.include_router(target_router, prefix="/target")

@router.post("/login")
async def login(body: LoginRequest, request: Request):
    """
    VULNERABILITY 1: SQL Injection (simulated — we use string matching not real SQL,
    but the logic flaw is equivalent).
    VULNERABILITY 2: Username enumeration via different error messages.
    VULNERABILITY 3: No rate limiting (enforced externally by middleware only if
    active_mitigations["rate_limit_login"] is True).
    VULNERABILITY 4: Timing side channel (hash check only runs for real users).

    Feature flag: active_mitigations["proper_auth"] → use constant-time check + generic error
    """

@router.get("/data")
async def get_data(id: int, request: Request, token: str = Header(None)):
    """
    VULNERABILITY: IDOR — no authorization check on record ownership.
    Any authenticated user can read any record by ID.

    Feature flag: active_mitigations["idor_check_enabled"] → enforce owner == current_user
    """

@router.get("/admin")
async def admin_panel(request: Request, token: str = Header(None)):
    """
    VULNERABILITY: Weak token check — checks if "admin" is a substring of the token.
    A token like "notadminx" passes the check.

    Feature flag: active_mitigations["proper_admin_auth"] → validate token cryptographically
    """

@router.post("/transfer")
async def transfer(body: TransferRequest, request: Request, token: str = Header(None)):
    """
    VULNERABILITY 1: No CSRF protection.
    VULNERABILITY 2: No re-authentication for sensitive action.
    VULNERABILITY 3: Mass assignment — extra fields in body are accepted.

    Feature flag: active_mitigations["csrf_protection"] → validate CSRF token header
    """

@router.get("/files")
async def get_file(path: str, request: Request):
    """
    VULNERABILITY: Path traversal — no sanitization of the path parameter.
    GET /files?path=../../../../etc/passwd succeeds.

    Feature flag: active_mitigations["path_sanitization"] → os.path.basename() + jail check
    """
```

**Implementation note for the coding agent:** The login endpoint must implement the SQLi logic flaw as string pattern matching, not real SQL. Check for `' --`, `' OR`, `UNION SELECT` patterns in the username/password fields and if detected (and `proper_auth` mitigation is NOT active), return HTTP 200 with a forged session token. This simulates a successful SQLi bypass without requiring a real database.

#### `backend/target/middleware.py`

This middleware runs on every request to the target router. It is the enforcement layer for blue team mitigations.

```python
# Applied as: app.add_middleware(SecurityMiddleware)
# Reads directly from the shared system_state singleton

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 1. IP blocking check — return 403 immediately if IP is blocked
        # 2. Rate limiting check — return 429 if endpoint is rate-limited and over threshold
        #    Use sliding window: defaultdict(lambda: defaultdict(deque))
        #    Window size: 60 seconds
        # 3. Pass through to route handler
        # 4. Log the completed request to logs.jsonl (ALWAYS, even for blocked requests)
        pass
```

**Log format — every line in `logs.jsonl` must be this exact structure:**

```json
{
  "timestamp": 1718000000.123,
  "ip": "127.0.0.1",
  "method": "POST",
  "path": "/target/login",
  "status_code": 401,
  "response_time_ms": 45.2,
  "request_body_hash": "sha256_of_body_or_empty_string",
  "query_params": {"id": "1"},
  "user_agent": "python-httpx/0.27.0",
  "content_length": 42,
  "blocked_by_middleware": false,
  "rate_limited": false
}
```

**The coding agent must NOT store request bodies in logs** — only the SHA-256 hash. This is intentional for demo safety.

---

### 8.2 Red Team Agents

#### `backend/agents/red/strategy.py` — `red_node`

This is the LangGraph node function. It selects which attack agent to run using entropy-weighted routing.

```python
AGENT_ROSTER = ["recon", "bruteforce", "sqli", "idor", "path_traversal", "auth_bypass"]

def compute_weights(state: SystemState) -> dict[str, float]:
    """
    Weight formula:
    - Base weight: 1.0 for all agents
    - Penalty: divide by (1 + recent_use_count) where recent_use_count is
      how many of the last 10 short_term_memory entries used this agent
    - Block penalty: weight = 0.0 if the agent's primary target endpoint
      is in state["rate_limited_endpoints"] AND all credentials are exhausted
    - Boost: multiply by 2.0 if supervisor's next_episode_strategy mentions this agent type
    Returns: dict of agent_name → weight (will be softmax-normalized for sampling)
    """

def red_node(state: SystemState) -> dict:
    weights = compute_weights(state)
    # Softmax normalize
    # Random sample with weights (use random.choices)
    selected = sample_agent(weights)
    result = run_agent(selected, state)
    return {"last_attack": result}
```

**Attack agents are called synchronously.** Each returns an `AttackEvent` dict. They use `httpx.Client` (sync), not async, because LangGraph nodes are sync by default.

#### `backend/agents/red/recon.py`

```python
TARGET_BASE = "http://127.0.0.1:8000/target"

ENDPOINT_WORDLIST = [
    "/login", "/admin", "/data", "/transfer", "/files",
    "/users", "/api", "/debug", "/health", "/docs",
    "/openapi.json", "/config", "/backup", "/metrics",
    "/api/v1", "/api/v2", "/internal", "/.env", "/status"
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

SECURITY_HEADERS_TO_CHECK = [
    "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy",
    "Strict-Transport-Security", "Access-Control-Allow-Origin",
    "X-XSS-Protection", "Referrer-Policy"
]

def run(state: SystemState) -> AttackEvent:
    """
    Phase 1 — Endpoint enumeration:
      For each path in ENDPOINT_WORDLIST, send GET request.
      Record: status_code, content_type, content_length, response_time_ms.
      If /openapi.json returns 200, parse it and extract all route paths/methods.

    Phase 2 — Method probing:
      For endpoints that returned 200 or 405, try all HTTP_METHODS.
      Record which methods are accepted (200/201) vs rejected (405).

    Phase 3 — Header analysis:
      For each discovered endpoint, check for missing SECURITY_HEADERS_TO_CHECK.
      Missing headers are findings: severity "low" to "medium".

    Phase 4 — Timing enumeration on /login:
      Send 5 requests with random (non-existent) usernames, record response times.
      Send 5 requests with usernames from USERS dict (known-good), record times.
      If mean(known_times) > mean(unknown_times) * 1.3: timing oracle confirmed.

    Phase 5 — Length oracle on /data:
      Request /data?id=1 through /data?id=10 without auth.
      Record content lengths. Variation in 200-range responses → IDOR surface confirmed.

    Returns AttackEvent with:
      type="recon"
      result="success" always (recon always produces data)
      evidence=JSON summary of findings
      severity="info"
    """
```

#### `backend/agents/red/bruteforce.py`

```python
COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "Password1", "qwerty",
    "welcome", "monkey", "1234567890", "password123", "admin123",
    "guest", "test", "user", "login", "pass", "secret", "root"
]

COMMON_USERNAMES = [
    "admin", "administrator", "user", "test", "guest", "root",
    "john", "alice", "bob", "service", "api", "operator"
]

# Known leaked credential pairs (credential stuffing simulation)
LEAKED_CREDENTIALS = [
    ("admin", "admin123"), ("admin", "admin"),
    ("guest", "guest"),   ("user", "user2024"),
    ("alice", "alice2024"), ("bob", "bob2024"),
    ("root", "toor"),     ("test", "test123"),
]

def run(state: SystemState, slow_mode: bool = False) -> AttackEvent:
    """
    Phase 1 — Credential stuffing:
      Try all LEAKED_CREDENTIALS pairs against /login.
      Stop immediately on first success.
      If slow_mode=True: sleep random.uniform(0.5, 3.0) between attempts.

    Phase 2 — Password spraying (if stuffing failed):
      For each password in COMMON_PASSWORDS:
        For each username in COMMON_USERNAMES:
          Skip if already tried (check state["short_term_memory"] for previous attempts).
          POST /login with {"username": username, "password": password}
          On 200: capture session token from response body, mark success.
          On 429: switch to slow_mode and continue.
          On 403: IP is blocked — return AttackEvent with result="blocked".
          If slow_mode: sleep random.uniform(1.0, 5.0)

    Phase 3 — Response discrimination:
      Parse response body for discriminating strings:
        "User not found" → username does not exist
        "Invalid password" → username exists (add to confirmed_users list)
        "Account locked" → username exists but locked
        "Authentication failed" → generic (patched behavior)
      Store confirmed_users in state for future use.

    On success: store token in state["short_term_memory"][-1]["harvested_token"]
    Returns AttackEvent with type="bruteforce", result="success"|"blocked"|"failed"
    """
```

**Slow mode activation rule:** If the last 3 bruteforce attempts all returned 429, switch to slow mode automatically.

#### `backend/agents/red/exploit.py`

This is the most complex red agent. It contains multiple exploit techniques, each as a separate function, called based on what the recon agent previously discovered.

```python
# ── SQLi Payloads ──────────────────────────────────────────────────────────────

SQLI_AUTH_BYPASS_PAYLOADS = [
    ("admin' --",          ""),           # Comment out password check
    ("admin'/*",           "*/--"),       # Block comment variant
    ("' OR '1'='1' --",   ""),           # Always-true condition
    ("admin' OR 1=1 --",  ""),           # Numeric always-true
    ("') OR ('1'='1",     ""),           # Parenthesis variant
]

SQLI_UNION_PAYLOADS = [
    "' UNION SELECT 1,username,password,4 FROM users --",
    "' UNION SELECT null,null,null,null --",   # column count probe
]

SQLI_BLIND_PAYLOAD = "admin' AND SLEEP(3) --"   # time-based blind

# ── IDOR Parameters ────────────────────────────────────────────────────────────

IDOR_ID_RANGE = range(1, 20)   # iterate through /data?id=1 to /data?id=19

# ── Path Traversal Payloads ────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",    # URL-encoded
    "%252e%252e%252f%252e%252fetc%252fpasswd",       # Double-encoded
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",  # Windows
]

PATH_TRAVERSAL_SUCCESS_PATTERNS = ["root:x:0:0", "nobody:", "[boot loader]", "127.0.0.1"]

# ── Auth Bypass Tokens ─────────────────────────────────────────────────────────

AUTH_BYPASS_TOKENS = [
    "admin",             # direct match
    "notadmin",          # substring attack
    "xadminx",           # substring attack
    "admin_user",        # prefix attack
    "superadmin",        # contains "admin"
    "ADMIN",             # case variation
    "Admin",             # case variation
    "'; DROP TABLE--",   # injection in token field
    "",                  # empty token
    "null",              # null string
    "undefined",         # JS undefined
    "Bearer admin",      # Bearer prefix
]

# ── Mass Assignment Body ───────────────────────────────────────────────────────

MASS_ASSIGN_PAYLOADS = [
    {"amount": 0.01, "to": "attacker", "is_admin": True},
    {"amount": 0.01, "to": "attacker", "role": "admin"},
    {"amount": 0.01, "to": "attacker", "__admin__": True},
]

def run(state: SystemState) -> AttackEvent:
    """
    Selects which exploit technique to run based on:
    1. What the recon agent found (stored in short_term_memory)
    2. What has already been tried (avoid repeating successful + patched exploits)
    3. Whether a session token is available (some exploits need auth)

    Priority order:
    1. SQLi on /login (no auth needed, highest severity)
    2. Path traversal on /files (no auth needed, high severity)
    3. Auth bypass on /admin (no auth needed)
    4. IDOR on /data (needs any valid session token)
    5. Mass assignment on /transfer (needs valid session token)
    6. CSRF on /transfer (needs victim session token)

    Each technique documented below:

    ── run_sqli_auth_bypass() ──────────────────────────────────────────────────
    Try each SQLI_AUTH_BYPASS_PAYLOADS pair as {username, password}.
    Success condition: HTTP 200 AND response body contains "token" or "session".
    Detection: response has {"token": "..."} structure.
    CWE: CWE-89, severity: critical.

    ── run_sqli_union() ────────────────────────────────────────────────────────
    Requires knowing column count first (try null probes).
    Send UNION SELECT payloads in username field.
    Success: response body length > 500 bytes (data dump) or contains email patterns.
    CWE: CWE-89, severity: critical.

    ── run_sqli_blind() ────────────────────────────────────────────────────────
    Send SQLI_BLIND_PAYLOAD, measure response time.
    Success: response_time > 2.5 seconds (confirms sleep(3) executed).
    CWE: CWE-89, severity: high (blind is harder to exploit but confirms vuln).

    ── run_idor() ──────────────────────────────────────────────────────────────
    Requires: a valid session token from a non-admin user.
    For each id in IDOR_ID_RANGE:
      GET /data?id={id} with the non-admin token.
      Success: HTTP 200 AND record owner != current_user.
    Record all successful IDs and their content snippets.
    CWE: CWE-639, severity: high.

    ── run_path_traversal() ────────────────────────────────────────────────────
    For each payload in PATH_TRAVERSAL_PAYLOADS:
      GET /files?path={payload}
      Check response body for any PATH_TRAVERSAL_SUCCESS_PATTERNS.
      First match = success, return immediately.
    CWE: CWE-22, severity: high.

    ── run_auth_bypass() ───────────────────────────────────────────────────────
    For each token in AUTH_BYPASS_TOKENS:
      GET /admin with Authorization: Bearer {token}
      Success: HTTP 200.
    CWE: CWE-284, severity: critical.

    ── run_mass_assignment() ───────────────────────────────────────────────────
    Requires: valid session token.
    POST /transfer with each MASS_ASSIGN_PAYLOADS body.
    Success: HTTP 200 AND response indicates elevated action was performed.
    CWE: CWE-915, severity: medium.
    """
```

---

### 8.3 Blue Team Agents

#### `backend/agents/blue/log_monitor.py` — `blue_node`

This is the LangGraph node function for the blue team. It orchestrates log parsing → anomaly detection → response.

```python
LOG_FILE = "data/logs.jsonl"
LOG_WINDOW_SECONDS = 60     # look at last 60 seconds of logs
MAX_LINES_TO_READ = 500     # never read more than 500 lines from end of file

def build_raw_observation(recent_logs: list[dict]) -> dict[str, float]:
    """
    Builds the raw_observation dict from recent log entries.
    All values must be float for the structural entropy pruner.

    Returns dict with exactly these keys (always present, 0.0 if not applicable):
    {
        # Volume
        "total_requests":           float,
        "unique_ips":               float,
        "requests_login":           float,
        "requests_data":            float,
        "requests_admin":           float,
        "requests_files":           float,
        "requests_transfer":        float,

        # Error rates
        "rate_401":                 float,   # fraction of responses that were 401
        "rate_403":                 float,
        "rate_429":                 float,
        "rate_500":                 float,
        "rate_200":                 float,

        # Top IP concentration
        "top_ip_request_fraction":  float,   # requests from busiest IP / total
        "max_ip_requests":          float,   # absolute count from busiest IP

        # Timing
        "avg_response_ms":          float,
        "max_response_ms":          float,   # indicator for time-based SQLi

        # Auth signals
        "failed_logins":            float,
        "successful_logins":        float,
        "unique_usernames_tried":   float,
        "login_success_rate":       float,

        # Attack signatures
        "sqli_patterns_detected":   float,   # count of requests matching SQLi regex
        "path_traversal_detected":  float,   # count of requests matching traversal regex
        "large_payload_count":      float,   # count of requests with body > 1024 bytes

        # IDOR signals
        "sequential_id_requests":   float,   # count of /data?id= sequential patterns
        "admin_probe_count":        float,   # count of /admin requests with non-admin tokens

        # Defense state (read from SystemState)
        "blocked_ip_count":         float,
        "rate_limited_endpoint_count": float,
        "active_mitigation_count":  float,
    }
    """

def blue_node(state: SystemState) -> dict:
    logs = read_recent_logs(LOG_FILE, LOG_WINDOW_SECONDS, MAX_LINES_TO_READ)
    raw_obs = build_raw_observation(logs)
    findings = run_anomaly_detection(raw_obs, logs, state)
    defense_event = apply_mitigations(findings, state)
    return {
        "raw_observation": raw_obs,
        "last_defense": defense_event,
        "current_findings": findings,
        # Mitigations update state directly via responder
    }
```

**SQLi detection regex:**
```python
SQLI_REGEX = re.compile(
    r"('|\"|;|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b"
    r"|\bDELETE\b|\bUPDATE\b|1=1|1%3d1|sleep\s*\()",
    re.IGNORECASE
)
```

**Path traversal detection regex:**
```python
TRAVERSAL_REGEX = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)",
    re.IGNORECASE
)
```

Note: detection runs against `query_params` values from log entries, not request bodies (which are hashed). The target endpoints echo back certain request parameters in error messages — those echoes appear in response content, which we do log snippets of for detected anomalies only.

#### `backend/agents/blue/anomaly_detector.py`

Complete rule set. Each rule is a function taking `(raw_obs, recent_logs, state)` and returning `Optional[Finding]`.

```python
# ── Volume-based rules ─────────────────────────────────────────────────────────

def rule_high_login_rate(obs, logs, state) -> Optional[Finding]:
    """
    RULE_HIGH_LOGIN_RATE
    Trigger: obs["failed_logins"] > 10 AND obs["max_ip_requests"] > 8
    Severity: medium
    Action: rate_limit /login
    Evidence: {count: obs["failed_logins"], top_ip: <ip>, attempts: <list>}
    """

def rule_endpoint_flood(obs, logs, state) -> Optional[Finding]:
    """
    RULE_ENDPOINT_FLOOD
    Trigger: any single endpoint has > 50 requests in the window
    Severity: medium
    Action: rate_limit <endpoint>
    """

def rule_ip_recon_sweep(obs, logs, state) -> Optional[Finding]:
    """
    RULE_IP_RECON_SWEEP
    Trigger: single IP has requests to > 7 distinct endpoints in window
    Severity: low
    Action: alert_only (flag for monitoring, don't block yet)
    Detection method: group logs by IP, count distinct paths per IP.
    """

# ── Signature-based rules ─────────────────────────────────────────────────────

def rule_sqli_signature(obs, logs, state) -> Optional[Finding]:
    """
    RULE_SQLI_SIGNATURE
    Trigger: obs["sqli_patterns_detected"] > 0
    Severity: critical
    Action: block_ip (block the source IP immediately)
    Evidence: the specific log entry that triggered it
    """

def rule_path_traversal(obs, logs, state) -> Optional[Finding]:
    """
    RULE_PATH_TRAVERSAL
    Trigger: obs["path_traversal_detected"] > 0
    Severity: high
    Action: block_ip
    """

def rule_large_get_payload(obs, logs, state) -> Optional[Finding]:
    """
    RULE_LARGE_GET_PAYLOAD
    Trigger: obs["large_payload_count"] > 3
    Severity: low
    Action: alert_only
    """

# ── Behavioral rules ───────────────────────────────────────────────────────────

def rule_sequential_idor(obs, logs, state) -> Optional[Finding]:
    """
    RULE_SEQUENTIAL_IDOR
    Trigger: same IP has requested /data?id=N for 3+ consecutive integers
    Detection: group /data logs by IP, extract id params, check for arithmetic sequences
    Use: sorted id list → check if any 3 consecutive form arithmetic sequence with diff=1
    Severity: high
    Action: patch_endpoint (enables active_mitigations["idor_check_enabled"])
    """

def rule_credential_stuffing(obs, logs, state) -> Optional[Finding]:
    """
    RULE_CREDENTIAL_STUFFING
    Trigger: obs["unique_usernames_tried"] > 5 AND obs["login_success_rate"] < 0.05
    Severity: high
    Action: rate_limit /login (stricter than high_login_rate: 3 req/min instead of 10)
    """

def rule_admin_probing(obs, logs, state) -> Optional[Finding]:
    """
    RULE_ADMIN_PROBING
    Trigger: obs["admin_probe_count"] > 3
    Severity: high
    Action: patch_endpoint (enables active_mitigations["proper_admin_auth"])
    """

def rule_slow_scripted_probe(obs, logs, state) -> Optional[Finding]:
    """
    RULE_SLOW_SCRIPTED_PROBE
    Trigger: single IP has regular inter-arrival times (coefficient of variation < 0.3)
             AND average inter-arrival time is between 0.5s and 6.0s
             AND > 5 requests in the window from that IP
    Detection: compute inter-arrival times per IP → std/mean = coefficient of variation
    Purpose: catches slow_mode bruteforce that evades rate-based rules
    Severity: medium
    Action: block_ip (pre-emptive block on scripted behavior)
    """

def rule_time_based_sqli(obs, logs, state) -> Optional[Finding]:
    """
    RULE_TIME_BASED_SQLI
    Trigger: obs["max_response_ms"] > 2500 AND the slow request was to /login
    Detection: find the log entry with max response_time_ms, check if path == /login
    Severity: high
    Action: block_ip of source + patch_endpoint (enables proper_auth)
    Note: This specifically catches time-based blind SQLi (SLEEP payload)
    """

# Rule execution order (critical — run in this order, stop after critical finding)
RULE_PIPELINE = [
    rule_sqli_signature,        # critical — always first
    rule_path_traversal,        # critical
    rule_time_based_sqli,       # high
    rule_sequential_idor,       # high
    rule_admin_probing,         # high
    rule_credential_stuffing,   # high
    rule_slow_scripted_probe,   # medium
    rule_high_login_rate,       # medium
    rule_endpoint_flood,        # medium
    rule_ip_recon_sweep,        # low
    rule_large_get_payload,     # low
]
```

#### `backend/agents/blue/responder.py`

```python
def apply_mitigations(findings: list[Finding], state: SystemState) -> DefenseEvent:
    """
    Processes the first (highest-severity) finding from the pipeline.
    Returns the DefenseEvent representing what action was taken.

    Action implementations:

    "block_ip":
      Append source_ip to state["blocked_ips"] if not already present.
      The middleware will enforce this on the next request.

    "rate_limit":
      Add endpoint to state["rate_limited_endpoints"] with threshold from config.
      Threshold values by trigger rule:
        RULE_HIGH_LOGIN_RATE:      10 req/min
        RULE_CREDENTIAL_STUFFING:  3 req/min
        RULE_ENDPOINT_FLOOD:       20 req/min

    "patch_endpoint":
      Set the appropriate flag in state["active_mitigations"]:
        RULE_SEQUENTIAL_IDOR   → active_mitigations["idor_check_enabled"] = True
        RULE_ADMIN_PROBING     → active_mitigations["proper_admin_auth"] = True
        RULE_TIME_BASED_SQLI   → active_mitigations["proper_auth"] = True

    "alert_only":
      Append to state["vulnerabilities_found"] with evidence.
      No enforcement action.

    If findings is empty: return DefenseEvent with action="none".
    """
```

---

### 8.4 Supervisor Agents

#### `backend/agents/supervisor/pruner.py` — `prune_node`

This is the direct implementation of SEMA Algorithm 1. See Section 2 for the mathematics. Full implementation:

```python
import networkx as nx
import numpy as np
from backend.config import PRUNE_ALPHA, PRUNE_BETA, PRUNE_MU, PRUNE_N

def build_attribute_graph(obs: dict[str, float], prev_obs: dict[str, float]) -> nx.Graph:
    """
    Builds weighted undirected graph G = (V, E, W).
    V = observation attribute names (string node IDs)
    E = all pairs of attributes
    W = spatio-temporal correlation of their deltas (SEMA eq. 6-7)

    For each pair (i, j):
      Δᵢ = |obs[i] - prev_obs.get(i, obs[i])|
      Φ(Δᵢ, Δⱼ) = |Δᵢ · Δⱼ| · ln(1 + |Δᵢ · Δⱼ|)
      wᵢⱼ = Φ / max(all Φ values)   [L∞ normalization]
    """

def structural_entropy_1d(G: nx.Graph) -> float:
    """
    H₁(G) = −Σᵥ (dᵥ / vol(G)) · log₂(dᵥ / vol(G))   [SEMA eq. 2]
    dᵥ = weighted degree of node v
    vol(G) = sum of all weighted degrees
    Returns 0.0 if graph has no edges.
    """

def compute_delta_h_graph(G: nx.Graph, node: str) -> float:
    """
    ΔHG = |H₁(G) - H₁(G \ {node})|
    Measures impact of removing this node on global structural entropy.
    """

def compute_delta_h_tree(G: nx.Graph, node: str) -> float:
    """
    ΔHT = approximated by change in local clustering coefficient of node.
    Full 2D structural entropy (SEMA eq. 3-4) requires encoding tree construction
    which is complex. For this implementation, use nx.clustering(G, node) as
    a proxy for the node's contribution to the tree's structural entropy.
    This approximation is acceptable for a hackathon implementation.
    """

def prune_observation(state: SystemState) -> dict:
    """
    Full SEMA Algorithm 1 implementation:

    1. Get current obs from state["raw_observation"]
    2. Get prev_obs from state["short_term_memory"][-1]["obs"] if memory exists,
       else use obs itself (no delta, all weights = 0, nothing pruned)
    3. Build G = build_attribute_graph(obs, prev_obs)
    4. For each node v in G:
       δH_v = PRUNE_ALPHA * compute_delta_h_graph(G, v)
             + PRUNE_BETA  * compute_delta_h_tree(G, v)
    5. Vcand = {v : δH_v < PRUNE_MU}
    6. If |Vcand| > PRUNE_N: Vremove = top-N by lowest δH from Vcand
       Else: Vremove = Vcand
    7. pruned_obs = {k: v for k, v in obs.items() if k not in Vremove}
    8. Return {"pruned_observation": pruned_obs}

    Log pruning stats: how many attributes removed, which ones, for debugging.
    """
```

#### `backend/agents/supervisor/evaluation_agent.py` — `evaluation_node`

```python
def vectorize_obs(obs: dict[str, float]) -> np.ndarray:
    """Convert obs dict to numpy array with consistent key ordering (sorted keys)."""

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Standard cosine similarity. Returns 0.0 if either vector is zero."""

def evaluation_node(state: SystemState) -> dict:
    """
    1. Vectorize current pruned_observation
    2. For each entry in short_term_memory:
       - Vectorize entry["obs"] (use same sorted key order)
       - Compute cosine similarity with current obs vector
    3. Find entry with highest similarity
    4. Extract entry["defense_action"] as prior_recommendation
    5. Return {
         "retrieved_similar_step": best_entry,
         "prior_recommendation": best_entry["defense_action"] if best_entry else "none"
       }

    If short_term_memory is empty: return {"retrieved_similar_step": None, "prior_recommendation": "none"}
    """
```

#### `backend/agents/supervisor/policy_agent.py` — `policy_node`

```python
POLICY_SYSTEM_PROMPT = """You are a senior cybersecurity analyst AI reviewing one episode of automated adversarial testing against a web application.

Your analysis must be grounded in the provided data only. Do not fabricate vulnerabilities not evidenced in the data.

You will receive:
- PRUNED OBSERVATION: Key security metrics from the final state of the episode (pre-filtered by structural entropy to show only high-signal attributes)
- ATTACK HISTORY: The last 10 attack events from this episode
- DEFENSE ACTIONS: Mitigations applied during this episode
- VULNERABILITIES FOUND: Confirmed findings from the rule-based detection system
- EPISODE SUMMARIES: Lessons from previous episodes (may be empty for episode 1)
- KNOWLEDGE BASE: Relevant CVE patterns and security rules

Your output must be valid JSON and nothing else. No markdown, no explanations outside the JSON structure."""

POLICY_USER_PROMPT = """EPISODE {episode} SUMMARY

PRUNED OBSERVATION (high-entropy attributes only):
{pruned_obs_json}

ATTACK HISTORY (last 10 events):
{attack_history_json}

DEFENSE ACTIONS TAKEN:
{defense_history_json}

RULE-BASED FINDINGS:
{vulnerabilities_json}

PREVIOUS EPISODE SUMMARIES:
{episode_pool_excerpts}

KNOWLEDGE BASE EXCERPTS:
{knowledge_snippets}

Produce your analysis as this exact JSON schema:
{{
  "risk_score": <float 0.0-1.0>,
  "vulnerabilities": [
    {{
      "name": "<vulnerability name>",
      "severity": "<low|medium|high|critical>",
      "endpoint": "<affected endpoint path>",
      "cwe": "<CWE-XXX>",
      "evidence": "<one sentence of evidence from the data>"
    }}
  ],
  "mitigations": ["<concrete mitigation step>"],
  "next_episode_strategy": "<one sentence strategy recommendation for the red team>",
  "episode_summary": "<two sentence summary for the memory pool>"
}}"""

def policy_node(state: SystemState) -> dict:
    """
    1. Build the prompt from state fields (see POLICY_USER_PROMPT template)
    2. Select relevant K excerpts from knowledge_base (simple keyword match on
       vulnerability names found)
    3. Call Gemini via gemini_client.py
    4. Parse response as JSON — if parsing fails, retry once with explicit JSON instruction
    5. Append report["episode_summary"] to state["episode_pool"]
    6. Persist episode_pool to data/episode_pool.json
    7. Return {"supervisor_report": parsed_report}

    Context window budget:
    - pruned_obs: ~200 tokens (pruned from 20+ attributes to ~8-10)
    - attack_history: last 10 events ≈ 400 tokens
    - defense_history: last 10 events ≈ 200 tokens
    - episode_pool: last 3 summaries ≈ 300 tokens
    - knowledge_snippets: top 3 matching ≈ 300 tokens
    - prompts: ~400 tokens
    Total: ~1800 tokens input — well within Gemini Flash free tier
    """
```

#### `backend/agents/supervisor/gemini_client.py`

```python
import google.generativeai as genai
import time
from backend.config import GEMINI_MODEL, GEMINI_MAX_RETRIES, GEMINI_RETRY_DELAY_S

def call_gemini(system_prompt: str, user_prompt: str) -> str:
    """
    Wraps genai.GenerativeModel call with:
    - Retry logic (max GEMINI_MAX_RETRIES retries on ResourceExhausted)
    - Exponential backoff starting at GEMINI_RETRY_DELAY_S seconds
    - Returns response.text as string
    - Raises RuntimeError after max retries exhausted

    Rate limit awareness: Gemini 1.5 Flash free tier is 15 RPM, 1500 RPD.
    We call this once per episode. At max speed (50 steps/episode, ~1s per step),
    one episode takes ~50 seconds. That is well under 1 call/minute.
    """

def configure_gemini(api_key: str):
    """Call once at startup: genai.configure(api_key=api_key)"""
```

---

### 8.5 Memory System

#### `backend/memory/short_term.py`

```python
from collections import deque
from backend.config import MAX_MEMORY_SIZE

# This is a module-level singleton, not stored in SystemState directly
# (SystemState stores a list copy for LangGraph serialization)
_memory: deque = deque(maxlen=MAX_MEMORY_SIZE)

def append_step(obs: dict, attack: dict, defense: dict, result: str):
    """
    Appends one tuple to M.
    Structure: {"obs": obs, "attack": attack, "defense": defense,
                "result": result, "harvested_token": attack.get("token")}
    deque handles maxlen eviction automatically.
    """

def get_all() -> list[dict]:
    """Returns list copy of current deque contents (for SystemState serialization)."""

def clear():
    """Called by reset_node at episode boundary."""
```

#### `backend/memory/episode_pool.py`

```python
POOL_FILE = "data/episode_pool.json"
MAX_POOL_SIZE = 20   # keep last 20 episode summaries

def append_summary(summary: str):
    """Load pool from JSON, append, trim to MAX_POOL_SIZE, save."""

def get_recent(n: int = 3) -> list[str]:
    """Returns last n summaries. Returns [] if file doesn't exist."""

def load_pool() -> list[str]:
    """Load from JSON file. Returns [] if file doesn't exist."""
```

---

### 8.6 Scoring Engine

#### `backend/scoring/risk_engine.py` — `risk_node`

```python
# Risk score formula:
# new_score = clip(old_score * decay + Σ(severity_weights * findings), 0, 1)
#
# severity_weights = {"critical": 0.25, "high": 0.15, "medium": 0.08, "low": 0.02}
# decay = 0.95 (score decays toward 0 if no new findings — defenses working)
# successful_attack_bonus = 0.10 (added when last_attack.result == "success")
# mitigation_discount = -0.05 per active mitigation added this step

def risk_node(state: SystemState) -> dict:
    """
    1. Compute new risk score using formula above
    2. Clip to [0.0, 1.0]
    3. Append to risk_history
    4. Append step tuple to short_term_memory via memory module
    5. Increment step counter
    6. Set supervisor_trigger = True if step >= max_steps
    7. Broadcast updated state to all WebSocket clients
    8. Return updated fields
    """
```

---

### 8.7 WebSocket Broadcaster

#### `backend/ws/broadcaster.py`

```python
from fastapi import WebSocket
from typing import set

class ConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_connections.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active_connections.discard(ws)

    async def broadcast(self, data: dict):
        """Send JSON to all connected clients. Remove disconnected clients silently."""
        dead = set()
        for ws in self.active_connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        self.active_connections -= dead

manager = ConnectionManager()

def broadcast_state(state: SystemState):
    """
    Synchronous wrapper called from risk_node (which runs in sync context).
    Uses asyncio.run_coroutine_threadsafe or asyncio.get_event_loop().
    
    Broadcasts StepUpdate message (see Section 10 for schema).
    """

def broadcast_report(report: SupervisorReport, episode: int):
    """Called from policy_node after Gemini response. Broadcasts EpisodeReport message."""
```

#### `backend/main.py`

```python
from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from backend.graph.langgraph_flow import arena
from backend.state import SystemState
from backend.target.router import target_router
from backend.target.middleware import SecurityMiddleware
from backend.ws.broadcaster import manager
from backend.agents.supervisor.gemini_client import configure_gemini
from backend.memory.episode_pool import load_pool
from backend.config import *
import os
from dotenv import load_dotenv

load_dotenv()

def get_initial_state() -> SystemState:
    """Returns a fully initialized SystemState with all required fields."""
    # Load knowledge_base from data/knowledge_base.json
    # Load episode_pool from data/episode_pool.json (or [] if not exists)
    # All other fields at safe defaults (0, [], {}, False, None)

@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_gemini(os.environ["GEMINI_API_KEY"])
    initial_state = get_initial_state()
    # Run arena loop in background thread (LangGraph is sync)
    loop = asyncio.get_event_loop()
    arena_task = loop.run_in_executor(None, lambda: arena.invoke(initial_state))
    yield
    arena_task.cancel()

app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityMiddleware)
app.include_router(target_router, prefix="/target")

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep connection alive, ignore client messages
    except WebSocketDisconnect:
        manager.disconnect(ws)

@app.get("/state")
async def get_state():
    """REST endpoint for dashboard to fetch current state on initial load."""
```

---

## 9. Frontend Component Specification

### `src/hooks/useArenaSocket.ts`

```typescript
type StepUpdate = {
  type: "step_update"
  episode: number
  step: number
  risk_score: number
  last_attack: AttackEvent | null
  last_defense: DefenseEvent | null
  active_mitigations: Record<string, boolean>
  vulnerabilities_found: string[]
  risk_history: number[]
}

type EpisodeReport = {
  type: "episode_report"
  episode: number
  report: SupervisorReport
}

type ArenaMessage = StepUpdate | EpisodeReport

export function useArenaSocket(url: string = "ws://localhost:8000/ws") {
  // Maintains: currentState, episodeReports[], connectionStatus
  // On message: parse JSON, dispatch to correct state update
  // Reconnects automatically on disconnect (exponential backoff, max 30s)
}
```

### `src/components/RiskGauge.tsx`

- Uses `recharts` `RadialBarChart`
- Color transitions: green (0-0.3) → yellow (0.3-0.6) → orange (0.6-0.8) → red (0.8-1.0)
- Animated value changes (CSS transition on fill)
- Shows numeric score in center with 2 decimal places
- Shows "EPISODE {n} · STEP {n}" below the gauge

### `src/components/AttackFeed.tsx`

- Scrolling list, newest at top, max 50 visible
- Each card shows: attack type badge (color-coded by severity), target endpoint, result badge, timestamp
- Cards animate in from the top on new entries
- "blocked" results shown with strikethrough styling

### `src/components/DefenseFeed.tsx`

- Same pattern as AttackFeed
- Each card shows: action type, trigger rule, affected IP or endpoint

### `src/components/EpisodeTimeline.tsx`

- `recharts` `LineChart`
- X axis: step number (0 to MAX_STEPS)
- Y axis: risk score (0.0 to 1.0)
- Multiple series: one line per episode (different color per episode, max 5 episodes shown)
- Reference lines at 0.3 (low), 0.6 (medium), 0.8 (high) with labels

### `src/components/ActiveMitigations.tsx`

- Grid of badge pills
- Each mitigation flag shown as green (active) or gray (inactive)
- Blocked IPs listed below as monospace chips
- Rate-limited endpoints listed with their current threshold

### `src/components/ReportPanel.tsx`

- Only visible when at least one `EpisodeReport` has been received
- Tabbed: one tab per episode with report
- Shows: risk score (large), vulnerability cards (color-coded by severity), mitigation list, next episode strategy (highlighted box), token count footer
- "No report yet — waiting for episode to complete" placeholder state

---

## 10. Data Contracts and Schemas

### WebSocket Message Types

**StepUpdate** (broadcast every step from `risk_node`):
```json
{
  "type": "step_update",
  "episode": 1,
  "step": 12,
  "risk_score": 0.43,
  "last_attack": {
    "type": "bruteforce",
    "target": "/login",
    "payload": "admin:Password1",
    "result": "blocked",
    "evidence": "HTTP 429 Too Many Requests",
    "cwe": "",
    "severity": "medium",
    "timestamp": 1718000100.5
  },
  "last_defense": {
    "action": "rate_limit",
    "trigger_rule": "RULE_HIGH_LOGIN_RATE",
    "target_ip": "",
    "target_endpoint": "/login",
    "timestamp": 1718000100.6
  },
  "active_mitigations": {
    "rate_limit_login": true,
    "idor_check_enabled": false,
    "proper_admin_auth": false,
    "proper_auth": false,
    "csrf_protection": false,
    "path_sanitization": false
  },
  "vulnerabilities_found": ["Brute force on /login partially succeeded before rate limiting"],
  "risk_history": [0.0, 0.08, 0.16, 0.31, 0.38, 0.43]
}
```

**EpisodeReport** (broadcast once per episode from `policy_node`):
```json
{
  "type": "episode_report",
  "episode": 1,
  "report": {
    "risk_score": 0.73,
    "vulnerabilities": [
      {
        "name": "SQL Injection — Authentication Bypass",
        "severity": "critical",
        "endpoint": "/login",
        "cwe": "CWE-89",
        "evidence": "SQLi payload returned HTTP 200 with admin session token at step 7"
      }
    ],
    "mitigations": [
      "Parameterize all SQL queries on /login endpoint",
      "Implement account lockout after 5 failed attempts",
      "Deploy WAF rule blocking SQL metacharacters in auth fields"
    ],
    "next_episode_strategy": "Shift focus to /files path traversal and /data IDOR — both endpoints remain unmitigated",
    "episode_summary": "Episode 1: SQLi auth bypass succeeded early (step 7) before blue team deployed rate limiting. Admin credentials were exposed. Path traversal and IDOR remain untested.",
    "token_count": 1847
  }
}
```

### `data/knowledge_base.json` (static, committed to repo)

```json
[
  {
    "id": "KB001",
    "tags": ["sqli", "authentication", "CWE-89"],
    "content": "SQL Injection in authentication: Use parameterized queries. Never concatenate user input into SQL strings. Mitigation: prepared statements, ORM with parameter binding, WAF rules for SQL metacharacters."
  },
  {
    "id": "KB002",
    "tags": ["idor", "authorization", "CWE-639"],
    "content": "Insecure Direct Object Reference: Always verify the authenticated user owns the requested resource. Add authorization layer between authentication and data retrieval. Never trust client-supplied IDs without ownership check."
  },
  {
    "id": "KB003",
    "tags": ["path_traversal", "file_access", "CWE-22"],
    "content": "Path Traversal: Sanitize all file path inputs. Use os.path.basename(), validate against a whitelist of allowed directories, use chroot jails. Never pass user input directly to filesystem operations."
  },
  {
    "id": "KB004",
    "tags": ["auth_bypass", "access_control", "CWE-284"],
    "content": "Improper Access Control: Use cryptographic token validation (JWT with signature verification). Never use substring matching for authorization checks. Implement proper RBAC with explicit permission checks."
  },
  {
    "id": "KB005",
    "tags": ["bruteforce", "rate_limiting", "CWE-307"],
    "content": "Credential brute force: Implement rate limiting (max 5 req/min per IP), account lockout after N failures, CAPTCHA for repeated failures, constant-time password comparison, generic error messages."
  },
  {
    "id": "KB006",
    "tags": ["csrf", "transfer", "CWE-352"],
    "content": "Cross-Site Request Forgery: Require CSRF token in all state-changing requests. Verify token on server. Require re-authentication for sensitive operations (transfers, password changes). Check Referer/Origin headers."
  },
  {
    "id": "KB007",
    "tags": ["mass_assignment", "input_validation", "CWE-915"],
    "content": "Mass Assignment: Explicitly whitelist allowed fields in request body models. Never bind entire request body to ORM models. Use separate request/response schemas with only the fields the user should control."
  },
  {
    "id": "KB008",
    "tags": ["timing", "enumeration", "CWE-208"],
    "content": "Timing Side Channel: Use constant-time comparison for all authentication checks. Always compute the password hash even for nonexistent users (use a dummy hash). Return identical error messages for all auth failures."
  }
]
```

---

## 11. Configuration Reference

```python
# backend/config.py

# ── LangGraph execution ────────────────────────────────────────────────────────
MAX_STEPS = 50                    # steps per episode before supervisor is triggered
MAX_EPISODES = 10                 # total episodes before arena stops (0 = infinite)
STEP_DELAY_S = 0.5                # sleep between steps (prevents hammering the target)

# ── Target application ─────────────────────────────────────────────────────────
TARGET_BASE_URL = "http://127.0.0.1:8000/target"
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8000

# ── Memory ─────────────────────────────────────────────────────────────────────
MAX_MEMORY_SIZE = 50              # max entries in short-term memory M (deque maxlen)
MAX_POOL_SIZE = 20                # max episode summaries in E

# ── SEMA pruning parameters ────────────────────────────────────────────────────
PRUNE_ALPHA = 0.95                # weight of global structural entropy ΔHG (from paper)
PRUNE_BETA = 0.05                 # weight of local tree entropy ΔHT (from paper)
PRUNE_MU = 0.05                   # pruning threshold — nodes with δH < MU are candidates
PRUNE_N = 8                       # max nodes to prune per step

# ── Risk scoring ───────────────────────────────────────────────────────────────
RISK_DECAY = 0.95
RISK_SEVERITY_WEIGHTS = {
    "critical": 0.25,
    "high":     0.15,
    "medium":   0.08,
    "low":      0.02,
}
RISK_ATTACK_SUCCESS_BONUS = 0.10
RISK_MITIGATION_DISCOUNT = -0.05

# ── Anomaly detection thresholds ──────────────────────────────────────────────
ANOMALY_LOGIN_RATE_THRESHOLD = 10     # failed logins per 60s → brute force
ANOMALY_FLOOD_THRESHOLD = 50          # requests per endpoint per 60s → flood
ANOMALY_RECON_ENDPOINT_THRESHOLD = 7  # distinct endpoints from one IP → recon
ANOMALY_TIMING_CV_THRESHOLD = 0.3     # coefficient of variation → scripted probe

# ── Rate limiting (mitigations) ───────────────────────────────────────────────
RATE_LIMIT_LOGIN_HIGH = 10            # req/min — high login rate finding
RATE_LIMIT_LOGIN_STUFFING = 3         # req/min — credential stuffing finding
RATE_LIMIT_FLOOD = 20                 # req/min — endpoint flood finding
LOG_WINDOW_SECONDS = 60
MAX_LOG_LINES = 500

# ── Gemini ─────────────────────────────────────────────────────────────────────
GEMINI_MODEL = "gemini-1.5-flash"
GEMINI_MAX_RETRIES = 3
GEMINI_RETRY_DELAY_S = 5.0

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_FILE = "data/logs.jsonl"
EPISODE_POOL_FILE = "data/episode_pool.json"
KNOWLEDGE_BASE_FILE = "data/knowledge_base.json"
```

---

## 12. Startup and Execution Flow

### What happens when you run the application

```
1. uvicorn backend.main:app --reload --port 8000

2. FastAPI lifespan starts:
   a. load_dotenv() → reads GEMINI_API_KEY from .env
   b. configure_gemini(api_key) → initializes Gemini SDK
   c. get_initial_state() → builds clean SystemState
      - Loads knowledge_base.json into state["knowledge_base"]
      - Loads episode_pool.json into state["episode_pool"] (or [])
      - All counters at 0, all lists empty, all flags False
   d. arena.invoke(initial_state) launched in background thread

3. LangGraph arena loop begins:
   Episode 1, Step 0:
   a. red_node: strategy.py selects "recon" (first step, nothing tried yet)
      - recon.py sends HTTP requests to TARGET_BASE_URL
      - Returns AttackEvent with full surface map
   b. blue_node: reads logs.jsonl (may be sparse at this point)
      - Builds raw_observation dict (mostly 0s at step 0)
      - anomaly_detector runs all rules → likely no findings at step 0
      - No defense action taken
   c. prune_node: builds attribute graph
      - prev_obs doesn't exist yet → all deltas = 0 → no pruning → pass through
   d. evaluation_node: short_term_memory is empty → no retrieval → no recommendation
   e. risk_node: no findings → risk_score barely changes from 0.0
      - Appends step 0 tuple to M
      - Broadcasts StepUpdate to WebSocket clients
      - step = 1, supervisor_trigger = False

   ... loop continues for MAX_STEPS steps ...

   Episode 1, Step 50 (MAX_STEPS reached):
   a-e: normal step execution
   e. risk_node: step = 50 → supervisor_trigger = True → returns "policy" from router
   f. policy_node: builds Gemini prompt, calls API, parses JSON response
      - Appends episode summary to episode_pool
      - Persists episode_pool.json
      - Broadcasts EpisodeReport to WebSocket clients
   g. reset_node: episode = 2, step = 0, M cleared, risk_history cleared
   h. Loop returns to red_node for Episode 2

4. Dashboard (separate process, port 5173):
   - Opens WebSocket connection to ws://localhost:8000/ws
   - Receives StepUpdate every ~0.5s
   - Receives EpisodeReport every ~25 seconds (50 steps × 0.5s)
   - Updates all components reactively
```

---

## 13. Environment Setup

### `requirements.txt`

```
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
langgraph>=0.2.0
langchain-core>=0.2.0
google-generativeai>=0.7.0
httpx>=0.27.0
networkx>=3.3
numpy>=1.26.0
python-dotenv>=1.0.0
pydantic>=2.7.0
```

### `.env.example`

```
GEMINI_API_KEY=your_gemini_api_key_here
```

### Frontend setup

```bash
cd frontend
npm create vite@latest . -- --template react-ts
npm install
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
npm install recharts
```

### Running everything

```bash
# Terminal 1 — Backend
cd cyber-defense-arena
pip install -r requirements.txt
uvicorn backend.main:app --port 8000

# Terminal 2 — Frontend
cd cyber-defense-arena/frontend
npm run dev
# Dashboard available at http://localhost:5173
```

---

## 14. Implementation Order

Follow this exact order. Each phase is a working increment you can demo.

### Phase 1 — Target App (Day 1 AM)
1. `backend/target/vuln_store.py` — seed data
2. `backend/target/router.py` — all 5 vulnerable endpoints, NO feature flags yet
3. `backend/target/middleware.py` — logging only (no enforcement yet)
4. `backend/main.py` — minimal: mount router, run uvicorn
5. **Verify:** `curl http://localhost:8000/target/login -d '{"username":"admin","password":"admin123"}'` returns 200

### Phase 2 — LangGraph Skeleton (Day 1 PM)
1. `backend/state.py` — full SystemState TypedDict
2. `backend/config.py` — all constants
3. `backend/graph/langgraph_flow.py` — graph with stub nodes (each node just returns empty dict)
4. `backend/graph/reset.py` — reset_node
5. **Verify:** `arena.invoke(get_initial_state())` runs without error (does nothing useful yet)

### Phase 3 — Red Team (Day 2 AM)
1. `backend/agents/red/recon.py`
2. `backend/agents/red/bruteforce.py`
3. `backend/agents/red/exploit.py`
4. `backend/agents/red/strategy.py` — wire all three agents
5. Replace red_node stub with real implementation
6. **Verify:** Running the graph produces real HTTP traffic in logs.jsonl

### Phase 4 — Blue Team (Day 2 PM)
1. `backend/agents/blue/log_monitor.py`
2. `backend/agents/blue/anomaly_detector.py` — implement all rules
3. `backend/agents/blue/responder.py`
4. Add enforcement to `middleware.py` — read from SystemState
5. Replace blue_node stub
6. **Verify:** After bruteforce runs, rate limiting is applied and next attempts get 429

### Phase 5 — Supervisor (Day 3 AM)
1. `backend/memory/short_term.py`
2. `backend/memory/episode_pool.py`
3. `backend/agents/supervisor/pruner.py` — SEMA Algorithm 1
4. `backend/agents/supervisor/evaluation_agent.py`
5. `backend/agents/supervisor/gemini_client.py`
6. `backend/agents/supervisor/policy_agent.py`
7. Replace prune, evaluation, policy node stubs
8. **Verify:** After 50 steps, Gemini produces a valid JSON report

### Phase 6 — Dashboard (Day 3 PM)
1. `backend/ws/broadcaster.py`
2. Wire broadcast into risk_node and policy_node
3. `backend/main.py` WebSocket endpoint
4. `frontend/src/hooks/useArenaSocket.ts`
5. All 6 components
6. **Verify:** Dashboard updates live while arena loop runs

---

## 15. Critical Rules for the Coding Agent

**Rule 1 — Never call Gemini outside of `policy_agent.py`.**
If you find yourself importing `gemini_client` anywhere else, stop. This is wrong.

**Rule 2 — `SystemState` is append-only within a step.**
Each node returns a dict of fields to update. It does not return the full state. LangGraph merges the returned dict into the state. Never return `state` directly from a node — return only the fields that changed.

**Rule 3 — `logs.jsonl` is append-only.**
Nothing ever deletes or rewrites this file. The log monitor reads the tail. Old entries accumulate. This is intentional — it gives you a complete audit trail.

**Rule 4 — The target app and the agent system share a process.**
Both run inside the same `uvicorn` process. The `SystemState` is a module-level singleton shared between the LangGraph execution thread and the FastAPI middleware. Access it via a module-level variable with appropriate thread safety (use `threading.Lock` for writes to `blocked_ips` and `rate_limited_endpoints`).

**Rule 5 — Red team agents make real HTTP requests using `httpx.Client`.**
Use synchronous `httpx.Client`, not `AsyncClient`. LangGraph nodes are synchronous. The requests go to `TARGET_BASE_URL` which is the same process. This is intentional and is what makes the demo real.

**Rule 6 — Pruning never removes more than half the observation attributes.**
Add a safety check in `pruner.py`: if `len(Vremove) > len(obs) // 2`, cap `Vremove` at `len(obs) // 2`. This prevents over-pruning from sending an empty dict to Gemini.

**Rule 7 — The attack agents must record every attempt in `short_term_memory`.**
Even failed and blocked attempts. The evaluation agent's cosine similarity only works if M has sufficient history. A blocked attack is still informative — it tells you that mitigation N is active.

**Rule 8 — The `knowledge_base.json` is read-only.**
It is loaded once at startup into `state["knowledge_base"]`. The policy agent selects relevant excerpts at call time via keyword matching. It is never modified at runtime.

**Rule 9 — Handle the case where `logs.jsonl` does not exist.**
At startup, the file may not exist. The log monitor must create it if absent and return an empty observation dict gracefully. Do not raise `FileNotFoundError`.

**Rule 10 — The WebSocket broadcast is fire-and-forget.**
If no clients are connected, `broadcast()` does nothing (the connection set is empty). If a client disconnects mid-broadcast, catch the exception silently and remove it from the set. Never let a broadcast failure crash the arena loop.

---

*End of PROMPT.md — this document fully specifies the ACDA system. Implement in the order given in Section 14. When in doubt, refer to the SystemState schema in Section 5 and the LangGraph topology in Section 6 as the ground truth.*
