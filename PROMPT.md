# ACDA — Autonomous Cyber Defense Arena
## Complete Implementation Guide for Coding Agents — **Version 2**

> **For the coding agent:** This document is the single source of truth for the entire project. Read it completely before writing a single line of code. Every architectural decision, every file, every function signature, and every data contract is specified here. Do not deviate from the file structure, the `SystemState` schema, or the LangGraph graph topology without a documented reason. Where implementation details are left to you, use the constraints in this document to make the correct choice.

---

## ⚠️ CHANGE SUMMARY — What Is Different From Version 1

> This section is for Claude Code. Read this before reading anything else. It tells you precisely which files changed, which are new, and which carry over unchanged. Every section that contains a change is marked with a **`🔄 CHANGED`** callout. Sections with no callout are identical to V1 and do not need re-implementation.

### Files That Are **NEW** (do not exist in V1)
```
backend/llm/ollama_client.py          ← NEW: Ollama wrapper for per-step red team reasoning
backend/agents/red/business_logic.py  ← NEW: LLM-discovered business logic attack agent
backend/agents/red/evasion.py         ← NEW: Encoding variants + timing mimicry agent
backend/agents/supervisor/patch_agent.py  ← NEW: Gemini patch generation + verification
backend/graph/patch_node.py           ← NEW: LangGraph node for between-episode patching
```

### Files That Are **SIGNIFICANTLY CHANGED**
```
backend/state.py          ← NEW fields: llm_decision, current_attack_layer,
                             behavioral_fingerprints, patch_records, ioc_export
backend/config.py         ← NEW constants: Ollama model, patch config, layer weights
backend/graph/langgraph_flow.py  ← NEW node: patch_node between policy and reset
                                   NEW routing: patch_node fires every episode
backend/agents/red/strategy.py  ← COMPLETELY REPLACED: was weight-table dispatcher,
                                   now Ollama LLM produces LLMDecision object
backend/agents/red/exploit.py   ← CHANGED: now accepts LLMDecision parameter,
                                   hardcoded lists become fallback defaults only
backend/agents/red/bruteforce.py ← CHANGED: accepts LLMDecision for dynamic targeting
backend/agents/blue/anomaly_detector.py ← NEW rules: behavioral fingerprinting,
                                           encoded SQLi detection, dynamic IOC export
backend/agents/blue/responder.py   ← NEW actions: fingerprint_and_block, export_ioc,
                                      deep_log_attacker
backend/agents/supervisor/policy_agent.py ← CHANGED: now also calls patch_agent,
                                             updated JSON schema with episode_summary
backend/graph/reset.py  ← CHANGED: carries forward behavioral_fingerprints across episodes
data/knowledge_base.json ← NEW entry KB009: double-encoded SQLi detection pattern
requirements.txt         ← NEW dependency: ollama Python client
```

### Files That Are **UNCHANGED** from V1
```
backend/main.py                           (no changes)
backend/agents/red/recon.py               (no changes)
backend/agents/blue/log_monitor.py        (no changes)
backend/agents/supervisor/pruner.py       (no changes — SEMA Algorithm 1 unchanged)
backend/agents/supervisor/evaluation_agent.py  (no changes)
backend/agents/supervisor/gemini_client.py     (no changes)
backend/memory/short_term.py              (no changes)
backend/memory/episode_pool.py            (no changes)
backend/scoring/risk_engine.py            (no changes)
backend/ws/broadcaster.py                 (no changes)
backend/target/router.py                  (no changes)
backend/target/vuln_store.py              (no changes)
backend/target/middleware.py              (no changes)
All frontend files                        (no changes)
```

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
   - 8.1 [FastAPI Target App](#81-fastapi-target-app-unchanged)
   - 8.2 [Red Team Agents](#82-red-team-agents-significantly-changed)
   - 8.3 [Blue Team Agents](#83-blue-team-agents-changed)
   - 8.4 [Supervisor Agents](#84-supervisor-agents-changed)
   - 8.5 [Memory System](#85-memory-system-unchanged)
   - 8.6 [Scoring Engine](#86-scoring-engine-unchanged)
   - 8.7 [WebSocket Broadcaster](#87-websocket-broadcaster-unchanged)
9. [Frontend — Component Specification](#9-frontend-component-specification-unchanged)
10. [Data Contracts and Schemas](#10-data-contracts-and-schemas)
11. [Configuration Reference](#11-configuration-reference)
12. [Startup and Execution Flow](#12-startup-and-execution-flow)
13. [Environment Setup](#13-environment-setup)
14. [Implementation Order](#14-implementation-order)
15. [Critical Rules for the Coding Agent](#15-critical-rules-for-the-coding-agent)

---

## 1. Project Overview

### What This Is

ACDA is a **continuous, autonomous cybersecurity stress-testing system**. It runs a real FastAPI web application with deliberately introduced vulnerabilities, deploys automated Red Team agents to attack it over HTTP, deploys automated Blue Team agents to detect and mitigate those attacks, and uses a Gemini-powered Supervisor to reason about system security posture once per episode.

The result is a **live security dashboard** showing a real cat-and-mouse dynamic: attacks land, defenses respond, risk scores shift, and the supervisor produces actionable vulnerability reports and verified code patches at episode boundaries.

### What This Is NOT

- Not a chatbot. No conversational interface of any kind.
- Not a pure simulation. Red team agents make real HTTP requests to a real running server.
- Not agents talking to each other. They share a `SystemState` dict through LangGraph; they do not communicate directly.

> 🔄 **CHANGED:** The original stated "Not LLM-heavy — Gemini is called once per episode." This is no longer accurate. The new implementation uses **two LLMs**: Ollama (local, free, per-step) for red team reasoning, and Gemini 1.5 Flash (once per episode) for the supervisor. The system is still cost-controlled — Ollama runs locally with no API cost.

### Core Value for a Hackathon Demo

When demoed, a judge sees:
1. Real HTTP traffic hitting a real server (visible in browser devtools or logs panel)
2. A live dashboard with a risk gauge climbing as attacks succeed
3. The blue team blocking IPs and rate-limiting endpoints in real time
4. The red team **discovering vulnerabilities the code never explicitly scripted** — the Ollama LLM reasons from the OpenAPI schema and response patterns to find novel attack surfaces
5. After N steps: Gemini generates a structured vulnerability report with risk score, CVE references, mitigation recommendations, **and verified code patches**
6. The next episode's red team shifting strategy based on the supervisor's recommendation — with **demonstrably different opening moves**
7. A direct, citable connection to the SEMA academic paper (arXiv:2603.23875)

### The Novel Claim

> *"We present the first application of SEMA-style structural entropy pruning to cybersecurity telemetry, enabling LLM-driven autonomous penetration testing with adversarially-verified patch generation. Unlike existing tools that suggest fixes, our system confirms patch effectiveness by re-running the exploits that discovered each vulnerability against the patched application."*

This claim is accurate, demonstrable, and does not exist in current literature.

---

## 2. SEMA Framework

### What SEMA Is

SEMA (Self-Evolving Multi-Agent, arXiv:2603.23875) is a framework for low-latency LLM decision-making in Real-Time Strategy games (StarCraft II). It solves two problems directly analogous to our cybersecurity domain:

| SEMA Problem (StarCraft II) | Our Analog (Cybersecurity) |
|---|---|
| Massive game-state observation causes token overflow | Raw log data is too large to send to Gemini every step |
| LLM stochastic bias causes inconsistent decisions | Gemini called ad-hoc would give inconsistent risk assessments |
| Need real-time response under latency constraint | Attack/defense loop must run fast; LLM in the loop kills speed |

### The Three SEMA Principles We Implement

#### Principle 1 — Structural Entropy-Driven Observation Pruning (Algorithm 1 in paper)

**UNCHANGED from V1.** Before any LLM call, we build a weighted attribute graph from the observation dictionary, score each attribute node by its structural entropy contribution, and remove the lowest-entropy nodes.

The math (from paper Section 4.2):
```
Δᵢ = |obs_t[i] − obs_{t-1}[i]|
Φ(Δᵢ, Δⱼ) = |Δᵢ · Δⱼ| · ln(1 + |Δᵢ · Δⱼ|)     # spatio-temporal operator (eq. 6)
wᵢⱼ = Φ(Δᵢ, Δⱼ) / ‖Wt‖∞                          # normalized edge weight (eq. 7)
H₁(G) = −Σᵥ (dᵥ / vol(G)) · log₂(dᵥ / vol(G))    # eq. 2
δH = α · ΔHG + β · ΔHT                               # eq. 8
```

Nodes with `δH < μ` are removed. This is the direct implementation of Algorithm 1 in `pruner.py`. It is what makes Ollama per-step calls cheap — the LLM receives only the 8-10 highest-signal attributes, not the full 28-attribute raw observation.

> **Clarification for coding agent:** The SEMA entropy equations are used **only for observation pruning** — compressing what gets sent to LLMs. They are NOT used for the action selection weight formula in `strategy.py`. The weight system in `strategy.py` is a separate, simpler heuristic described in Section 8.2.

#### Principle 2 — Three-Agent Role Separation

> 🔄 **CHANGED:** The Decision Agent row is updated. The red team strategist is now LLM-driven via Ollama, not rule-based.

| SEMA Agent | Our Implementation | LLM? | Frequency |
|---|---|---|---|
| Decision Agent | **Red team strategy (Ollama)** | **Yes — Ollama llama3 local** | **Every step** |
| Evaluation Agent | Blue team + memory retrieval | No (cosine similarity) | Every step |
| Policy Agent | Supervisor (Gemini) + patch generation | Yes (Gemini 1.5 Flash) | Once per episode |

The Evaluation Agent still makes **no LLM calls**. The Ollama cost for the Decision Agent is zero — it runs locally. The architecture correctly mirrors SEMA's three-agent structure with the Decision Agent now genuinely LLM-driven.

#### Principle 3 — Hierarchical Memory (L = ⟨M, E, K⟩)

**UNCHANGED from V1.**

| Layer | SEMA | Our Implementation | Storage |
|---|---|---|---|
| M | Micro-memory: step-level trajectory tuples | Last 50 (obs, llm_decision, attack, defense, result) tuples | In-memory deque |
| E | Macro-experience: episode-level strategy summaries | Post-episode Gemini summaries | `data/episode_pool.json` |
| K | External knowledge base: static domain rules | CVE patterns, attack signatures, defense playbooks | `data/knowledge_base.json` |

> 🔄 **CHANGED:** Short-term memory M entries now include `llm_decision` — the structured output from Ollama that caused each attack. This allows the evaluation agent to surface not just what attack happened but **what the LLM reasoned** when deciding it.

---

## 3. Tech Stack and Constraints

### Backend (unchanged from V1 except additions)

- **Python 3.11+**
- **FastAPI**
- **LangGraph 0.2+**
- **`google-generativeai`** — Gemini 1.5 Flash, once per episode
- **`httpx`** — sync HTTP client for red team agents
- **`networkx`** — structural entropy pruning
- **`numpy`** — cosine similarity and entropy math
- **`uvicorn`**
- **`python-dotenv`**

> 🔄 **NEW DEPENDENCY:** **`ollama`** — Python client for local Ollama inference. Install Ollama separately: `https://ollama.ai`. Pull the model before running: `ollama pull llama3`. The Python package: `pip install ollama`.

### Frontend

**UNCHANGED from V1.**

> 🔄 **CHANGED — LLM Usage Policy (HARD CONSTRAINT):**

```
Gemini API calls:  ONLY in policy_agent.py and patch_agent.py
                   ONLY once per episode (combined: policy + patch = 2 Gemini calls/episode)

Ollama calls:      ONLY in strategy.py (red_node)
                   Called every step — this is intentional and free (local inference)
                   Model: llama3 (or mistral as fallback)

NEVER: LLM calls in blue agents, prune_node, evaluation_node, risk_node, or reset_node
NEVER: Gemini calls in strategy.py or any red agent executor
NEVER: Ollama calls in supervisor files
```

The separation is strict: Ollama = attack decisions, Gemini = security analysis + patch generation.

---

## 4. System Architecture

### Execution Loop

> 🔄 **CHANGED:** `patch_node` added between `policy_node` and `reset_node`. Every episode now ends with: policy (Gemini analysis) → patch (Gemini patch generation + verification) → reset.

```
Episode starts
│
└─► [STEP LOOP — runs MAX_STEPS times]
     │
     ├─ red_node         → Ollama reasons from pruned obs → LLMDecision → executor fires HTTP
     ├─ blue_node        → reads logs, detects anomalies, applies mitigations
     ├─ prune_node       → SEMA structural entropy pruning (feeds BOTH Ollama and Gemini)
     ├─ evaluation_node  → cosine similarity retrieval from M
     ├─ risk_node        → update risk score, broadcast to dashboard
     │
     └─ [if step == MAX_STEPS]
          │
          ├─ policy_node  → Gemini: episode analysis → supervisor report → update E
          ├─ patch_node   → Gemini: generate patches → apply via exec() → verify by re-exploit
          └─ reset_node   → increment episode, reset step, clear M (keep fingerprints)
               │
               └─► [next episode begins]
```

### Component Map

> 🔄 **CHANGED:** Ollama added to red team layer. `patch_node` added to episode-end sequence.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        LangGraph StateGraph                          │
│  red → blue → prune → evaluation → risk ──┬──► policy → patch → reset│
│                              ▲            │                          │
│                              └────────────┘ (loop N steps)          │
└──────────────────────────────────────────────────────────────────────┘
    │ (Ollama)          │                         │ (Gemini x2)
    ▼                   ▼                         ▼
 LLM Decision       logs.jsonl              WebSocket /ws + PatchRecord
 (per step)         (append-only)           → React Dashboard
    │
    ▼
 Agent Executor
 (real HTTP)
```

### Two-Layer Red Team Architecture

> 🔄 **CHANGED:** This is the most important architectural change. The red team is now a two-layer system.

```
Layer 1 — LLM Strategist (Ollama)
  Input:  pruned_observation (8-10 attrs) + short_term_memory summary + episode_pool hint
  Output: LLMDecision { technique, target_endpoint, method, params, payload, rationale }
  Role:   Decides WHAT to try next, from first principles, no predefined menu

Layer 2 — Agent Executors (Python, deterministic)
  Input:  LLMDecision from Layer 1
  Role:   Execute the HTTP request the LLM specified, parse response, return AttackEvent
  Files:  recon.py, bruteforce.py, exploit.py, business_logic.py, evasion.py

Key principle: Executors define WHAT IS POSSIBLE (HTTP request categories).
               The LLM decides WHAT TO DO within what is possible.
```

---

## 5. The LangGraph State Schema

> 🔄 **CHANGED:** New fields added. All existing fields from V1 are preserved unchanged. Only additions shown here — do not remove any V1 fields.

```python
# backend/state.py
# CHANGES FROM V1: New TypedDict LLMDecision, new fields in SystemState
# All V1 fields remain — only additions documented here

from typing import TypedDict, List, Dict, Any, Optional

# ── NEW TypedDict ──────────────────────────────────────────────────────────────

class LLMDecision(TypedDict):
    """
    NEW in V2. Structured output from Ollama strategy LLM.
    Produced by strategy.py, consumed by agent executors.
    Stored in short_term_memory alongside the resulting AttackEvent.
    """
    technique: str        # e.g. "sqli_filter_param", "negative_transfer", "path_traversal_encoded"
    target_endpoint: str  # e.g. "/data", "/login", "/transfer"
    method: str           # "GET" | "POST" | "PUT" | "DELETE"
    params: Dict[str, str]   # query parameters
    headers: Dict[str, str]  # custom headers to include
    payload: Dict[str, Any]  # request body (for POST/PUT)
    rationale: str           # LLM's explanation of why it chose this — logged for demo
    attack_layer: int        # 1-6 (network, auth, authz, input, business_logic, evasion)


class PatchRecord(TypedDict):
    """
    NEW in V2. Records the result of one patch attempt.
    Produced by patch_agent.py after each episode.
    """
    vulnerability_name: str
    cwe: str
    endpoint: str
    patch_code: str           # actual Python code generated by Gemini
    patch_applied: bool       # whether exec() succeeded
    verification_payload: str # the specific payload used to verify
    verified: bool            # whether re-exploitation returned expected blocked response
    verification_evidence: str # HTTP status + body after patch applied
    requires_human_review: bool  # True for architectural fixes patch_agent cannot auto-apply


# ── ADDITIONS TO SystemState ───────────────────────────────────────────────────
# Add these fields to the existing SystemState TypedDict in state.py
# All V1 fields remain unchanged

class SystemState(TypedDict):
    # ... all V1 fields unchanged ...

    # 🔄 NEW: Red team LLM decision (updated every step by red_node)
    llm_decision: Optional[LLMDecision]

    # 🔄 NEW: Current attack layer (1-6), tracks escalation progression
    current_attack_layer: int

    # 🔄 NEW: Behavioral fingerprints of blocked attackers
    # Persists across episodes (NOT cleared by reset_node)
    # Allows blue team to identify IP rotation by behavioral similarity
    behavioral_fingerprints: List[Dict[str, Any]]

    # 🔄 NEW: Patch records from patch_node (accumulated across episodes)
    patch_records: List[PatchRecord]

    # 🔄 NEW: IOC (Indicator of Compromise) entries exported to knowledge base
    # When blue team discovers a new attack pattern, it adds it here
    # policy_agent reads these and adds them to knowledge_base for next episode
    ioc_exports: List[Dict[str, Any]]
```

**`get_initial_state()` additions:**
```python
# Add to get_initial_state() in state.py:
llm_decision=None,
current_attack_layer=1,
behavioral_fingerprints=[],   # persists across episodes
patch_records=[],              # accumulates across episodes
ioc_exports=[],
```

---

## 6. The LangGraph Graph Topology

> 🔄 **CHANGED:** `patch_node` added. Import list updated. Routing unchanged except patch fires every episode.

```python
# backend/graph/langgraph_flow.py

from langgraph.graph import StateGraph, END
from backend.state import SystemState

# ── Node imports ──────────────────────────────────────────────────────────────
from backend.agents.red.strategy import red_node
from backend.agents.blue.log_monitor import blue_node
from backend.agents.supervisor.pruner import prune_node
from backend.agents.supervisor.evaluation_agent import evaluation_node
from backend.scoring.risk_engine import risk_node
from backend.agents.supervisor.policy_agent import policy_node
from backend.agents.supervisor.patch_agent import patch_node    # 🔄 NEW
from backend.graph.reset import reset_node

# ── Routing ───────────────────────────────────────────────────────────────────
def route_after_risk(state: SystemState) -> str:
    if state["supervisor_trigger"]:
        return "policy"
    return "red"

# ── Graph definition ──────────────────────────────────────────────────────────
builder = StateGraph(SystemState)

builder.add_node("red",        red_node)
builder.add_node("blue",       blue_node)
builder.add_node("prune",      prune_node)
builder.add_node("evaluation", evaluation_node)
builder.add_node("risk",       risk_node)
builder.add_node("policy",     policy_node)
builder.add_node("patch",      patch_node)    # 🔄 NEW NODE
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
builder.add_edge("policy", "patch")    # 🔄 CHANGED: policy → patch (was policy → reset)
builder.add_edge("patch",  "reset")    # 🔄 NEW EDGE
builder.add_edge("reset",  "red")

arena = builder.compile()
```

**Node responsibility summary:**

> 🔄 **CHANGED:** `red_node` now uses Ollama. `policy_node` output updated. `patch_node` is new.

| Node | Input reads | Output writes | LLM? |
|---|---|---|---|
| `red_node` | `pruned_observation`, `short_term_memory`, `episode_pool`, `active_mitigations`, `blocked_ips`, `current_attack_layer` | `last_attack`, `llm_decision`, `current_attack_layer` | **Yes — Ollama llama3** |
| `blue_node` | reads `logs.jsonl` directly | `raw_observation`, `last_defense`, `current_findings`, `blocked_ips`, `rate_limited_endpoints`, `active_mitigations`, `behavioral_fingerprints` | No |
| `prune_node` | `raw_observation`, `short_term_memory` | `pruned_observation` | No |
| `evaluation_node` | `pruned_observation`, `short_term_memory` | `retrieved_similar_step`, `prior_recommendation` | No |
| `risk_node` | `current_findings`, `last_attack`, `active_mitigations`, `risk_score` | `risk_score`, `risk_history`, `vulnerabilities_found`, `step`, `supervisor_trigger` | No |
| `policy_node` | `pruned_observation`, `short_term_memory`, `episode_pool`, `knowledge_base`, `vulnerabilities_found`, `ioc_exports` | `supervisor_report`, `episode_pool` | **Yes — Gemini** |
| `patch_node` | `supervisor_report["vulnerabilities"]`, `active_mitigations` | `patch_records`, `active_mitigations` (updated) | **Yes — Gemini** |
| `reset_node` | all | `episode++`, `step=0`, `short_term_memory=[]`, `supervisor_trigger=False`, `risk_history=[]`, `ioc_exports=[]` | No |

---

## 7. Complete File Structure

> 🔄 **CHANGED:** New files added. Existing files unchanged in location.

```
cyber-defense-arena/
│
├── backend/
│   ├── main.py
│   ├── state.py                         # 🔄 CHANGED: new fields
│   ├── config.py                        # 🔄 CHANGED: new constants
│   │
│   ├── target/                          # UNCHANGED
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── vuln_store.py
│   │   └── middleware.py
│   │
│   ├── llm/                             # 🔄 NEW DIRECTORY
│   │   ├── __init__.py
│   │   └── ollama_client.py             # 🔄 NEW: Ollama wrapper
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── red/
│   │   │   ├── __init__.py
│   │   │   ├── strategy.py              # 🔄 COMPLETELY REPLACED: now Ollama-driven
│   │   │   ├── recon.py                 # UNCHANGED
│   │   │   ├── bruteforce.py            # 🔄 CHANGED: accepts LLMDecision param
│   │   │   ├── exploit.py               # 🔄 CHANGED: accepts LLMDecision param
│   │   │   ├── business_logic.py        # 🔄 NEW: negative amounts, overflow, replay
│   │   │   └── evasion.py               # 🔄 NEW: encoding variants, timing mimicry
│   │   │
│   │   ├── blue/
│   │   │   ├── __init__.py
│   │   │   ├── log_monitor.py           # UNCHANGED
│   │   │   ├── anomaly_detector.py      # 🔄 CHANGED: new rules
│   │   │   └── responder.py             # 🔄 CHANGED: new actions
│   │   │
│   │   └── supervisor/
│   │       ├── __init__.py
│   │       ├── pruner.py                # UNCHANGED — SEMA Algorithm 1
│   │       ├── evaluation_agent.py      # UNCHANGED
│   │       ├── policy_agent.py          # 🔄 CHANGED: updated schema + IOC ingestion
│   │       ├── patch_agent.py           # 🔄 NEW: patch generation + verification
│   │       └── gemini_client.py         # UNCHANGED
│   │
│   ├── graph/
│   │   ├── __init__.py
│   │   ├── langgraph_flow.py            # 🔄 CHANGED: patch_node added
│   │   └── reset.py                     # 🔄 CHANGED: preserves behavioral_fingerprints
│   │
│   ├── memory/                          # UNCHANGED
│   │   ├── __init__.py
│   │   ├── short_term.py
│   │   └── episode_pool.py
│   │
│   ├── scoring/                         # UNCHANGED
│   │   ├── __init__.py
│   │   └── risk_engine.py
│   │
│   └── ws/                              # UNCHANGED
│       ├── __init__.py
│       └── broadcaster.py
│
├── frontend/                            # UNCHANGED
│   └── ...
│
├── data/
│   ├── logs.jsonl
│   ├── episode_pool.json
│   ├── patch_records.json               # 🔄 NEW: persisted patch history across runs
│   └── knowledge_base.json              # 🔄 CHANGED: KB009 added
│
├── requirements.txt                     # 🔄 CHANGED: ollama added
├── .env
├── .env.example                         # 🔄 CHANGED: OLLAMA_MODEL added
└── README.md
```

---

## 8. Backend — File-by-File Specification

### 8.1 FastAPI Target App (UNCHANGED)

`backend/target/router.py`, `backend/target/vuln_store.py`, `backend/target/middleware.py` — **implement exactly as specified in V1**. No changes required.

---

### 8.2 Red Team Agents (SIGNIFICANTLY CHANGED)

#### 🔄 NEW: `backend/llm/ollama_client.py`

```python
"""
ollama_client.py — Local Ollama inference wrapper for red team strategy.

Called every step from strategy.py.
Zero API cost — runs on local hardware.
Model: llama3 (default) or mistral (fallback if llama3 not available).

IMPORTANT: Ollama must be running before starting the arena.
Start with: `ollama serve` (usually auto-starts on install).
Pull model:  `ollama pull llama3`
"""

import json
import ollama
from backend.config import OLLAMA_MODEL, OLLAMA_TIMEOUT_S


def call_ollama(prompt: str) -> str:
    """
    Calls Ollama with the given prompt.
    Returns raw response string.
    Raises RuntimeError if Ollama is not running or model is not available.

    Implementation:
    - Use ollama.chat(model=OLLAMA_MODEL, messages=[{"role":"user","content":prompt}])
    - Set timeout to OLLAMA_TIMEOUT_S (default: 10s — if Ollama takes longer, skip this step)
    - If connection refused: raise RuntimeError with clear message about starting Ollama
    - If model not found: raise RuntimeError with pull command
    - Returns response["message"]["content"]
    """

def call_ollama_json(prompt: str, schema_hint: str) -> dict:
    """
    Calls Ollama and parses the response as JSON.
    schema_hint is appended to the prompt to help the model format output.
    
    Implementation:
    - Append to prompt: f"\\n\\nRespond ONLY with valid JSON matching this schema:\\n{schema_hint}\\nNo explanation, no markdown, just JSON."
    - Call call_ollama(full_prompt)
    - Strip any markdown fences (```json ... ```) from response
    - json.loads() the result
    - If JSON parsing fails: retry once with more explicit JSON instruction
    - If second attempt fails: return a safe default dict with empty/null values
    - Log parse failures with the raw response for debugging
    """

def check_ollama_available() -> bool:
    """
    Returns True if Ollama is running and OLLAMA_MODEL is available.
    Called at startup in main.py lifespan.
    Does not raise — returns bool.
    """
```

#### 🔄 COMPLETELY REPLACED: `backend/agents/red/strategy.py` — `red_node`

> **This file is completely different from V1.** Do not reuse any V1 code. The weight-table dispatcher is gone. Replace it entirely with the following.

```python
"""
strategy.py — red_node: Ollama LLM-driven attack strategy.

WHAT CHANGED FROM V1:
  V1: Computed weights based on recent usage frequency, randomly sampled an agent.
      The "strategy" was mechanical rotation — no reasoning about what to try or why.
  
  V2: Ollama LLM reads the pruned observation and recent history, reasons about
      what attack to attempt next, and produces a structured LLMDecision object.
      Agent executors receive this decision and execute the specified HTTP request.
      The LLM can discover attack surfaces not in any hardcoded script.

TWO-LAYER ARCHITECTURE:
  Layer 1 (this file): LLM reasoning → LLMDecision
  Layer 2 (executor files): LLMDecision → real HTTP request → AttackEvent

IMPORTANT: Ollama is called synchronously. LangGraph nodes are sync.
           Expected latency: 0.5-2s per call on modern hardware.
           If Ollama times out: fall back to rule-based weight selection (see FALLBACK).
"""

import json
import random
from backend.state import SystemState, LLMDecision, AttackEvent
from backend.llm.ollama_client import call_ollama_json, check_ollama_available
from backend.config import OLLAMA_MODEL

# ── Attack layer definitions ───────────────────────────────────────────────────

ATTACK_LAYERS = {
    1: "network_transport",    # IP spoofing, header injection, user-agent mimicry
    2: "authentication",       # credential attacks, session attacks, token attacks
    3: "authorization",        # IDOR, privilege escalation, access control bypass
    4: "input_validation",     # SQLi, path traversal, injection variants
    5: "business_logic",       # negative amounts, race conditions, replay attacks
    6: "evasion",              # encoding variants, timing manipulation, pattern mimicry
}

# ── Executor routing ───────────────────────────────────────────────────────────
# Maps technique strings (produced by LLM) → executor module
# The LLM does not need to know these mappings — it produces technique strings
# naturally and we route them here.

TECHNIQUE_TO_EXECUTOR = {
    # Layer 2 — authentication
    "bruteforce":          "bruteforce",
    "credential_stuffing": "bruteforce",
    "timing_enumeration":  "bruteforce",
    # Layer 3 — authorization
    "idor":                "exploit",
    "auth_bypass":         "exploit",
    "privilege_escalation":"exploit",
    # Layer 4 — input validation
    "sqli_auth_bypass":    "exploit",
    "sqli_filter_param":   "exploit",
    "sqli_union":          "exploit",
    "sqli_blind":          "exploit",
    "path_traversal":      "exploit",
    "path_traversal_encoded": "exploit",
    # Layer 5 — business logic
    "negative_transfer":   "business_logic",
    "race_condition":      "business_logic",
    "replay_attack":       "business_logic",
    "integer_overflow":    "business_logic",
    # Layer 6 — evasion
    "sqli_double_encoded": "evasion",
    "timing_mimic":        "evasion",
    "header_injection":    "evasion",
    "ua_spoofing":         "evasion",
    # Layer 1 — recon (always routes to recon.py regardless of LLM)
    "recon":               "recon",
    "surface_mapping":     "recon",
}


# ── Prompt construction ────────────────────────────────────────────────────────

STRATEGY_SYSTEM_CONTEXT = """You are an autonomous penetration tester targeting a web application.
Your goal is to find and exploit security vulnerabilities.

You have access to these attack capabilities:
- Authentication attacks: bruteforce, credential_stuffing, timing_enumeration
- Authorization attacks: idor, auth_bypass, privilege_escalation
- Injection attacks: sqli_auth_bypass, sqli_filter_param, sqli_union, sqli_blind, path_traversal, path_traversal_encoded
- Business logic attacks: negative_transfer, race_condition, replay_attack
- Evasion techniques: sqli_double_encoded, timing_mimic, header_injection, ua_spoofing
- Reconnaissance: recon, surface_mapping

Be creative. Look for attack surfaces not in obvious places.
Consider: query parameters, request headers, HTTP methods, body fields the schema exposes.
If an endpoint has been patched, do not waste steps retrying the same technique there."""


def build_strategy_prompt(state: SystemState) -> str:
    """
    Builds the Ollama prompt from pruned_observation + recent history.
    
    Constructs a prompt with:
    1. Current pruned observation (the high-entropy attributes only)
    2. Last 5 memory entries (what was tried, what happened)
    3. Active mitigations (what has been patched)
    4. Episode pool hint (supervisor's last strategy recommendation)
    5. Attack layer context (where we are in the escalation ladder)
    
    Keep total prompt under ~800 tokens for fast local inference.
    """
    obs = state.get("pruned_observation", {})
    memory = state.get("short_term_memory", [])[-5:]
    mitigations = state.get("active_mitigations", {})
    episode_pool = state.get("episode_pool", [])
    layer = state.get("current_attack_layer", 1)

    active_m = [k for k, v in mitigations.items() if v]
    
    # Build concise memory summary
    memory_lines = []
    for m in memory:
        a = m.get("attack", {})
        d = m.get("llm_decision", {})
        memory_lines.append(
            f"  - {a.get('type','?')} on {a.get('target','?')} → {a.get('result','?')}"
            + (f" (rationale: {d.get('rationale','')})" if d.get("rationale") else "")
        )

    supervisor_hint = ""
    if episode_pool:
        # Extract next_episode_strategy from last pool entry if it exists
        supervisor_hint = f"\nSupervisor recommendation: {episode_pool[-1][:200]}"

    prompt = f"""{STRATEGY_SYSTEM_CONTEXT}

CURRENT SECURITY TELEMETRY (high-signal attributes only, pre-filtered by structural entropy):
{json.dumps(obs, indent=2)}

RECENT HISTORY (last 5 steps):
{chr(10).join(memory_lines) if memory_lines else "  No history yet — first steps of episode."}

ACTIVE MITIGATIONS (patched — do not retry these):
{', '.join(active_m) if active_m else 'None yet'}

CURRENT ATTACK LAYER: {layer} — {ATTACK_LAYERS.get(layer, 'unknown')}
{supervisor_hint}

Decide your next attack. Choose a technique that is:
1. Not already blocked by active mitigations
2. Contextually appropriate given the telemetry above
3. Ideally from a surface or endpoint not yet fully explored"""

    return prompt


DECISION_SCHEMA = """{
  "technique": "<technique_name from the list above>",
  "target_endpoint": "<endpoint path, e.g. /login or /data>",
  "method": "<GET|POST|PUT|DELETE>",
  "params": {"<key>": "<value>"},
  "headers": {"<key>": "<value>"},
  "payload": {"<key>": "<value>"},
  "rationale": "<one sentence: why this technique on this endpoint now>",
  "attack_layer": <integer 1-6>
}"""


# ── Fallback: rule-based selection when Ollama unavailable ────────────────────

FALLBACK_AGENT_ROSTER = ["recon", "bruteforce", "sqli_auth_bypass", "idor",
                          "path_traversal", "auth_bypass", "csrf",
                          "business_logic", "evasion"]

def _fallback_decision(state: SystemState) -> LLMDecision:
    """
    Rule-based fallback if Ollama is not available.
    Uses simple inverse-frequency weighting (V1 behavior).
    This is NOT the main path — Ollama should always be running.
    """
    memory = state.get("short_term_memory", [])[-10:]
    weights = {}
    for technique in FALLBACK_AGENT_ROSTER:
        recent = sum(1 for m in memory if m.get("attack", {}).get("type") == technique)
        weights[technique] = 1.0 / (1.0 + recent)

    techniques = list(weights.keys())
    w_values = list(weights.values())
    selected = random.choices(techniques, weights=w_values)[0]

    return LLMDecision(
        technique=selected,
        target_endpoint="/login",
        method="POST",
        params={},
        headers={},
        payload={},
        rationale="[FALLBACK — Ollama unavailable, using rule-based selection]",
        attack_layer=2,
    )


# ── Main node function ─────────────────────────────────────────────────────────

def red_node(state: SystemState) -> dict:
    """
    LangGraph node. Called every step.
    
    1. Build prompt from pruned_observation + memory + mitigations
    2. Call Ollama → get LLMDecision
    3. Route to appropriate executor based on technique
    4. Executor fires real HTTP request → returns AttackEvent
    5. Return updated state fields
    """
    # Get LLM decision
    try:
        prompt = build_strategy_prompt(state)
        decision_dict = call_ollama_json(prompt, DECISION_SCHEMA)
        llm_decision = LLMDecision(**decision_dict)
    except Exception as e:
        print(f"[RED] Ollama failed: {e}. Using fallback.")
        llm_decision = _fallback_decision(state)

    # Route to executor
    executor_name = TECHNIQUE_TO_EXECUTOR.get(llm_decision["technique"], "exploit")
    attack_event = _route_to_executor(executor_name, llm_decision, state)

    # Update attack layer based on LLM's self-reported layer
    new_layer = llm_decision.get("attack_layer", state.get("current_attack_layer", 1))

    print(f"  [RED] Ollama→{llm_decision['technique']} on {llm_decision['target_endpoint']} "
          f"| rationale: {llm_decision['rationale'][:80]}")

    return {
        "last_attack":          attack_event,
        "llm_decision":         llm_decision,
        "current_attack_layer": new_layer,
    }


def _route_to_executor(
    executor_name: str,
    decision: LLMDecision,
    state: SystemState
) -> AttackEvent:
    """
    Routes LLMDecision to the correct agent executor module.
    Each executor receives the full LLMDecision so it can use
    the LLM-specified payload, endpoint, and params rather than hardcoded values.
    """
    if executor_name == "recon":
        from backend.agents.red.recon import run
        return run(state)  # recon ignores LLMDecision, does its own logic
    elif executor_name == "bruteforce":
        from backend.agents.red.bruteforce import run
        return run(state, llm_decision=decision)
    elif executor_name == "exploit":
        from backend.agents.red.exploit import run
        return run(state, llm_decision=decision)
    elif executor_name == "business_logic":
        from backend.agents.red.business_logic import run
        return run(state, llm_decision=decision)
    elif executor_name == "evasion":
        from backend.agents.red.evasion import run
        return run(state, llm_decision=decision)
    else:
        # Unknown technique — attempt as generic HTTP request
        from backend.agents.red.exploit import run_generic
        return run_generic(state, decision)
```

#### 🔄 CHANGED: `backend/agents/red/exploit.py`

> **The file is not rewritten from scratch.** All V1 hardcoded payload lists remain as fallback defaults. The key change is that `run()` now accepts an optional `llm_decision` parameter and uses the LLM-specified payload when provided.

```python
# CHANGES FROM V1:
# - run() signature changes: def run(state, llm_decision=None) -> AttackEvent
# - When llm_decision is provided, use its endpoint/method/payload FIRST
# - Hardcoded payload lists become fallbacks only (used when llm_decision is None
#   or when the LLM-specified payload fails and we want to try known variants)
# - run_generic() is new: executes arbitrary LLMDecision as a raw HTTP request

def run(state: SystemState, llm_decision: Optional[LLMDecision] = None) -> AttackEvent:
    """
    CHANGED: Now accepts llm_decision parameter.
    
    If llm_decision is provided:
      - Use llm_decision["technique"] to select the sub-function
      - Use llm_decision["target_endpoint"] as the target
      - Use llm_decision["payload"] as the primary payload
      - Fall back to hardcoded payloads only if LLM payload fails
    
    If llm_decision is None (legacy/fallback path):
      - Use V1 logic: select technique based on what recon found
      - Try hardcoded payloads in priority order
    
    All technique sub-functions (run_sqli_auth_bypass, run_idor, etc.)
    remain unchanged from V1 — they just receive the LLM-specified
    payload as an argument now.
    """

def run_generic(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    NEW in V2. Executes an arbitrary LLMDecision as a raw HTTP request.
    Used when the LLM specifies a technique not in TECHNIQUE_TO_EXECUTOR
    or when it discovers a completely novel attack surface.
    
    Implementation:
    - Build request from decision["method"], decision["target_endpoint"],
      decision["params"], decision["headers"], decision["payload"]
    - Send via httpx.Client
    - Classify result (success/failed/blocked/rate_limited) from status code
    - Return AttackEvent with type=decision["technique"], severity="medium"
    - If status 200: success; 401/403: failed; 429: rate_limited; 403+blocked: blocked
    """
```

#### 🔄 CHANGED: `backend/agents/red/bruteforce.py`

```python
# CHANGE FROM V1:
# - run() signature: def run(state, llm_decision=None, slow_mode=False)
# - When llm_decision is provided and specifies a target endpoint or
#   specific username/password hint, use it
# - Otherwise fall back to V1 LEAKED_CREDENTIALS + COMMON_PASSWORDS logic
# - All V1 slow_mode, response discrimination, and stuffing logic UNCHANGED
```

#### 🔄 NEW: `backend/agents/red/business_logic.py`

```python
"""
business_logic.py — Business logic attack executor.

NEW in V2. Handles LLM-discovered business logic vulnerabilities.
These attacks are not in typical security scanners because they require
understanding application semantics, not just injection patterns.

Activated when Ollama specifies technique in:
  ["negative_transfer", "race_condition", "replay_attack", "integer_overflow",
   "boundary_value", "workflow_bypass"]
"""

import httpx
import threading
import time
from backend.state import SystemState, LLMDecision, AttackEvent
from backend.config import TARGET_BASE_URL


def run(state: SystemState, llm_decision: LLMDecision) -> AttackEvent:
    """
    Routes to sub-technique based on llm_decision["technique"].
    """
    technique = llm_decision.get("technique", "")
    
    if technique == "negative_transfer":
        return _run_negative_transfer(state, llm_decision)
    elif technique == "race_condition":
        return _run_race_condition(state, llm_decision)
    elif technique == "replay_attack":
        return _run_replay(state, llm_decision)
    else:
        # Unknown business logic technique — attempt as generic request
        from backend.agents.red.exploit import run_generic
        return run_generic(state, llm_decision)


def _run_negative_transfer(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Sends a transfer with a negative amount value.
    Tests whether the application validates amount > 0.
    
    Uses harvested session token from short_term_memory if available.
    
    Success condition: HTTP 200 with transfer amount = negative value
    Evidence: response body contains {"amount": <negative>}
    CWE: CWE-20 (Improper Input Validation), severity: medium
    """


def _run_race_condition(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Sends two identical POST /transfer requests concurrently using threading.
    Tests whether the application handles concurrent state-modifying requests.
    
    Implementation:
    - Get session token from memory
    - Create two threads, each sending the same transfer request
    - Start both threads within 5ms of each other
    - Check if both received HTTP 200 (double-execution = race condition exploited)
    
    Success condition: both requests return 200
    CWE: CWE-362 (Race Condition), severity: medium
    """


def _run_replay(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Replays a previously successful authenticated request.
    Tests whether session tokens expire or whether request replay is possible.
    
    Implementation:
    - Find the most recent successful attack in short_term_memory that has a token
    - Re-send that exact request with the same token
    - If still 200: session tokens do not expire (finding)
    
    CWE: CWE-294 (Authentication Bypass by Capture-replay), severity: low
    """
```

#### 🔄 NEW: `backend/agents/red/evasion.py`

```python
"""
evasion.py — Evasion technique executor.

NEW in V2. Handles attacks that try to bypass detection mechanisms
rather than directly exploiting vulnerabilities.

The key insight: once blue team deploys behavioral fingerprinting and
pattern-based detection, naive attacks get blocked regardless of IP.
Evasion techniques make attack traffic look like legitimate traffic.

Activated when Ollama specifies technique in:
  ["sqli_double_encoded", "timing_mimic", "header_injection", "ua_spoofing",
   "sqli_unicode_normalized", "fragmented_payload"]
"""

import httpx
import time
import random
from urllib.parse import quote
from backend.state import SystemState, LLMDecision, AttackEvent
from backend.config import TARGET_BASE_URL


def run(state: SystemState, llm_decision: LLMDecision) -> AttackEvent:
    """Routes to sub-technique based on llm_decision["technique"]."""
    technique = llm_decision.get("technique", "")
    
    if technique == "sqli_double_encoded":
        return _run_double_encoded_sqli(state, llm_decision)
    elif technique == "timing_mimic":
        return _run_timing_mimic(state, llm_decision)
    elif technique == "ua_spoofing":
        return _run_ua_spoof(state, llm_decision)
    elif technique == "header_injection":
        return _run_header_inject(state, llm_decision)
    else:
        from backend.agents.red.exploit import run_generic
        return run_generic(state, llm_decision)


def _run_double_encoded_sqli(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Sends SQLi payload with double URL-encoding to bypass regex detection.
    
    Encoding: ' → %27 → %2527 (percent-encodes the percent sign itself)
    Detection rule RULE_SQLI_SIGNATURE looks for raw ' character.
    After URL decode by the server, %2527 → %27 → ' (the original payload).
    
    The blue team's standard regex will miss this until RULE_SQLI_ENCODED is deployed.
    
    Payloads to try:
    - %2527%20OR%20%25271%2527%3D%25271  (→ ' OR '1'='1)
    - admin%2527%20--                     (→ admin' --)
    
    CWE: CWE-89, severity: critical (bypasses detection)
    """


def _run_timing_mimic(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Sends requests with inter-arrival times that mimic human browsing patterns.
    Goal: evade RULE_SLOW_SCRIPTED_PROBE (which detects regular machine timing).
    
    Implementation:
    - Sample inter-arrival delays from a log-normal distribution
      (μ=0.8s, σ=0.6s — approximates human web browsing)
    - This produces irregular timing that coefficient-of-variation rule misses
    - Embed the actual attack payload within the "human-like" request
    
    This technique activates the existing attack payload wrapped in realistic timing.
    The attack_result comes from the embedded payload, not the timing itself.
    """


def _run_ua_spoof(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Sends requests with a legitimate browser User-Agent header.
    Goal: evade fingerprinting rules that check for python-httpx user-agent.
    
    Use: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
    
    Combine with the technique from llm_decision["payload"] as the actual attack.
    """


def _run_header_inject(state: SystemState, decision: LLMDecision) -> AttackEvent:
    """
    Injects X-Forwarded-For header to spoof source IP.
    Goal: bypass IP-based blocking.
    
    Try: X-Forwarded-For: 10.0.0.100 (a non-blocked IP)
    If middleware checks this header: blocks are bypassed.
    If middleware ignores this header: no effect (still informative).
    """
```

#### `backend/agents/red/recon.py` — UNCHANGED

Implement exactly as specified in V1. No changes.

---

### 8.3 Blue Team Agents (CHANGED)

#### `backend/agents/blue/log_monitor.py` — UNCHANGED

Implement exactly as specified in V1. No changes.

#### 🔄 CHANGED: `backend/agents/blue/anomaly_detector.py`

> All V1 rules are **preserved unchanged**. Three new rules are added. One rule regex is enhanced.

```python
# V1 RULES — ALL UNCHANGED:
# rule_sqli_signature, rule_path_traversal, rule_time_based_sqli,
# rule_sequential_idor, rule_admin_probing, rule_credential_stuffing,
# rule_slow_scripted_probe, rule_high_login_rate, rule_endpoint_flood,
# rule_ip_recon_sweep, rule_large_get_payload

# 🔄 ENHANCED: SQLI_REGEX — normalize encoding before matching
# The V1 regex only checked raw characters. V2 normalizes URL encoding first.
# This catches double-encoded payloads (%2527) that V1 missed.

def _normalize_for_detection(value: str) -> str:
    """
    NEW helper. Normalize URL encoding up to 3 levels deep before applying regexes.
    %2527 → %27 → '  (double-encoded apostrophe)
    %252e%252e → %2e%2e → ..  (double-encoded path traversal)
    """
    from urllib.parse import unquote
    normalized = value
    for _ in range(3):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return normalized

# Apply _normalize_for_detection to all query_param values before regex matching
# in rule_sqli_signature and rule_path_traversal.


# 🔄 NEW RULE: RULE_BEHAVIORAL_FINGERPRINT
def rule_behavioral_fingerprint(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """
    RULE_BEHAVIORAL_FINGERPRINT
    
    When a new IP appears that has not been seen before, compare its behavioral
    signature to the signatures of previously blocked IPs.
    
    Behavioral signature = {
        inter_arrival_mean:  float  (average time between requests)
        inter_arrival_cv:    float  (coefficient of variation — regularity)
        endpoint_sequence:   list   (last 5 endpoint paths in order)
        error_rate:          float  (fraction of non-200 responses)
        user_agent:          str    (most common UA string)
    }
    
    Similarity metric: cosine similarity between signature vectors
    (flatten to numeric vector: [mean, cv, error_rate, ua_hash])
    
    Trigger: new IP's signature cosine similarity > 0.80 with any blocked IP's signature
    Severity: high
    Action: block_ip immediately (before it completes an attack)
    
    Implementation:
    - Group recent logs by IP
    - For each IP not in state["blocked_ips"]:
        - Build its behavioral signature from its log entries
        - Compare against state["behavioral_fingerprints"]
        - If similarity > 0.80: return Finding with recommended_action="block_ip"
    - Log fingerprint comparison scores for debugging
    """


# 🔄 NEW RULE: RULE_SQLI_ENCODED
def rule_sqli_encoded(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """
    RULE_SQLI_ENCODED
    
    Detects SQLi payloads that bypass standard regex via URL encoding.
    Applies _normalize_for_detection to each query param value before
    running SQLI_REGEX against the normalized value.
    
    This rule ONLY fires if rule_sqli_signature did NOT fire — meaning
    the raw regex check missed it but normalization reveals it.
    
    Trigger: normalized query param value matches SQLI_REGEX AND raw value did not
    Severity: critical
    Action: block_ip + export_ioc (add encoding pattern to knowledge base)
    """


# 🔄 NEW RULE: RULE_ANOMALOUS_SUCCESS_RATE
def rule_anomalous_success_rate(obs: dict, logs: list, state: SystemState) -> Optional[Finding]:
    """
    RULE_ANOMALOUS_SUCCESS_RATE
    
    Detects when an IP has a suspiciously high success rate
    despite no individual rule triggering (possible evasion of all other rules).
    
    This is the "catch-all" for sophisticated evasion that routes around
    every specific rule — if you are succeeding at an unusual rate from
    one IP without triggering any signature or rate rules, that is suspicious.
    
    Trigger: single IP has > 3 HTTP 200 responses in window
             AND no other rule has triggered for this IP
             AND obs["rate_401"] < 0.1 (not a brute force pattern)
    Severity: medium
    Action: deep_log_attacker (escalate logging for this IP — see responder.py)
    """


# 🔄 CHANGED: RULE_PIPELINE — new rules added in correct priority order
RULE_PIPELINE = [
    rule_sqli_signature,           # critical — always first (checks raw values)
    rule_sqli_encoded,             # critical — checks normalized values (🔄 NEW)
    rule_path_traversal,           # high
    rule_time_based_sqli,          # high
    rule_behavioral_fingerprint,   # high (🔄 NEW — before specific behavioral rules)
    rule_sequential_idor,          # high
    rule_admin_probing,            # high
    rule_credential_stuffing,      # high
    rule_slow_scripted_probe,      # medium
    rule_high_login_rate,          # medium
    rule_endpoint_flood,           # medium
    rule_anomalous_success_rate,   # medium (🔄 NEW — catch-all evasion detector)
    rule_ip_recon_sweep,           # low
    rule_large_get_payload,        # low
]
```

#### 🔄 CHANGED: `backend/agents/blue/responder.py`

> V1 actions (`block_ip`, `rate_limit`, `patch_endpoint`, `alert_only`) are **preserved unchanged**. Three new actions added.

```python
# V1 PATCH_MAP — UNCHANGED:
PATCH_MAP = {
    "RULE_SEQUENTIAL_IDOR":   "idor_check_enabled",
    "RULE_ADMIN_PROBING":     "proper_admin_auth",
    "RULE_TIME_BASED_SQLI":   "proper_auth",
    "RULE_SQLI_SIGNATURE":    "proper_auth",
    "RULE_SQLI_ENCODED":      "proper_auth",    # 🔄 NEW: encoded SQLi also patches auth
}

# 🔄 NEW ACTION: "deep_log_attacker"
# Triggered by: RULE_ANOMALOUS_SUCCESS_RATE
# Implementation:
#   - Add source_ip to a "deep_logging_ips" set (not in V1 SystemState — add it)
#   - Middleware checks this set and logs full query params (not just hash)
#     for requests from these IPs
#   - This is how the blue team discovers double-encoding in episode 3 of the demo

# 🔄 NEW ACTION: "export_ioc"
# Triggered by: RULE_SQLI_ENCODED, RULE_BEHAVIORAL_FINGERPRINT
# Implementation:
#   - Append to state["ioc_exports"]:
#     {
#       "pattern": <the specific value that triggered detection>,
#       "type": "sqli_encoded" | "behavioral",
#       "description": <human-readable>,
#       "kb_entry": <dict matching knowledge_base.json format>
#     }
#   - policy_agent reads ioc_exports and adds them to state["knowledge_base"]
#     at the end of the episode, so future episodes start with this knowledge

# 🔄 NEW ACTION: "fingerprint_and_block"
# Triggered by: RULE_BEHAVIORAL_FINGERPRINT
# Implementation:
#   - block_ip as normal
#   - ALSO: build behavioral fingerprint of the blocked IP
#   - Append fingerprint to state["behavioral_fingerprints"]
#   - These fingerprints persist across episodes (reset_node preserves them)


def apply_mitigations(findings: List[Finding], state: SystemState) -> dict:
    """
    CHANGED from V1: processes findings in order, applies all non-redundant mitigations.
    V1 only processed the first finding. V2 processes all findings but de-duplicates.
    
    Returns DefenseEvent representing the highest-severity action taken.
    Updates state directly for all mitigations (block_ip, rate_limit, etc.).
    
    New action routing:
    "deep_log_attacker" → add IP to deep_logging_ips set
    "export_ioc"        → append to state["ioc_exports"]
    "fingerprint_and_block" → block_ip + build + store fingerprint
    """
```

---

### 8.4 Supervisor Agents (CHANGED)

#### `backend/agents/supervisor/pruner.py` — UNCHANGED

Implement exactly as specified in V1 (SEMA Algorithm 1). No changes. This file is the core academic contribution and is correct as-is.

#### `backend/agents/supervisor/evaluation_agent.py` — UNCHANGED

Implement exactly as specified in V1. No changes.

#### `backend/agents/supervisor/gemini_client.py` — UNCHANGED

Implement exactly as specified in V1. No changes.

#### 🔄 CHANGED: `backend/agents/supervisor/policy_agent.py`

```python
# CHANGES FROM V1:
# 1. SupervisorReport JSON schema adds "episode_summary" field (was missing in V1)
# 2. policy_node now also reads state["ioc_exports"] and adds them to knowledge_base
# 3. policy_node passes context to patch_agent (returns patch-ready vuln list)
#    — actually patch_agent reads supervisor_report directly, so policy_node is unchanged
#    except for the ioc ingestion

# 🔄 UPDATED JSON SCHEMA (add episode_summary field):
SUPERVISOR_REPORT_SCHEMA = """
{
  "risk_score": <float 0.0-1.0>,
  "vulnerabilities": [
    {
      "name": "<vulnerability name>",
      "severity": "<low|medium|high|critical>",
      "endpoint": "<affected endpoint path>",
      "cwe": "<CWE-XXX>",
      "evidence": "<one sentence of evidence from the data>",
      "first_exploited_step": <int>,
      "exploit_payload": "<the specific payload that confirmed this vulnerability>"
    }
  ],
  "mitigations": ["<concrete mitigation step>"],
  "next_episode_strategy": "<one sentence strategy recommendation for the red team>",
  "episode_summary": "<two sentence summary for the memory pool>"
}"""
# The exploit_payload field is new — patch_agent uses it for verification

# 🔄 NEW: IOC ingestion at end of policy_node
def policy_node(state: SystemState) -> dict:
    """
    CHANGED: After Gemini call, ingest IOC exports into knowledge base.
    
    Additional step after parsing Gemini response:
    
    for ioc in state.get("ioc_exports", []):
        kb_entry = ioc.get("kb_entry")
        if kb_entry and kb_entry not in state["knowledge_base"]:
            state["knowledge_base"].append(kb_entry)
    
    This means the next episode's Gemini prompt will include the new
    attack pattern in its knowledge base context.
    Also persist updated knowledge_base to knowledge_base.json.
    """
```

#### 🔄 NEW: `backend/agents/supervisor/patch_agent.py` — `patch_node`

```python
"""
patch_agent.py — patch_node: Gemini-powered patch generation and verification.

NEW in V2. Called once per episode, immediately after policy_node.
This is the second Gemini call per episode (policy_node is the first).

Three-phase process:
  Phase 1 — Generate: ask Gemini to write a minimal Python patch for each vulnerability
  Phase 2 — Apply:    apply the patch to the running application via exec()
  Phase 3 — Verify:   re-run the specific exploit that found the vulnerability,
                      confirm it now returns a blocked/forbidden response

This is the component that produces the "adversarially verified patch" claim.
No other tool does this — Snyk, CodeQL, and GitHub Copilot Autofix suggest patches
but do not confirm effectiveness against real attacks.
"""

import json
import time
import httpx
from backend.state import SystemState, PatchRecord
from backend.agents.supervisor.gemini_client import call_gemini
from backend.config import TARGET_BASE_URL
from backend.ws.broadcaster import broadcast_episode_report


PATCH_SYSTEM_PROMPT = """You are a security engineer generating minimal, targeted Python patches.
You will receive a vulnerable function and evidence of how it was exploited.
Generate ONLY the patched version of that function — no explanations, no markdown, just Python code.
The patch must be minimal: fix only the specific vulnerability. Do not refactor or rename anything."""

PATCH_USER_PROMPT = """VULNERABILITY: {vuln_name}
CWE: {cwe}
ENDPOINT: {endpoint}
EXPLOIT PAYLOAD THAT WORKED: {exploit_payload}
EVIDENCE: {evidence}

CURRENT VULNERABLE FUNCTION CODE:
{function_source}

Write the patched version of this function that prevents this specific exploit.
Output only the function code, starting with 'async def' or 'def'."""


def patch_node(state: SystemState) -> dict:
    """
    LangGraph node. Called once per episode after policy_node.
    
    For each vulnerability in supervisor_report["vulnerabilities"]:
      1. Get the source code of the affected endpoint function
      2. Call Gemini to generate a patch
      3. Apply patch via exec() + FastAPI route replacement
      4. Re-run the exploit payload that originally found the vulnerability
      5. Record whether the patch successfully blocked the exploit
    
    Returns:
      {"patch_records": updated_list, "active_mitigations": updated_flags}
    """
    report = state.get("supervisor_report")
    if not report:
        return {"patch_records": state.get("patch_records", [])}

    vulns = report.get("vulnerabilities", [])
    new_records = list(state.get("patch_records", []))
    updated_mitigations = dict(state.get("active_mitigations", {}))

    for vuln in vulns:
        record = _patch_one_vulnerability(vuln, state)
        new_records.append(record)
        
        # If patch was verified, also flip the feature flag for belt-and-suspenders
        if record["verified"]:
            flag = _vuln_to_mitigation_flag(vuln["endpoint"], vuln["cwe"])
            if flag:
                updated_mitigations[flag] = True
        
        print(f"  [PATCH] {vuln['name']}: {'✓ VERIFIED' if record['verified'] else '✗ FAILED/NEEDS REVIEW'}")

    # Persist patch records to disk
    _persist_patch_records(new_records)
    
    # Broadcast patch summary to dashboard
    _broadcast_patch_summary(new_records, state["episode"])

    return {
        "patch_records":      new_records,
        "active_mitigations": updated_mitigations,
    }


def _patch_one_vulnerability(vuln: dict, state: SystemState) -> PatchRecord:
    """
    Attempts to patch a single vulnerability.
    
    1. Get source code: inspect.getsource(endpoint_function)
       Use importlib to get the router module, then get the function by name.
    
    2. Call Gemini: generate patched function code
    
    3. Apply patch:
       a. exec() the patched code in a namespace with all required imports
       b. Extract the new function from namespace
       c. Find the route in target_router.routes where route.name matches endpoint
       d. Replace route.endpoint with new function
       If exec() fails: mark requires_human_review=True, skip verify
    
    4. Verify:
       a. Re-run the original exploit payload against the endpoint
       b. If response is now 403/401/400: patch verified
       c. If response is still 200: patch failed
    
    Returns PatchRecord.
    """
    endpoint = vuln.get("endpoint", "")
    exploit_payload = vuln.get("exploit_payload", "")
    
    # Get current source code
    function_source = _get_endpoint_source(endpoint)
    if not function_source:
        return PatchRecord(
            vulnerability_name=vuln["name"],
            cwe=vuln.get("cwe", ""),
            endpoint=endpoint,
            patch_code="",
            patch_applied=False,
            verification_payload=exploit_payload,
            verified=False,
            verification_evidence="Could not retrieve endpoint source code",
            requires_human_review=True,
        )
    
    # Generate patch
    patch_code = call_gemini(
        system_prompt=PATCH_SYSTEM_PROMPT,
        user_prompt=PATCH_USER_PROMPT.format(
            vuln_name=vuln["name"],
            cwe=vuln.get("cwe", ""),
            endpoint=endpoint,
            exploit_payload=exploit_payload,
            evidence=vuln.get("evidence", ""),
            function_source=function_source,
        )
    )
    
    # Apply patch
    applied = _apply_patch(endpoint, patch_code)
    if not applied:
        return PatchRecord(
            vulnerability_name=vuln["name"],
            cwe=vuln.get("cwe", ""),
            endpoint=endpoint,
            patch_code=patch_code,
            patch_applied=False,
            verification_payload=exploit_payload,
            verified=False,
            verification_evidence="exec() failed — patch requires human review",
            requires_human_review=True,
        )
    
    # Verify patch
    verified, evidence = _verify_patch(endpoint, exploit_payload, vuln)
    
    return PatchRecord(
        vulnerability_name=vuln["name"],
        cwe=vuln.get("cwe", ""),
        endpoint=endpoint,
        patch_code=patch_code,
        patch_applied=True,
        verification_payload=exploit_payload,
        verified=verified,
        verification_evidence=evidence,
        requires_human_review=not verified,
    )


def _get_endpoint_source(endpoint: str) -> Optional[str]:
    """
    Returns the Python source code of the FastAPI route handler for endpoint.
    
    Implementation:
    - Import backend.target.router
    - Iterate router.routes to find route where route.path == endpoint
    - Use inspect.getsource(route.endpoint) to get source
    - Return as string, or None if not found
    """


def _apply_patch(endpoint: str, patch_code: str) -> bool:
    """
    Applies a patched function to the running FastAPI router.
    
    Implementation:
    - Build namespace dict with all imports the function needs:
      {"JSONResponse": JSONResponse, "USERS": USERS, "DATA_RECORDS": DATA_RECORDS,
       "get_session_user": get_session_user, "create_session": create_session,
       "Request": Request, "Header": Header, "Optional": Optional, ...}
    - exec(patch_code, namespace)
    - Extract the function from namespace by finding the callable matching endpoint name
    - Find the route in target_router.routes
    - Replace route.endpoint with the new function
    - Return True on success, False on any exception
    - Wrap entire operation in try/except — never crash the arena loop
    """


def _verify_patch(endpoint: str, exploit_payload: str, vuln: dict) -> tuple[bool, str]:
    """
    Re-runs the exploit that originally found the vulnerability.
    Returns (verified: bool, evidence: str).
    
    Implementation:
    - Parse exploit_payload to reconstruct the original HTTP request
    - Send request using httpx.Client
    - verified = response.status_code in (400, 401, 403, 422)
    - evidence = f"HTTP {response.status_code} {response.text[:100]}"
    
    For complex payloads, use the vuln["cwe"] to determine verification approach:
    - CWE-89 (SQLi): send SQLi string in appropriate field, expect 401 not 200
    - CWE-639 (IDOR): send cross-user request, expect 403 not 200
    - CWE-22 (path traversal): send ../ payload, expect 403/400 not 200
    - CWE-284 (auth bypass): send bypass token, expect 403 not 200
    """


def _vuln_to_mitigation_flag(endpoint: str, cwe: str) -> Optional[str]:
    """
    Maps (endpoint, cwe) → active_mitigations flag name.
    Provides belt-and-suspenders: even if exec() patch is applied,
    also flip the feature flag as a safety net.
    """
    mapping = {
        ("/login",    "CWE-89"):  "proper_auth",
        ("/data",     "CWE-639"): "idor_check_enabled",
        ("/admin",    "CWE-284"): "proper_admin_auth",
        ("/files",    "CWE-22"):  "path_sanitization",
        ("/transfer", "CWE-352"): "csrf_protection",
    }
    return mapping.get((endpoint, cwe))
```

---

### 8.5 Memory System (UNCHANGED)

`backend/memory/short_term.py`, `backend/memory/episode_pool.py` — implement exactly as specified in V1.

**One addition to `short_term.append_step()`:**

```python
# 🔄 CHANGED SIGNATURE: add llm_decision parameter
def append_step(
    obs:          dict,
    attack:       dict,
    defense:      dict,
    result:       str,
    llm_decision: dict = None,   # 🔄 NEW parameter
    harvested_token: str = None,
) -> None:
    _memory.append({
        "obs":             obs,
        "attack":          attack,
        "defense":         defense,
        "result":          result,
        "llm_decision":    llm_decision,   # 🔄 NEW field stored
        "defense_action":  defense.get("action", "none") if defense else "none",
        "harvested_token": harvested_token,
    })
```

---

### 8.6 Scoring Engine (UNCHANGED)

`backend/scoring/risk_engine.py` — implement exactly as specified in V1. No changes.

---

### 8.7 WebSocket Broadcaster (UNCHANGED)

`backend/ws/broadcaster.py` — implement exactly as specified in V1.

**One addition:** `broadcast_patch_summary()` function for patch_node:

```python
def broadcast_patch_summary(patch_records: list, episode: int):
    """
    NEW in V2. Called from patch_node after patch generation + verification.
    Sends a PatchSummary message to all connected dashboard clients.
    """
    manager.broadcast_sync({
        "type":    "patch_summary",
        "episode": episode,
        "patches": [
            {
                "vulnerability": p["vulnerability_name"],
                "endpoint":      p["endpoint"],
                "cwe":           p["cwe"],
                "verified":      p["verified"],
                "requires_human_review": p["requires_human_review"],
                "evidence":      p["verification_evidence"],
            }
            for p in patch_records
            if p.get("patch_applied")   # only show patches that were attempted
        ],
    })
```

---

## 9. Frontend — Component Specification (UNCHANGED)

All frontend files are unchanged from V1 except one addition: the `ReportPanel.tsx` should also render patch records when a `patch_summary` WebSocket message arrives. Add a "Patches" tab to `ReportPanel` that shows:
- Patch name, CWE, endpoint
- Verified: ✓ green badge or ✗ red badge
- Verification evidence (the HTTP response)
- Code snippet (the generated patch, collapsed by default)
- "Requires human review" warning for architectural patches

Everything else in the frontend is identical to V1.

---

## 10. Data Contracts and Schemas

### WebSocket Message Types

**StepUpdate** — UNCHANGED from V1.

**EpisodeReport** — UNCHANGED from V1.

> 🔄 **NEW: PatchSummary** (broadcast once per episode from `patch_node`, after EpisodeReport):

```json
{
  "type": "patch_summary",
  "episode": 1,
  "patches": [
    {
      "vulnerability": "SQL Injection — Authentication Bypass",
      "endpoint": "/login",
      "cwe": "CWE-89",
      "verified": true,
      "requires_human_review": false,
      "evidence": "HTTP 401 Authentication failed (was HTTP 200 with admin token)"
    },
    {
      "vulnerability": "Race Condition — Concurrent Transfers",
      "endpoint": "/transfer",
      "cwe": "CWE-362",
      "verified": true,
      "requires_human_review": true,
      "evidence": "Requires async idempotency key — architectural change needed"
    }
  ]
}
```

### `data/knowledge_base.json`

> 🔄 **CHANGED:** KB009 added. KB001–KB008 are unchanged from V1.

```json
{
  "id": "KB009",
  "tags": ["sqli", "encoding_evasion", "detection_bypass", "CWE-89"],
  "content": "Double URL-encoding bypasses naive SQLi regex detection. The sequence ' → %27 → %2527 produces a payload that looks benign to string matching but decodes to a SQL injection character after server-side URL normalization. Always apply urllib.parse.unquote() iteratively (up to 3 times) before applying SQLi signature detection. This variant was discovered autonomously by the LLM red team in episode 3."
}
```

---

## 11. Configuration Reference

> 🔄 **CHANGED:** New constants added. All V1 constants are preserved unchanged.

```python
# backend/config.py

# ── All V1 constants unchanged ─────────────────────────────────────────────────
MAX_STEPS       = 50
STEP_DELAY_S    = 0.3     # slightly faster than V1's 0.5 for demo responsiveness
MAX_MEMORY_SIZE = 50
MAX_POOL_SIZE   = 20
PRUNE_ALPHA     = 0.95
PRUNE_BETA      = 0.05
PRUNE_MU        = 0.05
PRUNE_N         = 8
RISK_DECAY      = 0.95
RISK_SEVERITY_WEIGHTS = {"critical": 0.25, "high": 0.15, "medium": 0.08, "low": 0.02}
RISK_ATTACK_SUCCESS_BONUS  = 0.10
RISK_MITIGATION_DISCOUNT   = -0.05
ANOMALY_LOGIN_RATE_THRESHOLD     = 10
ANOMALY_FLOOD_THRESHOLD          = 50
ANOMALY_RECON_ENDPOINT_THRESHOLD = 7
ANOMALY_TIMING_CV_THRESHOLD      = 0.3
RATE_LIMIT_LOGIN_HIGH     = 10
RATE_LIMIT_LOGIN_STUFFING = 3
RATE_LIMIT_FLOOD          = 20
LOG_WINDOW_SECONDS = 60
MAX_LOG_LINES      = 500
GEMINI_MODEL         = "gemini-1.5-flash"
GEMINI_MAX_RETRIES   = 3
GEMINI_RETRY_DELAY_S = 5.0
LOG_FILE            = "data/logs.jsonl"
EPISODE_POOL_FILE   = "data/episode_pool.json"
KNOWLEDGE_BASE_FILE = "data/knowledge_base.json"

# ── 🔄 NEW CONSTANTS ───────────────────────────────────────────────────────────

# Ollama configuration
OLLAMA_MODEL     = "llama3"      # primary model; fallback: "mistral"
OLLAMA_TIMEOUT_S = 10.0          # per-step timeout; if exceeded, use fallback decision
OLLAMA_FALLBACK_MODEL = "mistral" # tried if llama3 is not available

# Attack layer configuration
ATTACK_LAYER_ESCALATION_THRESHOLD = 0.15  # if layer success rate drops below this,
                                            # LLM is hinted to escalate to next layer

# Behavioral fingerprinting
FINGERPRINT_SIMILARITY_THRESHOLD = 0.80   # cosine similarity above this = same attacker
FINGERPRINT_MIN_REQUESTS         = 5      # minimum requests to build a fingerprint

# Patch generation
PATCH_RECORDS_FILE = "data/patch_records.json"
PATCH_VERIFICATION_TIMEOUT_S = 5.0  # time allowed for verification HTTP request
MAX_PATCHES_PER_EPISODE = 5          # cap Gemini calls from patch_agent per episode

# Anomaly detection — new rules
ANOMALY_IDOR_SEQ_THRESHOLD    = 3     # consecutive sequential IDs → IDOR scan
ANOMALY_STUFFING_USERNAMES    = 5     # unique usernames → credential stuffing
ANOMALY_STUFFING_SUCCESS_RATE = 0.05  # max success rate → stuffing rule
ANOMALY_ADMIN_PROBE_THRESHOLD = 3     # failed /admin attempts → probing
ANOMALY_SUCCESS_RATE_THRESHOLD = 3    # successful 200s from one IP → anomalous
```

---

## 12. Startup and Execution Flow

> 🔄 **CHANGED:** Ollama check added to startup. patch_node added to episode end.

```
1. Start Ollama (separate process, must be running before uvicorn):
   $ ollama serve        ← usually auto-starts on install
   $ ollama pull llama3  ← one-time model download (~4GB)

2. uvicorn backend.main:app --reload --port 8000

3. FastAPI lifespan starts:
   a. load_dotenv() → reads GEMINI_API_KEY from .env
   b. configure_gemini(api_key) → initializes Gemini SDK
   c. 🔄 NEW: check_ollama_available() → confirms llama3 is running
      If Ollama not available: print warning, red team will use fallback mode
   d. get_initial_state() → builds clean SystemState with all new fields
   e. arena.invoke(initial_state) launched in background thread

4. LangGraph arena loop begins:
   Episode 1, Step 0:
   a. red_node: strategy.py calls Ollama
      - Ollama reads pruned_observation (empty at step 0 — returns recon suggestion)
      - LLMDecision: {"technique": "surface_mapping", "target_endpoint": "/"}
      - recon.py executes HTTP surface scan
      - Returns AttackEvent + LLMDecision stored in state
   b. blue_node: reads logs.jsonl (may be sparse at step 0)
   c. prune_node: no prior obs → pass through
   d. evaluation_node: memory empty → no retrieval
   e. risk_node: step 0 → risk stays near 0.0
      - Appends step tuple (now including llm_decision) to M
      - Broadcasts StepUpdate to dashboard
      - step = 1

   ... loop continues for MAX_STEPS steps ...

   Episode 1, Step 50 (MAX_STEPS reached):
   a-e. normal step execution
   e.   risk_node: supervisor_trigger = True → route to "policy"
   f.   policy_node: Gemini call 1 — episode analysis + IOC ingestion
        - Appends episode summary to episode_pool
        - Ingests ioc_exports into knowledge_base
        - Broadcasts EpisodeReport to dashboard
   g.   🔄 NEW: patch_node: Gemini call 2 — patch generation + verification
        - For each vulnerability in supervisor_report:
          - Call Gemini to generate patch code
          - Apply via exec() to running router
          - Verify by re-running original exploit
        - Broadcasts PatchSummary to dashboard
        - Persists patch_records to data/patch_records.json
   h.   reset_node: episode = 2, step = 0, M cleared
        - 🔄 behavioral_fingerprints NOT cleared (persists for cross-episode fingerprinting)
        - 🔄 patch_records NOT cleared (accumulates across episodes)
        - 🔄 ioc_exports cleared (reset for next episode)
   i.   Loop returns to red_node for Episode 2
        - Episode 2 Ollama prompt includes episode_pool summary
        - Red team opens with higher weight on unexploited techniques
```

---

## 13. Environment Setup

### `requirements.txt`

> 🔄 **CHANGED:** `ollama` added.

```
fastapi==0.111.0
uvicorn[standard]==0.29.0
langgraph==0.2.28
langchain-core==0.2.10
google-generativeai==0.7.2
httpx==0.27.0
networkx==3.3
numpy==1.26.4
python-dotenv==1.0.1
pydantic==2.7.4
ollama==0.2.1
```

### `.env.example`

> 🔄 **CHANGED:** `OLLAMA_MODEL` added.

```
GEMINI_API_KEY=your_gemini_api_key_here
OLLAMA_MODEL=llama3
```

### Ollama Setup (NEW — required before running)

```bash
# Install Ollama (macOS)
brew install ollama

# Install Ollama (Linux)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the model (one time, ~4GB download)
ollama pull llama3

# Verify it works
ollama run llama3 "Say hello in one word"

# Start the server (usually auto-starts, but if not:)
ollama serve
```

If `llama3` is too large for your hardware, use `mistral` (4GB) or `llama3:8b` (4.7GB). Update `OLLAMA_MODEL` in `.env` to match.

### Frontend Setup (UNCHANGED)

```bash
cd frontend
npm install
npm run dev
```

### Running Everything

```bash
# Terminal 1 — Ollama (if not auto-started)
ollama serve

# Terminal 2 — Backend
cd cyber-defense-arena
pip install -r requirements.txt
uvicorn backend.main:app --port 8000

# Terminal 3 — Frontend
cd cyber-defense-arena/frontend
npm run dev
# Dashboard available at http://localhost:5173
```

---

## 14. Implementation Order

> 🔄 **CHANGED:** Phase 3 now includes Ollama client and new red agent files. Phase 5 adds patch_agent. Verification steps updated.

### Phase 1 — Target App (UNCHANGED from V1)
1. `backend/target/vuln_store.py`
2. `backend/target/router.py`
3. `backend/target/middleware.py`
4. `backend/main.py` skeleton
5. **Verify:** `curl http://localhost:8000/target/login -d '{"username":"admin","password":"admin123"}'` returns 200

### Phase 2 — LangGraph Skeleton (UNCHANGED from V1)
1. `backend/state.py` — include all new V2 fields
2. `backend/config.py` — include all new V2 constants
3. `backend/graph/langgraph_flow.py` — graph with stub nodes including patch_node stub
4. `backend/graph/reset.py`
5. **Verify:** `arena.invoke(get_initial_state())` runs without error

### Phase 3 — Red Team (🔄 CHANGED)
1. `backend/llm/ollama_client.py` — Ollama wrapper
2. **Verify Ollama:** `python -c "from backend.llm.ollama_client import check_ollama_available; print(check_ollama_available())"` returns `True`
3. `backend/agents/red/recon.py` — UNCHANGED from V1
4. `backend/agents/red/bruteforce.py` — add `llm_decision` param
5. `backend/agents/red/exploit.py` — add `llm_decision` param + `run_generic()`
6. `backend/agents/red/business_logic.py` — new file
7. `backend/agents/red/evasion.py` — new file
8. `backend/agents/red/strategy.py` — COMPLETELY REPLACED with Ollama-driven version
9. Replace red_node stub in `langgraph_flow.py`
10. **Verify:** Running the graph produces real HTTP traffic AND console shows Ollama rationale strings

### Phase 4 — Blue Team (🔄 CHANGED)
1. `backend/agents/blue/log_monitor.py` — UNCHANGED from V1
2. `backend/agents/blue/anomaly_detector.py` — V1 rules + 3 new rules
3. `backend/agents/blue/responder.py` — V1 actions + 3 new actions
4. Add enforcement to `middleware.py`
5. Replace blue_node stub
6. **Verify:** After bruteforce runs, rate limiting fires AND behavioral fingerprint is stored

### Phase 5 — Supervisor + Patches (🔄 CHANGED)
1. `backend/memory/short_term.py` — add `llm_decision` param
2. `backend/memory/episode_pool.py` — UNCHANGED from V1
3. `backend/agents/supervisor/pruner.py` — UNCHANGED from V1
4. `backend/agents/supervisor/evaluation_agent.py` — UNCHANGED from V1
5. `backend/agents/supervisor/gemini_client.py` — UNCHANGED from V1
6. `backend/agents/supervisor/policy_agent.py` — add IOC ingestion
7. `backend/agents/supervisor/patch_agent.py` — new file
8. `backend/graph/patch_node.py` — wire patch_node into graph
9. Replace supervisor stubs
10. **Verify:** After 50 steps, Gemini produces report AND patch records show ✓ VERIFIED entries

### Phase 6 — Dashboard (CHANGED: add PatchSummary handling)
1. `backend/ws/broadcaster.py` — add `broadcast_patch_summary()`
2. Wire broadcasts into risk_node, policy_node, and patch_node
3. `backend/main.py` WebSocket endpoint
4. `frontend/src/hooks/useArenaSocket.ts` — handle `patch_summary` message type
5. All 6 components (V1 unchanged) + Patches tab in ReportPanel
6. **Verify:** Dashboard shows patch cards with verification status after episode ends

---

## 15. Critical Rules for the Coding Agent

**Rules 1–10 from V1 are all preserved.** New rules added below.

**Rule 1 — Never call Gemini outside of `policy_agent.py` and `patch_agent.py`.**

**Rule 2 — `SystemState` is append-only within a step.** Each node returns only changed fields.

**Rule 3 — `logs.jsonl` is append-only.**

**Rule 4 — Target app and agent system share a process.** Use `STATE_LOCK` for writes to `blocked_ips`, `rate_limited_endpoints`, and `behavioral_fingerprints`.

**Rule 5 — Red team agents make real HTTP requests using `httpx.Client` (sync).**

**Rule 6 — Pruning never removes more than half the observation attributes.**

**Rule 7 — Record every attempt in `short_term_memory`.** Now includes `llm_decision`.

**Rule 8 — `knowledge_base.json` starts read-only but can be extended at runtime via `ioc_exports`.** The base file is never overwritten — new entries are appended to the in-memory list and optionally persisted to a separate `knowledge_base_runtime.json`.

**Rule 9 — Handle missing `logs.jsonl` gracefully.**

**Rule 10 — WebSocket broadcast is fire-and-forget.**

> 🔄 **NEW Rule 11 — Ollama is called synchronously in `strategy.py` only.**
Never call Ollama from blue team agents, supervisor agents, or any node other than `red_node`. If Ollama times out (>OLLAMA_TIMEOUT_S), use `_fallback_decision()` and continue — never let an Ollama timeout crash the arena loop.

> 🔄 **NEW Rule 12 — `patch_agent.py` uses `exec()` with a controlled namespace.**
Never pass an open namespace to exec(). Always build an explicit dict of allowed imports. Wrap every exec() call in try/except. A failed patch should log the error and set `patch_applied=False` — it must never crash the arena loop. The arena loop is more important than any individual patch attempt.

> 🔄 **NEW Rule 13 — Agent executors are parameterized, not rewritten.**
When `llm_decision` is provided to `exploit.py` or `bruteforce.py`, it augments the agent's behavior — the LLM-specified payload is tried first, then hardcoded fallbacks if needed. Do not delete the hardcoded payload lists. They serve as safety nets when the LLM produces an incomplete or malformed decision.

> 🔄 **NEW Rule 14 — `behavioral_fingerprints` persists across episodes.**
`reset_node` clears step-level state (M, risk_history, vulnerabilities_found) but must NOT clear `behavioral_fingerprints`. Fingerprints accumulated in episode 1 must be available for episode 2's blue team. This is what makes IP-rotation defense durable.

> 🔄 **NEW Rule 15 — The LLMDecision rationale field must be logged every step.**
The `rationale` string from Ollama is the most important demo artifact. It shows the judge that the red team is reasoning, not scripting. Print it to console in `red_node` (already shown in the implementation above) and include it in the WebSocket `StepUpdate` message so the dashboard can display it.

> 🔄 **NEW Rule 16 — Two Gemini calls per episode, not one.**
`policy_node` = Gemini call 1 (analysis). `patch_agent.py` = Gemini call 2 (patch generation). At 50 steps × 0.3s per step = 15 seconds per episode, you make 2 Gemini calls per 15 seconds = 8 calls/minute. This is safely under the 15 RPM free tier limit. Do not add more Gemini calls.

---

## Connecting This Chat to Claude Code

> **Direct answer to the question:** There is no native "continue this conversation in Claude Code" button. The best workflow is:

1. **Save this document** as `PROMPT_V2.md` in your repo root
2. **Start Claude Code** in your project directory: `claude` (in terminal with Claude Code installed)
3. **Open this file** in the Claude Code session: the command `claude --context PROMPT_V2.md` or simply paste the relevant section when asking Claude Code to implement a specific file
4. **The most effective approach** for Claude Code is to give it one file at a time with the relevant section of this document. For example:
   ```
   Implement backend/llm/ollama_client.py exactly as specified 
   in Section 8.2 (the NEW: ollama_client.py block) of PROMPT_V2.md
   ```
5. **For the changed files**, tell Claude Code explicitly: "This file exists from V1. Make only the changes marked with 🔄 CHANGED in PROMPT_V2.md Section 8.2. Do not rewrite anything not marked as changed."

The change markers (`🔄 CHANGED`, `🔄 NEW`) in this document are specifically designed to help Claude Code know exactly what to touch and what to leave alone.

---

*End of PROMPT_V2.md — implement in the order given in Section 14. The Change Summary at the top of this document is the authoritative list of what changed from V1. When in doubt, the SystemState schema in Section 5 and the LangGraph topology in Section 6 are the ground truth.*
