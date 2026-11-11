# arena

A continuous, autonomous cybersecurity stress-testing system inspired by the SEMA framework (arXiv:2603.23875).

Red Team agents attack a real FastAPI application over HTTP. Blue Team agents detect and mitigate those attacks using rule-based logic. A Gemini-powered Supervisor reasons about system security posture once per episode and produces structured vulnerability reports.

<img width="806" height="423" alt="gallery" src="https://github.com/user-attachments/assets/8025da88-e1fa-4da3-9781-debe7cda11a4" />
<img width="806" height="464" alt="gallery (1)" src="https://github.com/user-attachments/assets/80dc6459-454e-4d91-8357-9bed6625151e" />

## Architecture

```
LangGraph orchestration loop
  red_node → blue_node → prune_node → evaluation_node → risk_node
                                                              ↓ (every N steps)
                                                         policy_node → reset_node
```

- **Red Team** — rule-based attack agents (recon, bruteforce, SQLi, IDOR, path traversal, auth bypass)
- **Blue Team** — rule-based detection and mitigation (10 anomaly rules, IP blocking, rate limiting, endpoint patching)
- **Supervisor** — SEMA-inspired structural entropy pruning + Gemini 1.5 Flash for post-episode analysis
- **Dashboard** — React live dashboard showing risk score, attack/defense feed, and episode reports

## Quickstart

### Backend

```bash
cp .env.example .env
# Add your GEMINI_API_KEY to .env

pip install -r requirements.txt
uvicorn backend.main:app --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Dashboard at http://localhost:5173
```

## SEMA Framework Connection

This project implements SEMA's three core principles:

1. **Structural Entropy Pruning** (`backend/agents/supervisor/pruner.py`) — direct implementation of Algorithm 1 from the paper. Builds a weighted attribute graph from observation deltas, scores nodes by δH = α·ΔHG + β·ΔHT, prunes low-entropy attributes before each Gemini call.

2. **Three-Agent Role Separation** — Decision Agent (red team, rule-based), Evaluation Agent (cosine similarity retrieval, no LLM), Policy Agent (Gemini, once per episode).

3. **Hierarchical Memory L = ⟨M, E, K⟩** — short-term step tuples (M), episode summaries (E), static knowledge base (K).

## Team

Built at Bitcamp 2026 by Runtime Errors.
