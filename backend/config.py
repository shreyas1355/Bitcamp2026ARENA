"""
config.py — all tuneable constants for the ACDA system.

RULES FOR ALL DEVELOPERS:
- Every magic number in the codebase must come from here.
- Never hardcode values in agent files. Import from config.
- To change system behavior, change values here only.
"""

import os

# ── Target application ─────────────────────────────────────────────────────────
TARGET_BASE_URL = "http://127.0.0.1:8000/target"
TARGET_HOST     = "127.0.0.1"
TARGET_PORT     = 8000

# ── LangGraph execution ────────────────────────────────────────────────────────
MAX_STEPS       = 50     # steps per episode before supervisor fires
STEP_DELAY_S    = 0.3    # sleep between steps (keeps demo readable on dashboard)
# Cyclic graph has no END; invoke stops at this Pregel step count — main.py restarts invoke.
ARENA_RECURSION_LIMIT = 100_000

# ── Memory ─────────────────────────────────────────────────────────────────────
MAX_MEMORY_SIZE = 50     # max entries in short-term memory M (deque maxlen)
MAX_POOL_SIZE   = 20     # max episode summaries stored in E

# ── SEMA pruning parameters (from paper Section 4.2) ──────────────────────────
PRUNE_ALPHA = 0.95   # weight of global structural entropy ΔHG
PRUNE_BETA  = 0.05   # weight of local tree entropy ΔHT
PRUNE_MU    = 0.05   # pruning threshold — nodes with δH < MU are candidates
PRUNE_N     = 8      # max nodes to prune per step

# ── Risk scoring ───────────────────────────────────────────────────────────────
RISK_DECAY = 0.95
RISK_SEVERITY_WEIGHTS = {
    "critical": 0.25,
    "high":     0.15,
    "medium":   0.08,
    "low":      0.02,
    "info":     0.00,
}
RISK_ATTACK_SUCCESS_BONUS  =  0.10
RISK_MITIGATION_DISCOUNT   = -0.05

# ── Anomaly detection thresholds ──────────────────────────────────────────────
ANOMALY_LOGIN_RATE_THRESHOLD      = 10    # failed logins per window → brute force
ANOMALY_FLOOD_THRESHOLD           = 50    # requests per endpoint per window → flood
ANOMALY_RECON_ENDPOINT_THRESHOLD  = 7     # distinct endpoints from one IP → recon
ANOMALY_TIMING_CV_THRESHOLD       = 0.3   # coefficient of variation → scripted probe
ANOMALY_IDOR_SEQ_THRESHOLD        = 3     # consecutive sequential IDs → IDOR scan
ANOMALY_STUFFING_USERNAMES        = 5     # unique usernames with low success → stuffing
ANOMALY_STUFFING_SUCCESS_RATE     = 0.05  # max success rate to trigger stuffing rule
ANOMALY_ADMIN_PROBE_THRESHOLD     = 3     # failed /admin attempts → probing

# ── Log observation window ────────────────────────────────────────────────────
LOG_WINDOW_SECONDS = 60    # look at last N seconds of logs for observations
MAX_LOG_LINES      = 500   # never read more than this many lines from log tail

# ── Rate limiting (applied as mitigations) ────────────────────────────────────
RATE_LIMIT_LOGIN_HIGH      = 10   # req/min — high login rate finding
RATE_LIMIT_LOGIN_STUFFING  = 3    # req/min — credential stuffing finding
RATE_LIMIT_FLOOD           = 20   # req/min — endpoint flood finding

# ── Gemini ─────────────────────────────────────────────────────────────────────
GEMINI_MODEL         = "gemini-2.5-flash-lite"
GEMINI_MAX_RETRIES   = 3
GEMINI_RETRY_DELAY_S = 5.0

# ── File paths ─────────────────────────────────────────────────────────────────
LOG_FILE            = "data/logs.jsonl"
EPISODE_POOL_FILE   = "data/episode_pool.json"
KNOWLEDGE_BASE_FILE = "data/knowledge_base.json"
SAMPLE_LOGS_FILE    = "data/sample_logs.jsonl"

# ── V2: Ollama (local LLM for red team strategy) ───────────────────────────────
# Called every step from strategy.py only. Zero API cost — runs locally.
# Start with: `ollama serve`  |  Pull with: `ollama pull llama3`
OLLAMA_MODEL          = os.environ.get("OLLAMA_MODEL", "llama3")
OLLAMA_FALLBACK_MODEL = "mistral"   # tried if llama3 is not available
OLLAMA_TIMEOUT_S      = 10.0        # per-step timeout; if exceeded, use fallback decision
OLLAMA_PING_TIMEOUT_S = 5.0         # startup health check for check_ollama_available()
# Max tokens per chat completion (JSON decisions need room for rationale + fields).
# Increase if you see truncated JSON mid-string; set via env OLLAMA_NUM_PREDICT.
OLLAMA_NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "1024"))

# ── V2: Attack layer escalation ────────────────────────────────────────────────
# If a layer's success rate drops below this, LLM is hinted to escalate.
ATTACK_LAYER_ESCALATION_THRESHOLD = 0.15

# ── V2: Behavioral fingerprinting ─────────────────────────────────────────────
FINGERPRINT_SIMILARITY_THRESHOLD = 0.80  # cosine similarity above this = same attacker
FINGERPRINT_MIN_REQUESTS         = 5     # minimum requests needed to build a fingerprint

# ── V2: Patch generation ──────────────────────────────────────────────────────
PATCH_RECORDS_FILE           = "data/patch_records.json"
PATCH_VERIFICATION_TIMEOUT_S = 5.0   # time allowed for verification HTTP request
MAX_PATCHES_PER_EPISODE      = 5     # cap Gemini calls from patch_agent per episode

# ── V2: Additional anomaly detection thresholds ───────────────────────────────
ANOMALY_SUCCESS_RATE_THRESHOLD = 3   # successful 200s from one IP → anomalous success
