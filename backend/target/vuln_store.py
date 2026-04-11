"""
vuln_store.py — In-memory "database" for the vulnerable target application.

TODO (Dev B, Phase 1): This file is mostly complete.
Add any additional seed data needed for your exploit scenarios.

This is intentionally simple — no real database, no persistence.
The data resets every time the server restarts, which is fine for the demo.
"""

import secrets
from typing import Dict, List, Optional

# ── User store ─────────────────────────────────────────────────────────────────

USERS: Dict[str, Dict] = {
    "admin": {
        "id":       1,
        "password": "admin123",
        "role":     "admin",
        "email":    "admin@corp.internal",
    },
    "alice": {
        "id":       2,
        "password": "alice2024",
        "role":     "user",
        "email":    "alice@corp.internal",
    },
    "bob": {
        "id":       3,
        "password": "bob2024",
        "role":     "user",
        "email":    "bob@corp.internal",
    },
    "guest": {
        "id":       4,
        "password": "guest",
        "role":     "guest",
        "email":    "guest@corp.internal",
    },
}

# ── Data records (owned by users) ─────────────────────────────────────────────

DATA_RECORDS: Dict[int, Dict] = {
    1:  {"id": 1,  "owner": "admin", "classification": "CONFIDENTIAL",
         "content": "Q3 Financial Report: Revenue $4.2M, EBITDA $1.1M"},
    2:  {"id": 2,  "owner": "alice", "classification": "INTERNAL",
         "content": "Alice's project notes: Sprint 12 backlog items"},
    3:  {"id": 3,  "owner": "bob",   "classification": "INTERNAL",
         "content": "Bob's personal notes: vacation request pending"},
    4:  {"id": 4,  "owner": "admin", "classification": "CONFIDENTIAL",
         "content": "Employee salary data: see attached spreadsheet"},
    5:  {"id": 5,  "owner": "admin", "classification": "SECRET",
         "content": "AWS root credentials: ACCESS_KEY=AKIA... SECRET=..."},
    6:  {"id": 6,  "owner": "alice", "classification": "INTERNAL",
         "content": "Alice's draft blog post about the new product launch"},
    7:  {"id": 7,  "owner": "bob",   "classification": "INTERNAL",
         "content": "Bob's expense report for Q3 travel"},
    8:  {"id": 8,  "owner": "admin", "classification": "CONFIDENTIAL",
         "content": "Board meeting minutes: acquisition target discussed"},
}

# ── Active sessions ────────────────────────────────────────────────────────────
# token (str) → username (str)

SESSIONS: Dict[str, str] = {}


def create_session(username: str) -> str:
    """Creates a new session token for username and stores it."""
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    return token


def get_session_user(token: str) -> Optional[str]:
    """Returns username for token, or None if token is invalid."""
    return SESSIONS.get(token)


def validate_user(username: str, password: str) -> Optional[Dict]:
    """Returns user dict if credentials are valid, else None."""
    user = USERS.get(username)
    if user and user["password"] == password:
        return user
    return None


# ── Transfer log ───────────────────────────────────────────────────────────────

TRANSFERS: List[Dict] = []


def record_transfer(from_user: str, to_user: str, amount: float) -> Dict:
    transfer = {
        "id":        len(TRANSFERS) + 1,
        "from":      from_user,
        "to":        to_user,
        "amount":    amount,
        "timestamp": __import__("time").time(),
    }
    TRANSFERS.append(transfer)
    return transfer
