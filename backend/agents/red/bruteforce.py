"""
bruteforce.py — Credential spraying and stuffing agent.

TODO (Dev B, Phase 3): Implement this file.
See PROMPT.md Section 8.2 for full spec.

Techniques:
- Credential stuffing (known leaked pairs)
- Password spraying (one password, many usernames)
- Response discrimination (different error messages leak username existence)
- Timing-based username enumeration
- Slow mode (random delays to evade rate-based detection)
"""

import time
from backend.state import SystemState
from backend.config import TARGET_BASE_URL

# Known leaked credential pairs — used for stuffing phase
LEAKED_CREDENTIALS = [
    ("admin",  "admin123"),
    ("admin",  "admin"),
    ("guest",  "guest"),
    ("user",   "user2024"),
    ("alice",  "alice2024"),
    ("bob",    "bob2024"),
    ("root",   "toor"),
    ("test",   "test123"),
]

COMMON_PASSWORDS = [
    "password", "123456", "admin", "letmein", "Password1",
    "qwerty", "welcome", "monkey", "1234567890", "password123",
    "admin123", "guest", "test", "user", "login", "pass",
    "secret", "root",
]

COMMON_USERNAMES = [
    "admin", "administrator", "user", "test", "guest", "root",
    "john", "alice", "bob", "service", "api", "operator",
]


def run(state: SystemState, slow_mode: bool = False) -> dict:
    """
    TODO (Dev B): Implement bruteforce agent.

    Phase 1 — Credential stuffing: try LEAKED_CREDENTIALS pairs.
    Phase 2 — Password spraying: if stuffing fails.
    Phase 3 — Response discrimination: parse error messages.

    Slow mode: sleep random.uniform(1.0, 5.0) between attempts.
    Auto-enable slow mode if last 3 attempts all returned 429.

    Returns an AttackEvent dict.
    """
    return {
        "type":      "bruteforce",
        "target":    "/login",
        "payload":   "STUB",
        "result":    "failed",
        "evidence":  "STUB — implement bruteforce.py",
        "cwe":       "",
        "severity":  "medium",
        "timestamp": time.time(),
    }
