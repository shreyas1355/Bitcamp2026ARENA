"""
strategy.py — red_node: entropy-weighted attack agent selector.

TODO (Dev B, Phase 3): Implement this file.

Selects which attack agent to run each step using entropy-weighted routing.
See PROMPT.md Section 8.2 for full spec.
"""

import time
from backend.state import SystemState


def red_node(state: SystemState) -> dict:
    """
    TODO (Dev B): Implement entropy-weighted agent selection + execution.

    1. Compute weights for each agent based on:
       - Recent usage in short_term_memory (penalize recently used)
       - Active mitigations (penalize if agent's target is fully mitigated)
       - Supervisor strategy recommendation (boost recommended agent type)
    2. Softmax-normalize weights
    3. Sample agent
    4. Call agent's run(state) function
    5. Return {"last_attack": result}
    """
    # STUB
    return {
        "last_attack": {
            "type":      "bruteforce",
            "target":    "/login",
            "payload":   "admin:password",
            "result":    "failed",
            "evidence":  "HTTP 401 (STUB — implement strategy.py)",
            "cwe":       "",
            "severity":  "medium",
            "timestamp": time.time(),
        }
    }
