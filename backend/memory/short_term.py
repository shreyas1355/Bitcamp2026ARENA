"""
short_term.py — Short-term memory M (micro-memory block).

Stores step-level trajectory tuples: (obs, attack, defense, result).
Implemented as a module-level deque with maxlen=MAX_MEMORY_SIZE.
When the deque is full, the oldest entry is automatically evicted.

LangGraph nodes access this via the functions below.
The SystemState["short_term_memory"] field holds a list copy for
serialization — always call get_all() to sync it into state returns.
"""

from collections import deque
from typing import Any, Dict, List, Optional

from backend.config import MAX_MEMORY_SIZE

_memory: deque = deque(maxlen=MAX_MEMORY_SIZE)


def append_step(
    obs:     Dict[str, float],
    attack:  Optional[Dict[str, Any]],
    defense: Optional[Dict[str, Any]],
    result:  str,
    harvested_token: Optional[str] = None,
) -> None:
    """
    Appends one step tuple to memory M.

    Args:
        obs:             pruned_observation dict at this step
        attack:          AttackEvent dict (or None if no attack this step)
        defense:         DefenseEvent dict (or None if no defense this step)
        result:          string summary e.g. "bruteforce:success" or "sqli:blocked"
        harvested_token: session token if the attack captured one, else None
    """
    _memory.append({
        "obs":             obs,
        "attack":          attack,
        "defense":         defense,
        "result":          result,
        "defense_action":  defense.get("action", "none") if defense else "none",
        "harvested_token": harvested_token,
    })


def get_all() -> List[Dict[str, Any]]:
    """
    Returns a list copy of all entries in M.
    Use this to set SystemState["short_term_memory"] in node return dicts.
    """
    return list(_memory)


def get_recent(n: int) -> List[Dict[str, Any]]:
    """Returns the last n entries. Returns all if n > len(memory)."""
    entries = list(_memory)
    return entries[-n:] if n < len(entries) else entries


def get_harvested_tokens() -> List[str]:
    """Returns all non-None harvested tokens in memory. Used by exploit agent."""
    return [
        entry["harvested_token"]
        for entry in _memory
        if entry.get("harvested_token")
    ]


def clear() -> None:
    """Called by reset_node at episode boundary."""
    _memory.clear()


def size() -> int:
    return len(_memory)
