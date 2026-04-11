"""
episode_pool.py — Episode-level experience pool E (macro-experience).

Stores post-episode strategy summaries produced by the Gemini Policy Agent.
Persisted to data/episode_pool.json after each update.
Loaded at startup via main.py into SystemState["episode_pool"].
"""

import json
from typing import List

from backend.config import EPISODE_POOL_FILE, MAX_POOL_SIZE


def load_pool() -> List[str]:
    """
    Loads episode pool from JSON file.
    Returns empty list if file does not exist.
    """
    try:
        with open(EPISODE_POOL_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        print(f"[WARN] {EPISODE_POOL_FILE} is malformed — starting with empty pool")
        return []


def append_summary(summary: str) -> List[str]:
    """
    Appends an episode summary to the pool and persists to disk.
    Trims to MAX_POOL_SIZE (keeps most recent).

    Returns the updated pool as a list.
    """
    pool = load_pool()
    pool.append(summary)

    # Keep only the most recent MAX_POOL_SIZE entries
    if len(pool) > MAX_POOL_SIZE:
        pool = pool[-MAX_POOL_SIZE:]

    _persist(pool)
    return pool


def get_recent(n: int = 3) -> List[str]:
    """
    Returns the last n episode summaries.
    Returns [] if pool file does not exist.
    """
    pool = load_pool()
    return pool[-n:] if n < len(pool) else pool


def _persist(pool: List[str]) -> None:
    """Writes the pool to disk. Creates the file if it doesn't exist."""
    try:
        with open(EPISODE_POOL_FILE, "w") as f:
            json.dump(pool, f, indent=2)
    except OSError as e:
        print(f"[ERROR] Could not persist episode pool: {e}")
