"""
SEMA evaluation agent: cosine similarity retrieval from short-term memory M.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np

from backend.state import SystemState


def vectorize_obs(obs: Dict[str, float], key_order: List[str]) -> np.ndarray:
    """Fixed key order → vector (missing keys → 0.0)."""
    return np.array([float(obs.get(k, 0.0)) for k in key_order], dtype=np.float64)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity; 0.0 if either vector is (near) zero."""
    na = np.linalg.norm(a)
    nb = np.linalg.norm(b)
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


def evaluation_node(state: SystemState) -> Dict[str, Any]:
    pruned = state.get("pruned_observation") or {}
    if not pruned:
        return {"retrieved_similar_step": None, "prior_recommendation": "none"}

    key_order = sorted(pruned.keys())
    cur = vectorize_obs(pruned, key_order)

    mem: List[Dict[str, Any]] = state.get("short_term_memory") or []
    best_sim = -1.0
    best_entry: Optional[Dict[str, Any]] = None

    for entry in mem:
        past = entry.get("obs") or {}
        if not past:
            continue
        vec = vectorize_obs(past, key_order)
        sim = cosine_similarity(cur, vec)
        if sim > best_sim:
            best_sim = sim
            best_entry = entry

    if best_entry is None:
        return {"retrieved_similar_step": None, "prior_recommendation": "none"}

    prior = str(best_entry.get("defense_action", "none"))
    return {
        "retrieved_similar_step": best_entry,
        "prior_recommendation": prior,
    }
