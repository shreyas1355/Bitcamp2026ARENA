"""
SEMA structural entropy observation pruning (Algorithm 1, PROMPT §2 / §8.4).
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

import networkx as nx

from backend.config import PRUNE_ALPHA, PRUNE_BETA, PRUNE_MU, PRUNE_N
from backend.state import SystemState


def build_attribute_graph(
    obs: Dict[str, float], prev_obs: Dict[str, float]
) -> nx.Graph:
    """
    Weighted graph on observation keys. Edge weight from SEMA eq. 6–7 (L∞ normalized).
    """
    G = nx.Graph()
    keys = list(obs.keys())
    for k in keys:
        G.add_node(k)

    if len(keys) < 2:
        return G

    phis: list[float] = []
    pair_keys: list[Tuple[str, str]] = []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            ki, kj = keys[i], keys[j]
            delta_i = abs(obs[ki] - prev_obs.get(ki, obs[ki]))
            delta_j = abs(obs[kj] - prev_obs.get(kj, obs[kj]))
            prod = abs(delta_i * delta_j)
            phi = prod * math.log1p(prod)
            phis.append(phi)
            pair_keys.append((ki, kj))

    max_phi = max(phis) if phis else 0.0
    if max_phi <= 1e-18:
        return G

    for phi, (ki, kj) in zip(phis, pair_keys):
        w = phi / max_phi
        G.add_edge(ki, kj, weight=w)

    return G


def structural_entropy_1d(G: nx.Graph) -> float:
    """
    H₁(G) = −Σᵥ (dᵥ / vol(G)) · log₂(dᵥ / vol(G))  [SEMA eq. 2]
    """
    if G.number_of_nodes() == 0:
        return 0.0

    degrees: Dict[str, float] = {n: 0.0 for n in G.nodes()}
    for u, v, data in G.edges(data=True):
        w = float(data.get("weight", 1.0))
        degrees[u] += w
        degrees[v] += w

    vol = sum(degrees.values())
    if vol <= 1e-18:
        return 0.0

    h = 0.0
    for d in degrees.values():
        if d <= 1e-18:
            continue
        p = d / vol
        h -= p * math.log(p, 2.0)
    return float(h)


def compute_delta_h_graph(G: nx.Graph, node: str) -> float:
    """ΔHG = |H₁(G) − H₁(G \\ {node})|"""
    if node not in G:
        return 0.0
    h0 = structural_entropy_1d(G)
    G2 = G.copy()
    G2.remove_node(node)
    h1 = structural_entropy_1d(G2)
    return abs(h0 - h1)


def compute_delta_h_tree(G: nx.Graph, node: str) -> float:
    """Proxy: local clustering coefficient (PROMPT §8.4)."""
    if node not in G or G.number_of_nodes() < 2:
        return 0.0
    try:
        cmap = nx.clustering(G, [node], weight="weight")
        c = float(cmap.get(node, 0.0))
    except Exception:
        cmap = nx.clustering(G, [node])
        c = float(cmap.get(node, 0.0))
    return c


def _delta_h_for_node(G: nx.Graph, node: str) -> float:
    return PRUNE_ALPHA * compute_delta_h_graph(G, node) + PRUNE_BETA * compute_delta_h_tree(
        G, node
    )


def prune_observation(state: SystemState) -> Dict[str, object]:
    obs: Dict[str, float] = dict(state.get("raw_observation") or {})
    if not obs:
        return {"pruned_observation": {}, "last_prune_removed": []}

    mem = state.get("short_term_memory") or []
    if mem:
        prev_entry = mem[-1]
        # Use raw_obs for delta computation so previously-pruned attributes
        # retain their true prior values. Falling back to "obs" (pruned) would
        # give delta=0 for any attribute that was pruned last step, locking
        # those attributes into permanent zero-δH and defeating the algorithm.
        prev_obs = dict(prev_entry.get("raw_obs") or prev_entry.get("obs") or {})
    else:
        prev_obs = dict(obs)

    G = build_attribute_graph(obs, prev_obs)
    keys = list(obs.keys())

    if len(keys) <= 1 or G.number_of_edges() == 0:
        return {"pruned_observation": dict(obs), "last_prune_removed": []}

    delta_map: Dict[str, float] = {k: _delta_h_for_node(G, k) for k in keys}

    vcand = [k for k in keys if delta_map[k] < PRUNE_MU]
    if not vcand:
        return {"pruned_observation": dict(obs), "last_prune_removed": []}

    vcand_sorted = sorted(vcand, key=lambda k: delta_map[k])
    if len(vcand_sorted) > PRUNE_N:
        vremove_candidates = vcand_sorted[:PRUNE_N]
    else:
        vremove_candidates = vcand_sorted

    max_remove = len(obs) // 2
    if max_remove < 1:
        return {"pruned_observation": dict(obs), "last_prune_removed": []}
    vremove = vremove_candidates[:max_remove]

    pruned = {k: v for k, v in obs.items() if k not in vremove}
    removed_meta: List[Dict[str, Any]] = [
        {"attribute": k, "delta_h": round(float(delta_map.get(k, 0.0)), 6)}
        for k in vremove
    ]
    removed_meta.sort(key=lambda r: r["delta_h"])
    print(
        f"  [PRUNE] removed {len(vremove)}/{len(keys)} attrs: {vremove[:12]}"
        f"{'...' if len(vremove) > 12 else ''}"
    )
    return {"pruned_observation": pruned, "last_prune_removed": removed_meta}


def prune_node(state: SystemState) -> Dict[str, object]:
    return prune_observation(state)
