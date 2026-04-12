"""
recon.py — Endpoint enumeration and surface mapping for the red team.

Probes the mounted target app with a small wordlist and optional OpenAPI discovery.
Ignores LLMDecision (strategy layer may still label technique as recon / surface_mapping).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

import httpx

from backend.config import TARGET_BASE_URL
from backend.state import AttackEvent, SystemState

# Paths relative to TARGET_BASE_URL (e.g. .../target/login)
_DEFAULT_PROBE_ROUTES: List[Tuple[str, str]] = [
    ("GET", "/login"),   # expect 405 Method Not Allowed — confirms route exists
    ("POST", "/login"),
    ("GET", "/data"),
    ("GET", "/admin"),
    ("POST", "/transfer"),
    ("GET", "/files"),
]

_CLIENT_TIMEOUT = httpx.Timeout(12.0)


def _probe_once(
    client: httpx.Client,
    method: str,
    path: str,
) -> Dict[str, Any]:
    """Sends one HTTP request and returns a compact result dict for evidence."""
    url = f"{TARGET_BASE_URL.rstrip('/')}{path}"
    try:
        if method == "GET":
            r = client.get(url, timeout=_CLIENT_TIMEOUT)
        elif method == "POST":
            r = client.post(url, json={}, timeout=_CLIENT_TIMEOUT)
        else:
            r = client.request(method, url, timeout=_CLIENT_TIMEOUT)
        return {"method": method, "path": path, "status": r.status_code, "len": len(r.text)}
    except Exception as e:
        return {"method": method, "path": path, "error": str(e)[:120]}


def _try_openapi(client: httpx.Client) -> Dict[str, Any] | None:
    """Fetches FastAPI OpenAPI schema if exposed — high value for the strategy LLM."""
    for suffix in ("/openapi.json", "/docs"):
        url = f"{TARGET_BASE_URL.rstrip('/')}{suffix}"
        try:
            r = client.get(url, timeout=_CLIENT_TIMEOUT)
            ok = r.status_code == 200 and (
                "openapi" in r.text[:200].lower() or suffix == "/docs"
            )
            if ok:
                return {"openapi_or_docs": suffix, "status": r.status_code, "bytes": len(r.text)}
        except Exception:
            continue
    return None


def run(state: SystemState) -> AttackEvent:
    """
    Runs a light recon pass: probes configured routes and optionally discovers OpenAPI.

    Returns an AttackEvent summarizing reachable endpoints (always result=success for demo;
    value is in evidence string for pruning / LLM context).
    """
    _ = state  # recon does not yet consume memory; reserved for future prioritization

    lines: List[str] = []
    with httpx.Client(headers={"User-Agent": "ACDA-recon/1.0"}) as client:
        for method, path in _DEFAULT_PROBE_ROUTES:
            row = _probe_once(client, method, path)
            lines.append(f"{row.get('method')} {row.get('path')} → {row.get('status', row.get('error'))}")

        extra = _try_openapi(client)
        if extra:
            lines.append(f"discovery: {extra}")

    evidence = " | ".join(lines[:12])
    if len(lines) > 12:
        evidence += f" … (+{len(lines) - 12} more)"

    return AttackEvent(
        type="recon",
        target="/",
        payload="surface_probe",
        result="success",
        evidence=evidence[:2000],
        cwe="",
        severity="info",
        timestamp=time.time(),
    )
