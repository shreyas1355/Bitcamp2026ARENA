"""
middleware.py — Security middleware: request logger + IP blocker + rate limiter.

TODO (Dev B, Phase 1): Implement logging first.
TODO (Dev B, Phase 4): Add IP blocking and rate limiting enforcement.

Runs on every request to the target router.
Reads blocked_ips, rate_limited_endpoints, and deep_logging_ips from SYSTEM_STATE.
Appends one JSON line per request to data/logs.jsonl.
"""

import hashlib
import json
import time
from collections import defaultdict, deque
from typing import Dict, List

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from backend.config import LOG_FILE


def _deep_logging_ips_list() -> List[str]:
    """IPs the blue team marked for verbose logging (see agents/blue/responder.py)."""
    try:
        from backend.main import SYSTEM_STATE
        dl = SYSTEM_STATE.get("deep_logging_ips")
        if dl is None:
            return []
        if isinstance(dl, list):
            return dl
        return list(dl) if isinstance(dl, (set, tuple)) else []
    except ImportError:
        return []


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        # Sliding window for rate limiting: {ip: {endpoint: deque of timestamps}}
        self._request_counts: Dict[str, Dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque())
        )

    async def dispatch(self, request: Request, call_next):
        # Only intercept requests to /target/*
        if not request.url.path.startswith("/target"):
            return await call_next(request)

        # Intentional vulnerability (CWE-346): trust X-Forwarded-For from client.
        # This lets the red team bypass IP blocks via header_injection.
        # The blue team can detect the spoofed header pattern and alert on it.
        xff = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        real_ip = request.client.host if request.client else "unknown"
        client_ip = xff if xff else real_ip
        path = request.url.path
        user_agent = request.headers.get("user-agent", "")
        start_time = time.time()
        deep_ips = _deep_logging_ips_list()
        is_deep = client_ip in deep_ips

        # ── IP blocking check ─────────────────────────────────────────────────
        # Reads blocked_ips from the shared SYSTEM_STATE singleton.
        # STATE_LOCK is not needed for reads — only writes require it.
        try:
            from backend.main import SYSTEM_STATE
            if client_ip in SYSTEM_STATE.get("blocked_ips", []):
                self._log_request(
                    ip=client_ip,
                    method=request.method,
                    path=path,
                    status_code=403,
                    response_time_ms=0.0,
                    query_params=dict(request.query_params),
                    blocked=True,
                    deep_logging=is_deep,
                    user_agent=user_agent,
                    payload={},
                    x_forwarded_for=xff,
                    real_ip=real_ip,
                )
                return Response("Forbidden", status_code=403)
        except ImportError:
            pass  # SYSTEM_STATE not available during early startup

        # ── Rate limiting check ───────────────────────────────────────────────
        # Sliding window per (client_ip, endpoint). Limit is req/min.
        try:
            from backend.main import SYSTEM_STATE
            rate_limits = SYSTEM_STATE.get("rate_limited_endpoints", {})

            # Match on the endpoint segment after /target (e.g. /target/login → /login)
            endpoint = "/" + path.split("/target/", 1)[-1].split("/")[0] if "/target/" in path else path

            if endpoint in rate_limits:
                limit = rate_limits[endpoint]
                window = self._request_counts[client_ip][endpoint]
                now = time.time()
                # Evict entries older than 60 seconds
                while window and now - window[0] > 60:
                    window.popleft()
                if len(window) >= limit:
                    self._log_request(
                        ip=client_ip,
                        method=request.method,
                        path=path,
                        status_code=429,
                        response_time_ms=0.0,
                        query_params=dict(request.query_params),
                        rate_limited=True,
                        deep_logging=is_deep,
                        user_agent=user_agent,
                        payload={},
                        x_forwarded_for=xff,
                        real_ip=real_ip,
                    )
                    return Response(
                        "Too Many Requests",
                        status_code=429,
                        headers={"Retry-After": "60"},
                    )
                window.append(now)
        except ImportError:
            pass  # SYSTEM_STATE not available during early startup

        # ── Capture request body before passing to route handler ─────────────
        body_hash = ""
        payload_dict: dict = {}
        body_bytes = b""
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_hash = hashlib.sha256(body_bytes).hexdigest()
                # Always parse JSON body so anomaly rules can inspect field values
                # (SQLi/traversal patterns live in POST bodies, not query params)
                parsed = json.loads(body_bytes)
                if isinstance(parsed, dict):
                    payload_dict = parsed
        except Exception:
            pass

        # Pass through to route handler
        response = await call_next(request)
        elapsed_ms = (time.time() - start_time) * 1000

        self._log_request(
            ip=client_ip,
            method=request.method,
            path=path,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            query_params=dict(request.query_params),
            payload=payload_dict,
            body_hash=body_hash,
            deep_logging=is_deep,
            user_agent=user_agent,
            x_forwarded_for=xff,
            real_ip=real_ip,
        )

        return response

    def _log_request(
        self,
        ip: str,
        method: str,
        path: str,
        status_code: int,
        response_time_ms: float,
        query_params: dict,
        blocked: bool = False,
        rate_limited: bool = False,
        payload: dict | None = None,
        body_hash: str = "",
        deep_logging: bool = False,
        user_agent: str = "",
        x_forwarded_for: str = "",
        real_ip: str = "",
    ) -> None:
        """
        Appends one JSON line to LOG_FILE.

        `payload` is the parsed JSON request body (always present for POST/PUT/PATCH).
        Anomaly rules read entry["payload"] to detect SQLi/traversal in POST bodies.
        user_agent is always logged — required by behavioral fingerprinting.
        """
        entry = {
            "timestamp":             time.time(),
            "ip":                    ip,
            "method":                method,
            "path":                  path,
            "status_code":           status_code,
            "response_time_ms":      round(response_time_ms, 2),
            "query_params":          query_params,
            "payload":               payload or {},
            "blocked_by_middleware": blocked,
            "rate_limited":          rate_limited,
            "body_hash":             body_hash,
            "user_agent":            user_agent,
            "x_forwarded_for":       x_forwarded_for,
            "real_ip":               real_ip,
        }
        if deep_logging:
            entry["deep_logging"] = True
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            print(f"[WARN] Could not write to {LOG_FILE}: {e}")
