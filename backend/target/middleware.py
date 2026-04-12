"""
middleware.py — Security middleware: request logger + IP blocker + rate limiter.

TODO (Dev B, Phase 1): Implement logging first.
TODO (Dev B, Phase 4): Add IP blocking and rate limiting enforcement.

Runs on every request to the target router.
Reads blocked_ips and rate_limited_endpoints from SYSTEM_STATE singleton.
Appends one JSON line per request to data/logs.jsonl.
"""

import hashlib
import json
import time
from collections import defaultdict, deque
from typing import Dict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from backend.config import LOG_FILE, STEP_DELAY_S


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

        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        start_time = time.time()

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
                    )
                    return Response(
                        "Too Many Requests",
                        status_code=429,
                        headers={"Retry-After": "60"},
                    )
                window.append(now)
        except ImportError:
            pass  # SYSTEM_STATE not available during early startup

        # ── Capture request body hash before passing to route handler ─────────
        # request.body() caches to request._body in modern Starlette so the
        # route handler can still read the body after this call.
        body_hash = ""
        try:
            body_bytes = await request.body()
            if body_bytes:
                body_hash = hashlib.sha256(body_bytes).hexdigest()
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
            body_hash=body_hash,
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
        body_hash: str = "",
    ) -> None:
        """
        Appends one JSON line to LOG_FILE.

        Log entry schema (blue team reads this exact format):
        {
          "timestamp":             float,
          "ip":                    str,
          "method":                str,
          "path":                  str,
          "status_code":           int,
          "response_time_ms":      float,
          "query_params":          dict,
          "blocked_by_middleware": bool,
          "rate_limited":          bool,
          "body_hash":             str   (sha256 hex of request body, "" if empty)
        }
        """
        entry = {
            "timestamp":             time.time(),
            "ip":                    ip,
            "method":                method,
            "path":                  path,
            "status_code":           status_code,
            "response_time_ms":      round(response_time_ms, 2),
            "query_params":          query_params,
            "blocked_by_middleware": blocked,
            "rate_limited":          rate_limited,
            "body_hash":             body_hash,
        }
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            print(f"[WARN] Could not write to {LOG_FILE}: {e}")