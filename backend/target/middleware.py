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

        # ── TODO (Dev B, Phase 4): IP blocking check ──────────────────────────
        # from backend.main import SYSTEM_STATE, STATE_LOCK
        # if client_ip in SYSTEM_STATE["blocked_ips"]:
        #     self._log_request(client_ip, request.method, path, 403, 0.0,
        #                       dict(request.query_params), blocked=True)
        #     return Response("Forbidden", status_code=403)

        # ── TODO (Dev B, Phase 4): Rate limiting check ─────────────────────────
        # from backend.main import SYSTEM_STATE
        # if path in SYSTEM_STATE["rate_limited_endpoints"]:
        #     limit = SYSTEM_STATE["rate_limited_endpoints"][path]
        #     window = self._request_counts[client_ip][path]
        #     now = time.time()
        #     while window and now - window[0] > 60:
        #         window.popleft()
        #     if len(window) >= limit:
        #         self._log_request(client_ip, request.method, path, 429, 0.0,
        #                           dict(request.query_params), rate_limited=True)
        #         return Response("Too Many Requests", status_code=429,
        #                         headers={"Retry-After": "60"})
        #     window.append(now)

        # Pass through to route handler
        response = await call_next(request)
        elapsed_ms = (time.time() - start_time) * 1000

        # ── TODO (Dev B, Phase 1): Implement _log_request fully ───────────────
        self._log_request(
            ip=client_ip,
            method=request.method,
            path=path,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            query_params=dict(request.query_params),
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
    ) -> None:
        """
        Appends one JSON line to LOG_FILE.

        Log entry schema (must match exactly — blue team reads this format):
        {
          "timestamp":           float,
          "ip":                  str,
          "method":              str,
          "path":                str,
          "status_code":         int,
          "response_time_ms":    float,
          "query_params":        dict,
          "blocked_by_middleware": bool,
          "rate_limited":        bool
        }

        TODO (Dev B): Also capture and hash request body:
          body = await request.body()
          body_hash = hashlib.sha256(body).hexdigest() if body else ""
        Note: body capture requires reading before call_next() and
        reconstructing the request — see starlette docs for pattern.
        """
        entry = {
            "timestamp":            time.time(),
            "ip":                   ip,
            "method":               method,
            "path":                 path,
            "status_code":          status_code,
            "response_time_ms":     round(response_time_ms, 2),
            "query_params":         query_params,
            "blocked_by_middleware": blocked,
            "rate_limited":         rate_limited,
        }
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            print(f"[WARN] Could not write to {LOG_FILE}: {e}")
