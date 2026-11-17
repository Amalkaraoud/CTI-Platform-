"""
ONYX CTI - ASGI middleware: rate limiting and request auditing.

Pure ASGI (no framework import), so it can be unit-tested without FastAPI. Wired in main.py.
"""
from __future__ import annotations

import json
from typing import Any

from onyx_core.audit import audit
from onyx_core.ratelimit import AUTH_PATH_PREFIXES, SlidingWindowLimiter, budgets_from_env

_AUDITED_PREFIXES = ("/api/v1/auth", "/api/v1/internal", "/_internal", "/taxii2")
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def _client_ip(scope: dict[str, Any]) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"


class RateLimitAuditMiddleware:
    def __init__(self, app, limiter: SlidingWindowLimiter | None = None, env: dict[str, str] | None = None) -> None:
        self.app = app
        self.limiter = limiter or SlidingWindowLimiter()
        self.general, self.auth = budgets_from_env(env)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path, method, ip = scope.get("path", ""), scope.get("method", "GET"), _client_ip(scope)
        is_auth = path.startswith(AUTH_PATH_PREFIXES)
        allowed, retry = self.limiter.check(
            f"{'auth' if is_auth else 'api'}:{ip}", self.auth if is_auth else self.general)
        if not allowed:
            audit("rate_limit", "throttled", resource=path, client_ip=ip, details={"method": method})
            body = json.dumps({"detail": "Too many requests"}).encode()
            await send({"type": "http.response.start", "status": 429, "headers": [
                (b"content-type", b"application/json"), (b"retry-after", str(int(retry) + 1).encode())]})
            await send({"type": "http.response.body", "body": body})
            return

        status = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            if path.startswith(_AUDITED_PREFIXES) or method in _MUTATING:
                code = status["code"]
                outcome = "success" if code < 400 else ("denied" if code in (401, 403) else "failure")
                audit(f"{method} {path}", outcome, resource=path, client_ip=ip, details={"status": code})
