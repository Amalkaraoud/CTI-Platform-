"""
ONYX CTI - request rate limiting (standard library only).

Implements the "controle du debit des requetes" of the security model: a sliding-window limiter,
keyed by client, with a stricter budget for authentication endpoints (brute-force and enumeration
protection). The state is in-process; behind several API replicas, put the same budget on the
reverse proxy as well (documented in the README).
"""
from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Budget:
    limit: int
    window_s: float

    @classmethod
    def parse(cls, text: str, default: "Budget") -> "Budget":
        """'120/60' -> 120 requests per 60 seconds. Invalid text falls back to the default."""
        try:
            n, w = text.split("/")
            b = cls(int(n), float(w))
            return b if b.limit > 0 and b.window_s > 0 else default
        except (ValueError, AttributeError):
            return default


class SlidingWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic, max_keys: int = 50_000) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._max_keys = max_keys

    def check(self, key: str, budget: Budget) -> tuple[bool, float]:
        """Record one request. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        q = self._hits.setdefault(key, deque())
        cutoff = now - budget.window_s
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= budget.limit:
            return False, max(0.0, q[0] + budget.window_s - now)
        q.append(now)
        if len(self._hits) > self._max_keys:          # bound memory under key-flooding
            self._evict(now, budget.window_s)
        return True, 0.0

    def _evict(self, now: float, window_s: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - window_s]:
            del self._hits[k]


DEFAULT_BUDGET = Budget(1200, 60.0)   # generous: the dashboard proxy shares one client address
DEFAULT_AUTH_BUDGET = Budget(10, 60.0)
AUTH_PATH_PREFIXES = ("/api/v1/auth/login", "/api/v1/auth/refresh")


def budgets_from_env(env: dict[str, str] | None = None) -> tuple[Budget, Budget]:
    """ONYX_RATE_LIMIT and ONYX_AUTH_RATE_LIMIT, as 'requests/seconds'."""
    e = os.environ if env is None else env
    return (Budget.parse(e.get("ONYX_RATE_LIMIT", ""), DEFAULT_BUDGET),
            Budget.parse(e.get("ONYX_AUTH_RATE_LIMIT", ""), DEFAULT_AUTH_BUDGET))
