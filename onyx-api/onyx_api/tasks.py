"""
ONYX CTI - Celery tasks.

The Celery application (onyx_core.services.celery_app) declared a beat schedule that pointed at
callables which did not exist (`onyx_api.tasks.*`, and `scan` methods that are not tasks). This
module registers those tasks with explicit names, so the schedule resolves and workers have
something to execute. Each task is a thin wrapper over code that already exists in the repository:

    onyx.crawlers.pastebin_scan     -> PastebinMonitor.scan
    onyx.crawlers.github_scan       -> GitHubMonitor.scan
    onyx.api.refresh_dashboard_cache-> invalidate the dashboard cache keys in Redis
    onyx.api.expire_stale_iocs      -> workers.ioc_persister.recalculate_decay_all

Heavy imports happen inside the task body so that importing this module stays cheap.
"""
from __future__ import annotations

import asyncio
from typing import Any

from onyx_core.services.celery_app import celery

_monitors: dict[str, Any] = {}   # keep monitors alive between runs: they hold the dedup cache


def _run(coro):
    """Run a coroutine to completion from a (synchronous) Celery worker process."""
    return asyncio.run(coro)


def _monitor(key: str, factory):
    if key not in _monitors:
        _monitors[key] = factory()
    return _monitors[key]


@celery.task(name="onyx.crawlers.pastebin_scan", queue="crawlers")
def pastebin_scan() -> dict[str, Any]:
    from onyx_crawlers.clearweb.pastebin_monitor import PastebinMonitor

    mon = _monitor("pastebin", PastebinMonitor)
    matches = _run(mon.scan())
    return {"matched": len(matches)}


@celery.task(name="onyx.crawlers.github_scan", queue="crawlers")
def github_scan() -> dict[str, Any]:
    from onyx_crawlers.clearweb.github_monitor import GitHubMonitor

    mon = _monitor("github", GitHubMonitor)
    leaks = _run(mon.scan())
    return {"leaks": len(leaks)}


@celery.task(name="onyx.api.refresh_dashboard_cache", queue="default")
def refresh_dashboard_cache() -> dict[str, Any]:
    from onyx_core.services.redis import RedisService

    async def _go() -> None:
        redis = RedisService()
        await redis.cache_delete("dashboard:stats")

    _run(_go())
    return {"status": "ok"}


@celery.task(name="onyx.api.expire_stale_iocs", queue="default")
def expire_stale_iocs() -> dict[str, Any]:
    """Recompute decay and composite confidence for every indicator (VALID -> ... -> OBSOLETE)."""
    from onyx_api.workers.ioc_persister import recalculate_decay_all

    return _run(recalculate_decay_all())


@celery.task(name="onyx.api.export_indicators", queue="default")
def export_indicators() -> dict[str, Any]:
    """Push active indicators (VALID, DEGRADING) to the SIEM/TIP destinations set in the environment."""
    import os

    from onyx_connectors.dispatch import configured_destinations, dispatch
    from onyx_core.services.mongodb import MongoDBService

    if not configured_destinations(os.environ):
        return {"status": "skipped", "reason": "no export destination configured"}

    async def _load() -> list[dict[str, Any]]:
        mongo = MongoDBService()
        await mongo.initialize()
        cursor = mongo.collection("indicators").find({"decay_state": {"$in": ["VALID", "DEGRADING"]}}, {"_id": 0}).limit(5000)
        return [d async for d in cursor]

    return dispatch(_run(_load()), os.environ)
