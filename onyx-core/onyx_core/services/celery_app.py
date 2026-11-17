"""
ONYX CTI — Celery Application
Distributed task queue for crawlers, NLP processing, analysis, and enrichment.
Uses Redis as broker and result backend.
"""

from __future__ import annotations

import os

from celery import Celery

def _redis_url() -> str:
    """Broker URL from the environment. No credential is embedded in the code."""
    pw = os.getenv("REDIS_PASSWORD", "")
    host = os.getenv("REDIS_HOST", "redis")
    return f"redis://:{pw}@{host}:6379/1" if pw else f"redis://{host}:6379/1"


# Create Celery app
celery = Celery(
    "onyx",
    broker=os.getenv("CELERY_BROKER_URL", _redis_url()),
    backend=os.getenv("CELERY_RESULT_BACKEND", _redis_url()),
)

# Configuration
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="default",
    task_queues={
        "default": {"routing_key": "default"},
        "crawlers": {"routing_key": "crawlers"},
        "nlp": {"routing_key": "nlp"},
        "analysis": {"routing_key": "analysis"},
    },
    task_routes={
        "onyx.crawlers.*": {"queue": "crawlers"},
        "onyx.nlp.*": {"queue": "nlp"},
        "onyx.api.*": {"queue": "default"},
        "onyx_analyzers.*": {"queue": "analysis"},
    },
    beat_schedule={
        "clearweb-pastebin-monitor": {
            "task": "onyx.crawlers.pastebin_scan",
            "schedule": 300.0,  # Every 5 minutes
        },
        "clearweb-github-monitor": {
            "task": "onyx.crawlers.github_scan",
            "schedule": 600.0,  # Every 10 minutes
        },
        "dashboard-stats-refresh": {
            "task": "onyx.api.refresh_dashboard_cache",
            "schedule": 30.0,  # Every 30 seconds
        },
        "siem-export": {
            "task": "onyx.api.export_indicators",
            "schedule": 900.0,  # Every 15 minutes; no-op until ONYX_EXPORT_* destinations are set
        },
        "ioc-expiration-check": {
            "task": "onyx.api.expire_stale_iocs",
            "schedule": 3600.0,  # Every hour
        },
    },
)

# Auto-discover tasks from all ONYX packages
celery.autodiscover_tasks(["onyx_api"], related_name="tasks")
