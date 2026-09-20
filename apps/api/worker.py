"""Celery application instance for SeekThreat async task processing.

This module defines the single Celery app used by the API to dispatch
scan jobs and by the worker process to execute them.

Usage:
    # Start the worker (from project root):
    celery -A apps.api.worker.celery_app worker --loglevel=info --queues=scans

    # In the API, import and use:
    from apps.api.tasks.scans import execute_scan
    execute_scan.delay(...)
"""

from __future__ import annotations

from celery import Celery

from apps.api.core.config import settings

celery_app = Celery(
    "seekthreat",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    # Use JSON serializer — safe, human-readable, avoids pickle security risk
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # UTC timestamps throughout
    enable_utc=True,
    timezone="UTC",
    # Route scan jobs to a dedicated queue so other task types don't block
    task_routes={
        "seekthreat.scans.execute": {"queue": "scans"},
    },
    # Retry policy defaults (overridden per-task where needed)
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# Explicit import, not autodiscover_tasks(): Celery's autodiscovery treats each
# entry as a package and imports "<entry>.tasks", so autodiscover_tasks(["apps.api"])
# would be needed to find apps.api.tasks — passing the tasks package itself here
# silently looked for the nonexistent apps.api.tasks.tasks and registered nothing,
# so execute_scan.delay() queued jobs no worker ever picked up.
from apps.api.tasks import scans as _scans_tasks  # noqa: E402, F401
