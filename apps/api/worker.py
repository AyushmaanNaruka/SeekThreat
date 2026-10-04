"""Celery application instance for SeekThreat async task processing.

This module defines the single Celery app used by the API to dispatch
scan and enrichment jobs and by the worker process to execute them.

Usage:
    # Start the worker (from project root):
    celery -A apps.api.worker.celery_app worker --loglevel=info --queues=scans,enrichment

    # In the API, import and use:
    from apps.api.tasks.scans import execute_scan
    execute_scan.delay(...)
"""

from __future__ import annotations

from celery import Celery

from apps.api.core.config import settings
from services.scanners.nuclei_adapter import MAX_TIMEOUT_SECONDS

# Headroom over the longest scan a caller may request, for broker latency, retry
# back-off and result persistence after the scanner exits.
VISIBILITY_TIMEOUT_MARGIN_SECONDS = 3600

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
    # Route scan and enrichment jobs to dedicated queues
    task_routes={
        "seekthreat.scans.execute": {"queue": "scans"},
        "seekthreat.enrichment.enrich": {"queue": "enrichment"},
    },
    # Retry policy defaults (overridden per-task where needed)
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # With acks_late a scan's message stays unacknowledged until the task finishes,
    # and Redis redelivers any message unacked after visibility_timeout (default 1h)
    # to another worker. That must outlast the longest permitted scan, or a long
    # scan is started a second time while the first is still running.
    broker_transport_options={
        "visibility_timeout": MAX_TIMEOUT_SECONDS + VISIBILITY_TIMEOUT_MARGIN_SECONDS,
    },
)

# Explicit import, not autodiscover_tasks(): Celery's autodiscovery treats each
# entry as a package and imports "<entry>.tasks", so autodiscover_tasks(["apps.api"])
# would be needed to find apps.api.tasks — passing the tasks package itself here
# silently looked for the nonexistent apps.api.tasks.tasks and registered nothing,
# so execute_scan.delay() queued jobs no worker ever picked up.
from apps.api.tasks import enrichment as _enrichment_tasks  # noqa: E402, F401
from apps.api.tasks import scans as _scans_tasks  # noqa: E402, F401
