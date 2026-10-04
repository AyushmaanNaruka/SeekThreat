"""Celery task: periodic intelligence feed synchronization.

Scheduled via Celery beat to run daily (or on demand). Downloads CVE.org,
CISA KEV, and FIRST EPSS v4 into ENRICHMENT_CACHE_DIR using FeedSyncer.

Network is ONLY allowed in this task — never on the enrichment request path.

Usage (manual trigger):
    from apps.api.tasks.sync_feeds import sync_feeds
    sync_feeds.delay()

Beat schedule is configured in apps/api/worker.py.
"""

from __future__ import annotations

import logging
from typing import Any

from celery.exceptions import MaxRetriesExceededError

from apps.api.core.config import settings
from apps.api.worker import celery_app
from services.enrichment.sources.sync import FeedSyncer

logger = logging.getLogger(__name__)


@celery_app.task(  # type: ignore[untyped-decorator]
    name="seekthreat.sync_feeds.run",
    bind=True,
    max_retries=2,
    default_retry_delay=300,  # 5 minutes between retries
    queue="enrichment",
)
def sync_feeds(self: Any) -> dict[str, Any]:
    """Download all intelligence feed mirrors. Scheduled daily by Celery beat.

    Returns a summary dict with one entry per source:
      {"kev": {"success": True, "records": 1234}, ...}

    Never raises — all errors are logged and returned in the summary.
    """
    logger.info("feed_sync: starting scheduled intelligence mirror sync")

    syncer = FeedSyncer(cache_dir=settings.enrichment_cache_dir)

    try:
        results = syncer.sync_all()
    except Exception as exc:
        logger.error("feed_sync: unexpected error in sync_all: %s", exc)
        try:
            raise self.retry(exc=exc)
        except MaxRetriesExceededError:
            logger.error("feed_sync: max retries exhausted — mirrors may be stale")
            return {"error": str(exc)}

    summary: dict[str, Any] = {}
    for result in results:
        key = result.source.value
        if result.success:
            logger.info(
                "feed_sync: ✓ %s — %d records → %s",
                key,
                result.records_synced,
                result.target_path,
            )
            summary[key] = {"success": True, "records": result.records_synced}
        else:
            logger.error("feed_sync: ✗ %s — %s", key, result.error)
            summary[key] = {"success": False, "error": result.error}

    return summary
