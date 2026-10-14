"""Celery task: periodic intelligence feed synchronization.

Scheduled daily at 02:00 UTC by Celery beat (``apps/api/worker.py``; the ``beat``
service in ``infra/docker-compose.yml``) and runnable on demand. One run syncs:

- full mirrors: CISA KEV, FIRST EPSS (bulk CSV), ExploitDB and Metasploit metadata;
- targeted per-CVE records from CVE.org, CISA Vulnrichment, ENISA EUVD and NVD for
  every CVE ID in ``enriched_findings`` and in ``VULN_CANDIDATE`` observations, plus
  any IDs passed in. Observations are included so CVEs a scan found but that no
  finding carries yet -- e.g. ones the post-scan task deferred over its per-run cap
  or failed to fetch -- are still retried. IDs an upstream recently reported as not
  found are skipped for a TTL (``FeedSyncer``'s ``<name>.notfound.json``).

Network is ONLY allowed in this task (and the equivalent CLI) — never on the
enrichment request path.

Every run writes one audit event (``feed_sync.completed`` / ``feed_sync.failed``)
with actor ``system:celery_beat``. A run in which any source failed is retried for
the failed sources only, and once retries are exhausted the task raises
``FeedSyncError`` so Celery records it as FAILED rather than as a success.

Usage (manual trigger):
    from apps.api.tasks.sync_feeds import sync_feeds
    sync_feeds.delay()
    sync_feeds.delay(cve_ids=["CVE-2021-44228"], sources=["cve_org", "nvd"])
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from celery.exceptions import MaxRetriesExceededError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
from apps.api.db.models import EnrichedFindingModel, ObservationModel
from apps.api.db.session import SessionLocal
from apps.api.worker import celery_app
from packages.schema.models.observation import ObservationKind
from services.enrichment.sources.sync import FeedSyncer, SyncReport, normalize_cve_ids

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system:celery_beat"
#: Feed sync is platform-wide, not engagement-scoped; audit records say so.
AUDIT_ENGAGEMENT = "n/a"
AUDIT_SCANNER = "feed_sync"


class FeedSyncError(RuntimeError):
    """At least one feed failed to sync; raised after the failure is audited."""


#: Rows read per round trip when collecting CVE IDs from the database.
_YIELD_PER = 1000


def _known_cve_ids(session: Session) -> list[str]:
    """Every CVE ID in an enriched finding or a VULN_CANDIDATE observation, sorted.

    Observations carry CVE IDs as a comma-separated ``attributes["cve_ids"]`` string.
    """
    ids: set[str] = set()
    findings = select(EnrichedFindingModel.finding_data).execution_options(yield_per=_YIELD_PER)
    for finding_data in session.execute(findings).scalars():
        cves = finding_data.get("cve_ids") if isinstance(finding_data, dict) else None
        if isinstance(cves, list):
            ids.update(c for c in cves if isinstance(c, str))
    observations = (
        select(ObservationModel.attributes)
        .where(ObservationModel.kind == ObservationKind.VULN_CANDIDATE.value)
        .execution_options(yield_per=_YIELD_PER)
    )
    for attributes in session.execute(observations).scalars():
        raw = attributes.get("cve_ids") if isinstance(attributes, dict) else None
        if isinstance(raw, str):
            ids.update(c.strip() for c in raw.split(",") if c.strip())
    return normalize_cve_ids(ids)


def _gather_cve_ids(explicit: Iterable[str] | None) -> tuple[list[str], str | None]:
    """Explicit IDs plus those known from the database; returns (ids, db_error)."""
    ids = set(explicit or ())
    db_error: str | None = None
    try:
        with SessionLocal() as session:
            ids.update(_known_cve_ids(session))
    except SQLAlchemyError as exc:
        db_error = f"{type(exc).__name__}: {exc}"
        logger.error("feed_sync: could not read CVE IDs from the database: %s", db_error)
    return normalize_cve_ids(ids), db_error


def audit_sync_report(report: SyncReport, actor: str, **extra: Any) -> dict[str, Any]:
    """Write the audit event for one sync run and return its details."""
    details = {**report.to_summary(), **extra}
    log_audit_event(
        event="feed_sync.completed" if report.ok else "feed_sync.failed",
        actor=actor,
        target=",".join(r.key for r in report.results) or "no feeds selected",
        engagement_id=AUDIT_ENGAGEMENT,
        scanner=AUDIT_SCANNER,
        status="success" if report.ok else "failed",
        details=details,
    )
    return details


@celery_app.task(  # type: ignore[untyped-decorator]
    name="seekthreat.sync_feeds.run",
    bind=True,
    max_retries=2,
    default_retry_delay=300,  # 5 minutes between retries
    queue="enrichment",
)
def sync_feeds(
    self: Any,
    cve_ids: list[str] | None = None,
    sources: list[str] | None = None,
    actor: str = SYSTEM_ACTOR,
) -> dict[str, Any]:
    """Sync intelligence feed mirrors and audit the outcome.

    Args:
        cve_ids: Extra CVE IDs for the targeted sources, on top of every CVE ID
            in ``enriched_findings`` and in VULN_CANDIDATE observations.
        sources: Restrict the run to these short source names (``kev``, ``epss``,
            ``exploitdb``, ``metasploit``, ``cve_org``, ``vulnrichment``, ``euvd``,
            ``nvd``). None syncs all of them. Retries pass only the failed ones.
        actor: Audit actor. Scheduled runs are ``system:celery_beat``.

    Returns:
        ``SyncReport.to_summary()`` plus run metadata, when every source succeeded.

    Raises:
        FeedSyncError: after auditing, when any source failed and retries are
            exhausted (``celery.exceptions.Retry`` while retries remain).
    """
    ids, db_error = _gather_cve_ids(cve_ids)
    logger.info(
        "feed_sync: starting (actor=%s, sources=%s, %d CVE IDs for targeted sync)",
        actor,
        sources or "all",
        len(ids),
    )

    syncer = FeedSyncer(cache_dir=settings.enrichment_cache_dir, nvd_api_key=settings.nvd_api_key)
    report = syncer.sync_all(cve_ids=ids, sources=sources)

    for result in report.results:
        if result.success:
            logger.info(
                "feed_sync: ok %s, %d records -> %s (%s)",
                result.key,
                result.records_synced,
                result.target_path,
                result.note or "full mirror",
            )
        else:
            logger.error("feed_sync: FAILED %s: %s", result.key, result.error)

    retries = int(getattr(getattr(self, "request", None), "retries", 0) or 0)
    details = audit_sync_report(
        report, actor, cve_ids_requested=len(ids), db_error=db_error, retries=retries
    )
    if report.ok:
        return details

    failed = [r.key for r in report.failed]
    error = FeedSyncError(f"feed sync failed for: {', '.join(failed)}")
    try:
        raise self.retry(exc=error, kwargs={"cve_ids": cve_ids, "sources": failed, "actor": actor})
    except MaxRetriesExceededError:
        logger.error("feed_sync: retries exhausted; mirrors for %s may be stale", failed)
        raise error from None
