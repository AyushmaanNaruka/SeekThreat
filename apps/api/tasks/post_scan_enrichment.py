"""Celery task: post-scan targeted feed sync & re-enrichment pipeline.

Dispatched automatically off the request path upon scan completion by
``apps/api/tasks/scans.run_scan``, after the scan's ``scan.completed`` audit
event. The task is fire-and-forget from the scan's perspective: it never feeds
back into the scan result and a failure here must never mark a scan as failed.

Pipeline (Task 6 – D-036):
1. Extract unique CVE IDs from ``ObservationKind.VULN_CANDIDATE``
   observations that were produced by the scan (looked up by artifact_id).
2. For each per-CVE source (CVE.org, Vulnrichment, EUVD, NVD) separately,
   identify the CVE IDs that source's mirror lacks. A record in one mirror says
   nothing about the others. IDs the source recently reported as not found
   (``<name>.notfound.json``) are not missing.
3. Cap the distinct IDs sent upstream at ``settings.post_scan_max_cves``; the
   rest are logged as deferred and retried by the daily beat sync, which reads
   CVE IDs from VULN_CANDIDATE observations as well as ``enriched_findings``.
4. ``FeedSyncer.sync_missing_cve_records`` syncs each source for only its own
   gaps, under a time budget inside the task's soft time limit.
5. Re-enrich the persisted findings of *this scan's engagement* whose
   ``cve_ids`` intersect the CVE IDs that actually got new records, and persist
   them via idempotent upsert. Nothing new fetched means nothing re-enriched.

Error isolation:
- Network timeouts / upstream rate limits during post-scan sync do NOT fail
  the scan.  All exceptions are caught, logged, and turned into audit events.
- The task is not retried on network failure: a stale per-CVE mirror is
  corrected by the next daily Celery beat job (``seekthreat.sync_feeds.run``).
  This avoids repeated costly upstream calls for every scan that detects the
  same CVE during an outage window.
- A scan that produces no VULN_CANDIDATE observations exits immediately with
  no network I/O.
- Celery's soft time limit is never swallowed by the per-step error handling;
  it is audited by the task wrapper.

Authorization scoping (CLAUDE.md, D-031/D-032):
- Re-enrichment reads and writes only rows with the scan's ``engagement_id``.
- Every run writes one audit event with actor = the scan authorization's
  ``authorized_by`` (``system:post_scan_enrichment`` when none was passed),
  target = engagement/scan, the CVE IDs sent upstream and per-source results.

Design decisions:
- ``artifact_id`` is passed rather than a full observation list so the Celery
  JSON transport carries only a small string across the broker.
- The task runs on the ``enrichment`` queue (same as ``sync_feeds.run``),
  consumed by the dedicated ``enrichment-worker`` compose service
  (concurrency 1), so slow upstream lookups never occupy the scan worker.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
from apps.api.db.models import EnrichedFindingModel
from apps.api.db.repositories import (
    EnrichedFindingRepository,
    ObservationRepository,
)
from apps.api.db.session import SessionLocal
from apps.api.worker import celery_app
from packages.schema.models.finding import Finding
from packages.schema.models.observation import ObservationKind
from services.enrichment.service import EnrichmentService
from services.enrichment.sources.sync import (
    SOURCE_NAMES,
    TARGETED_SOURCES,
    FeedSyncer,
    SyncReport,
    missing_cve_ids_by_source,
    normalize_cve_ids,
)

logger = logging.getLogger(__name__)

TASK_NAME = "seekthreat.enrichment.sync_new_findings_cves"
SYSTEM_ACTOR = "system:post_scan_enrichment"
AUDIT_SCANNER = "post_scan_enrichment"
#: Hard time limit headroom over the soft limit, for the wrapper to audit and exit.
HARD_LIMIT_MARGIN_SECONDS = 120
#: Part of the soft limit kept back from the targeted sync for re-enrichment.
REENRICH_RESERVE_SECONDS = 300
#: Stored findings are scanned this many rows at a time (keyset-paged by finding_id).
REENRICH_CHUNK_SIZE = 500

__all__ = [
    "SOURCE_NAMES",
    "SYSTEM_ACTOR",
    "TARGETED_SOURCES",
    "run_post_scan_enrichment",
    "sync_new_findings_cves",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cve_ids_from_artifact(session: Any, artifact_id: str) -> list[str]:
    """Return all CVE IDs from VULN_CANDIDATE observations for ``artifact_id``.

    Observations store CVE IDs in ``attributes["cve_ids"]`` as a
    comma-separated string (e.g. ``"CVE-2021-44228,CVE-2024-3400"``).
    Empty or absent values are silently skipped.
    """
    obs_repo = ObservationRepository(session)
    observations = obs_repo.get_by_artifact(
        artifact_id=artifact_id, kind=ObservationKind.VULN_CANDIDATE
    )
    raw_cves: list[str] = []
    for obs in observations:
        raw = obs.attributes.get("cve_ids", "")
        if isinstance(raw, str) and raw.strip():
            raw_cves.extend(c.strip() for c in raw.split(",") if c.strip())
    return normalize_cve_ids(raw_cves)


def _missing_cve_ids(cve_ids: list[str], cache_dir: Path) -> dict[str, list[str]]:
    """Per targeted source, the subset of ``cve_ids`` that source's mirror lacks.

    Computed per source: being in the CVE.org mirror does not mean NVD,
    Vulnrichment or EUVD were ever asked. A missing or unreadable mirror makes
    every ID missing for that source; a recent not-found entry makes it not
    missing (see ``services.enrichment.sources.sync.missing_cve_ids_by_source``).
    """
    return missing_cve_ids_by_source(cache_dir, cve_ids)


def _findings_for_cves(
    session: Any,
    engagement_id: str,
    cve_ids: set[str],
    *,
    chunk_size: int = REENRICH_CHUNK_SIZE,
) -> Iterator[list[Finding]]:
    """Yield, in chunks, the engagement's stored Findings whose ``cve_ids`` intersect.

    Scoped to ``engagement_id`` (D-031): another engagement's rows are never read,
    so they can never be rewritten. Rows are keyset-paged by ``finding_id`` and only
    the ``finding_id``/``finding_data`` columns are loaded, so memory stays bounded
    by ``chunk_size`` regardless of how many findings the engagement holds. CVE
    matching is done in Python to stay portable across PostgreSQL and SQLite.
    """
    wanted = {c.upper() for c in cve_ids}
    last_id: str | None = None
    while True:
        stmt = (
            select(EnrichedFindingModel.finding_id, EnrichedFindingModel.finding_data)
            .where(EnrichedFindingModel.engagement_id == engagement_id)
            .order_by(EnrichedFindingModel.finding_id.asc())
            .limit(chunk_size)
        )
        if last_id is not None:
            stmt = stmt.where(EnrichedFindingModel.finding_id > last_id)
        rows = session.execute(stmt).all()
        if not rows:
            return
        last_id = rows[-1][0]
        matches: list[Finding] = []
        for _finding_id, finding_data in rows:
            if not isinstance(finding_data, dict):
                continue
            stored_cves = finding_data.get("cve_ids")
            if not isinstance(stored_cves, list):
                continue
            if wanted.intersection(c.upper() for c in stored_cves if isinstance(c, str)):
                try:
                    matches.append(Finding.model_validate(finding_data))
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "post_scan_enrichment: could not deserialize finding %s: %s",
                        finding_data.get("finding_id", "<unknown>"),
                        exc,
                    )
        if matches:
            yield matches
        if len(rows) < chunk_size:
            return


def _cap(
    missing: dict[str, list[str]], limit: int, scan_id: str
) -> tuple[dict[str, list[str]], list[str], int]:
    """Limit the distinct CVE IDs sent upstream to ``limit`` (lowest IDs first)."""
    union = sorted({cve for ids in missing.values() for cve in ids})
    sent = union[:limit]
    deferred = len(union) - len(sent)
    if deferred:
        logger.warning(
            "post_scan_enrichment: scan %s has %d CVEs missing from local mirrors; per-run "
            "cap is %d, so %d are deferred to the daily beat sync",
            scan_id,
            len(union),
            limit,
            deferred,
        )
    keep = set(sent)
    capped = {name: [cve for cve in ids if cve in keep] for name, ids in missing.items()}
    return capped, sent, deferred


# ---------------------------------------------------------------------------
# Core pipeline logic (testable without Celery)
# ---------------------------------------------------------------------------


def _reenrich_findings(
    *,
    cve_ids: set[str],
    engagement_id: str,
    cache_dir: Path,
    summary: dict[str, Any],
) -> None:
    """Re-enrich and persist this engagement's findings whose CVE IDs intersect ``cve_ids``."""
    try:
        with SessionLocal() as session:
            repo = EnrichedFindingRepository(session)
            service = EnrichmentService(repository=repo, cache_dir=cache_dir)
            total = 0
            for chunk in _findings_for_cves(
                session, engagement_id, cve_ids, chunk_size=REENRICH_CHUNK_SIZE
            ):
                total += len(service.enrich_batch(chunk, persist=True))
            session.commit()
            summary["findings_reenriched"] = total
            logger.info(
                "post_scan_enrichment: re-enriched %d findings for engagement %s",
                total,
                engagement_id,
            )
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "post_scan_enrichment: re-enrichment failed for engagement %s: %s",
            engagement_id,
            exc,
        )
        summary["ok"] = False
        summary["error"] = f"re-enrichment: {type(exc).__name__}: {exc}"


def run_post_scan_enrichment(
    artifact_id: str,
    engagement_id: str,
    scan_id: str,
    *,
    cache_dir: Path | None = None,
    nvd_api_key: str | None = None,
) -> dict[str, Any]:
    """Execute the post-scan enrichment pipeline and return a summary dict.

    This function contains the full business logic and is deliberately kept
    separate from the Celery task wrapper so it can be tested without a
    running Celery broker.

    Args:
        artifact_id: The ``RawArtifact.artifact_id`` produced by the scan.
        engagement_id: The scan's engagement. Re-enrichment is scoped to it.
        scan_id: The scan record ID (for audit context only).
        cache_dir: Local mirror directory. Defaults to
            ``settings.enrichment_cache_dir``.
        nvd_api_key: Optional NVD API key for rate-limit relief. Defaults to
            ``settings.nvd_api_key``.

    Returns:
        Summary dict: ``cves_found``, ``cves_missing`` (distinct IDs missing from
        at least one source), ``missing_by_source``, ``cves_sent_upstream``,
        ``cves_deferred`` (over the per-run cap), ``cves_synced`` (records
        written), ``cves_with_new_data``, ``sources`` (per-source results),
        ``failed_sources``, ``findings_reenriched`` and ``ok`` (bool).

    Raises:
        SoftTimeLimitExceeded: never swallowed here; the task wrapper audits it.
    """
    effective_cache_dir: Path = cache_dir or settings.enrichment_cache_dir
    effective_nvd_key: str | None = nvd_api_key or settings.nvd_api_key

    summary: dict[str, Any] = {
        "artifact_id": artifact_id,
        "scan_id": scan_id,
        "cves_found": 0,
        "cves_missing": 0,
        "missing_by_source": {},
        "cves_sent_upstream": [],
        "cves_deferred": 0,
        "cves_synced": 0,
        "cves_with_new_data": [],
        "sources": {},
        "failed_sources": [],
        "findings_reenriched": 0,
        "ok": True,
    }

    # ------------------------------------------------------ 1. Extract CVE IDs
    cve_ids: list[str] = []
    try:
        with SessionLocal() as session:
            cve_ids = _cve_ids_from_artifact(session, artifact_id)
    except SQLAlchemyError as exc:
        logger.error(
            "post_scan_enrichment: DB error reading observations for artifact %s: %s",
            artifact_id,
            exc,
        )
        summary["ok"] = False
        summary["error"] = f"{type(exc).__name__}: {exc}"
        return summary

    summary["cves_found"] = len(cve_ids)

    if not cve_ids:
        logger.info(
            "post_scan_enrichment: scan %s produced no VULN_CANDIDATE CVEs — nothing to sync",
            scan_id,
        )
        return summary

    # ------------------------------------------- 2. Identify gaps, per source
    missing = _missing_cve_ids(cve_ids, effective_cache_dir)
    missing_union = sorted({cve for ids in missing.values() for cve in ids})
    summary["cves_missing"] = len(missing_union)

    if not missing_union:
        # Every source already has (or recently reported not having) every CVE, so
        # this run fetches nothing new and there is nothing to re-enrich.
        logger.info(
            "post_scan_enrichment: all %d CVEs from scan %s already in every local mirror",
            len(cve_ids),
            scan_id,
        )
        return summary

    # ------------------------------------------------------ 3. Per-run cap
    missing, sent, deferred = _cap(missing, settings.post_scan_max_cves, scan_id)
    summary["missing_by_source"] = missing
    summary["cves_sent_upstream"] = sent
    summary["cves_deferred"] = deferred

    # ------------------------------------------------------- 4. Targeted sync
    logger.info(
        "post_scan_enrichment: syncing %d CVEs for scan %s: %s%s",
        len(sent),
        scan_id,
        sent[:10],
        " ..." if len(sent) > 10 else "",
    )
    new_data: set[str] = set()
    try:
        syncer = FeedSyncer(
            cache_dir=effective_cache_dir,
            nvd_api_key=effective_nvd_key,
            time_budget_seconds=max(
                60.0, float(settings.post_scan_soft_time_limit_seconds - REENRICH_RESERVE_SECONDS)
            ),
        )
        sync_results = syncer.sync_missing_cve_records(missing)
        report = SyncReport(results=list(sync_results))
        summary["sources"] = report.to_summary()["sources"]
        summary["cves_synced"] = sum(r.records_synced for r in sync_results)
        for r in sync_results:
            new_data.update(r.cve_ids_synced)
        summary["failed_sources"] = [r.key for r in report.failed]
        if report.failed:
            logger.warning(
                "post_scan_enrichment: sync partially failed for sources %s (scan %s)",
                summary["failed_sources"],
                scan_id,
            )
            summary["ok"] = False
        else:
            logger.info(
                "post_scan_enrichment: synced %d records for %d CVEs (scan %s)",
                summary["cves_synced"],
                len(sent),
                scan_id,
            )
    except SoftTimeLimitExceeded:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "post_scan_enrichment: targeted sync raised unexpectedly for scan %s: %s",
            scan_id,
            exc,
        )
        summary["ok"] = False
        summary["error"] = f"{type(exc).__name__}: {exc}"
    summary["cves_with_new_data"] = sorted(new_data)

    # -------------------------------------------------- 5. Re-enrich findings
    if not new_data:
        logger.info(
            "post_scan_enrichment: no new records for scan %s; nothing to re-enrich", scan_id
        )
        return summary
    _reenrich_findings(
        cve_ids=new_data,
        engagement_id=engagement_id,
        cache_dir=effective_cache_dir,
        summary=summary,
    )
    return summary


# ---------------------------------------------------------------------------
# Celery task entry point
# ---------------------------------------------------------------------------


@celery_app.task(  # type: ignore[untyped-decorator]
    name=TASK_NAME,
    bind=True,
    max_retries=0,  # fire-and-forget; daily beat corrects stale mirrors
    queue="enrichment",
    ignore_result=True,
    soft_time_limit=settings.post_scan_soft_time_limit_seconds,
    time_limit=settings.post_scan_soft_time_limit_seconds + HARD_LIMIT_MARGIN_SECONDS,
)
def sync_new_findings_cves(
    self: Any,
    artifact_id: str,
    engagement_id: str,
    scan_id: str,
    actor: str | None = None,
) -> None:
    """Post-scan targeted feed sync & re-enrichment (fire-and-forget).

    Dispatched automatically upon scan completion.  Failures are audited
    but never propagate back to the scan result.

    Args:
        artifact_id: The ``RawArtifact.artifact_id`` produced by the scan.
        engagement_id: The scan's engagement (authorization reference).
        scan_id: The scan record ID (for audit context).
        actor: The scan authorization's ``authorized_by``; audited as the actor.
            Falls back to ``system:post_scan_enrichment``.
    """
    audit_actor = actor.strip() if isinstance(actor, str) and actor.strip() else SYSTEM_ACTOR
    target = f"engagement:{engagement_id}/scan:{scan_id}"
    logger.info(
        "post_scan_enrichment: task started for scan %s / artifact %s (actor=%s)",
        scan_id,
        artifact_id,
        audit_actor,
    )

    try:
        summary = run_post_scan_enrichment(
            artifact_id=artifact_id,
            engagement_id=engagement_id,
            scan_id=scan_id,
        )
    except Exception as exc:  # noqa: BLE001  — must never bubble up (incl. soft time limit)
        logger.error(
            "post_scan_enrichment: unhandled error for scan %s: %s",
            scan_id,
            exc,
            exc_info=True,
        )
        log_audit_event(
            event="post_scan_enrichment.error",
            actor=audit_actor,
            target=target,
            engagement_id=engagement_id,
            scanner=AUDIT_SCANNER,
            status="error",
            details={
                "scan_id": scan_id,
                "artifact_id": artifact_id,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        return

    event = "post_scan_enrichment.completed" if summary["ok"] else "post_scan_enrichment.partial"
    log_audit_event(
        event=event,
        actor=audit_actor,
        target=target,
        engagement_id=engagement_id,
        scanner=AUDIT_SCANNER,
        status="success" if summary["ok"] else "partial",
        details=summary,
    )
    logger.info(
        "post_scan_enrichment: done for scan %s — %s",
        scan_id,
        summary,
    )
