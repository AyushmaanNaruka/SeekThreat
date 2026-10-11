"""Celery task: post-scan targeted feed sync & re-enrichment pipeline.

Dispatched automatically off the request path upon scan completion by
``apps/api/tasks/scans.execute_scan``.  The task is fire-and-forget from
the scan's perspective: it never feeds back into the scan result and a
failure here must never mark a scan as failed.

Pipeline (Task 6 – D-036):
1. Extract unique CVE IDs from ``ObservationKind.VULN_CANDIDATE``
   observations that were produced by the scan (looked up by artifact_id).
2. Identify which CVE IDs are missing from the local per-CVE record mirrors
   (CVE.org, Vulnrichment, EUVD, NVD).
3. Trigger ``FeedSyncer.sync_cve_records(missing_cves)`` for only the gaps.
4. Trigger batch re-enrichment of every ``Finding`` whose ``cve_ids``
   intersect the newly synced set, persisting updated ``EnrichedFinding``
   rows via idempotent upsert.

Error isolation:
- Network timeouts / upstream rate limits during post-scan sync do NOT fail
  the scan.  All exceptions are caught, logged, and turned into audit events.
- The task is not retried on network failure: a stale per-CVE mirror is
  corrected by the next daily Celery beat job (``seekthreat.sync_feeds.run``).
  This avoids repeated costly upstream calls for every scan that detects the
  same CVE during an outage window.
- A scan that produces no VULN_CANDIDATE observations exits immediately with
  no network I/O.

Design decisions:
- ``artifact_id`` is passed rather than a full observation list so the Celery
  JSON transport carries only a small string across the broker.
- Finding re-enrichment is limited to findings whose ``cve_ids`` intersect
  the *missing* set; findings already enriched from a prior sync are left
  untouched — their high-confidence data is still in the mirrors.
- The task runs on the ``enrichment`` queue (same as ``sync_feeds.run``)
  to share the dedicated worker pool and keep the default ``celery`` queue
  free for scan tasks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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
from packages.schema.models.provenance import Source
from services.enrichment.service import EnrichmentService
from services.enrichment.sources.sync import (
    MIRROR_FILENAMES,
    FeedSyncer,
    normalize_cve_ids,
)

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "system:post_scan_enrichment"
AUDIT_SCANNER = "post_scan_enrichment"
#: Per-CVE record sources that need targeted sync; full-catalog sources
#: (KEV, EPSS, ExploitDB, Metasploit) are updated only by the daily beat job.
TARGETED_SOURCES = ("cve_org", "vulnrichment", "euvd", "nvd")
#: Source enum values that correspond to per-CVE mirrors.
_PER_CVE_SOURCES: tuple[Source, ...] = (
    Source.CVE_ORG,
    Source.VULNRICHMENT,
    Source.EUVD,
    Source.NVD,
)


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


def _missing_cve_ids(cve_ids: list[str], cache_dir: Path) -> list[str]:
    """Return the subset of ``cve_ids`` absent from *all* per-CVE mirrors.

    A CVE ID is considered 'known' if it appears as a key in **any** of the
    four per-CVE mirror files.  If the mirror file does not exist, every ID
    is treated as missing for that source and becomes a sync candidate.
    """
    known: set[str] = set()
    for source in _PER_CVE_SOURCES:
        path = cache_dir / MIRROR_FILENAMES.get(source, f"{source.value}.json")
        if not path.exists():
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                known.update(k.upper() for k in data if not k.startswith("_"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "post_scan_enrichment: could not read mirror %s to check known CVEs: %s",
                path,
                exc,
            )
    return [cve for cve in cve_ids if cve not in known]


def _findings_for_cves(session: Any, cve_ids: set[str]) -> list[Finding]:
    """Return every persisted Finding whose ``cve_ids`` intersect ``cve_ids``.

    Findings are stored as JSON blobs in ``enriched_findings.finding_data``.
    We load all rows and filter in Python rather than relying on a JSON
    containment query, keeping this portable across PostgreSQL and SQLite.
    """
    stmt = select(EnrichedFindingModel)
    rows = session.scalars(stmt).all()
    matches: list[Finding] = []
    for row in rows:
        finding_data = row.finding_data
        if not isinstance(finding_data, dict):
            continue
        stored_cves = finding_data.get("cve_ids")
        if not isinstance(stored_cves, list):
            continue
        if cve_ids.intersection(c.upper() for c in stored_cves if isinstance(c, str)):
            try:
                matches.append(Finding.model_validate(finding_data))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "post_scan_enrichment: could not deserialize finding %s: %s",
                    finding_data.get("finding_id", "<unknown>"),
                    exc,
                )
    return matches


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
    """Re-enrich and persist findings whose CVE IDs intersect ``cve_ids``."""
    try:
        with SessionLocal() as session:
            findings = _findings_for_cves(session, cve_ids)
            if not findings:
                logger.debug(
                    "post_scan_enrichment: no persisted findings intersect CVE set %s",
                    sorted(cve_ids)[:5],
                )
                return

            repo = EnrichedFindingRepository(session)
            service = EnrichmentService(repository=repo, cache_dir=cache_dir)
            enriched_list = service.enrich_batch(findings, persist=True)
            session.commit()
            summary["findings_reenriched"] = len(enriched_list)
            logger.info(
                "post_scan_enrichment: re-enriched %d findings for engagement %s",
                len(enriched_list),
                engagement_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "post_scan_enrichment: re-enrichment failed for engagement %s: %s",
            engagement_id,
            exc,
        )
        summary["ok"] = False


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
        engagement_id: Parent engagement ID (for audit logging).
        scan_id: The scan record ID (for audit context only).
        cache_dir: Local mirror directory. Defaults to
            ``settings.enrichment_cache_dir``.
        nvd_api_key: Optional NVD API key for rate-limit relief. Defaults to
            ``settings.nvd_api_key``.

    Returns:
        Summary dict with keys ``cves_found``, ``cves_missing``,
        ``cves_synced``, ``findings_reenriched``, and ``ok`` (bool).
    """
    effective_cache_dir: Path = cache_dir or settings.enrichment_cache_dir
    effective_nvd_key: str | None = nvd_api_key or settings.nvd_api_key

    summary: dict[str, Any] = {
        "artifact_id": artifact_id,
        "scan_id": scan_id,
        "cves_found": 0,
        "cves_missing": 0,
        "cves_synced": 0,
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
        return summary

    summary["cves_found"] = len(cve_ids)

    if not cve_ids:
        logger.info(
            "post_scan_enrichment: scan %s produced no VULN_CANDIDATE CVEs — nothing to sync",
            scan_id,
        )
        return summary

    # ---------------------------------------------------- 2. Identify missing
    missing_cves = _missing_cve_ids(cve_ids, effective_cache_dir)
    summary["cves_missing"] = len(missing_cves)

    if not missing_cves:
        logger.info(
            "post_scan_enrichment: all %d CVEs from scan %s already in local mirrors",
            len(cve_ids),
            scan_id,
        )
        # Still re-enrich in case new findings were stored but not yet enriched.
        _reenrich_findings(
            cve_ids=set(cve_ids),
            engagement_id=engagement_id,
            cache_dir=effective_cache_dir,
            summary=summary,
        )
        return summary

    # ------------------------------------------------------- 3. Targeted sync
    logger.info(
        "post_scan_enrichment: syncing %d missing CVEs for scan %s: %s%s",
        len(missing_cves),
        scan_id,
        missing_cves[:10],
        " ..." if len(missing_cves) > 10 else "",
    )
    try:
        syncer = FeedSyncer(
            cache_dir=effective_cache_dir,
            nvd_api_key=effective_nvd_key,
        )
        sync_results = syncer.sync_cve_records(missing_cves)
        synced_count = sum(r.records_synced for r in sync_results)
        summary["cves_synced"] = synced_count
        failed_sources = [r.key for r in sync_results if not r.success]
        if failed_sources:
            logger.warning(
                "post_scan_enrichment: sync partially failed for sources %s (scan %s)",
                failed_sources,
                scan_id,
            )
            summary["ok"] = False
        else:
            logger.info(
                "post_scan_enrichment: synced %d records for %d CVEs (scan %s)",
                synced_count,
                len(missing_cves),
                scan_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "post_scan_enrichment: targeted sync raised unexpectedly for scan %s: %s",
            scan_id,
            exc,
        )
        summary["ok"] = False
        # Fall through — re-enrich using whatever mirror data existed before.

    # -------------------------------------------------- 4. Re-enrich findings
    _reenrich_findings(
        cve_ids=set(cve_ids),
        engagement_id=engagement_id,
        cache_dir=effective_cache_dir,
        summary=summary,
    )
    return summary


# ---------------------------------------------------------------------------
# Celery task entry point
# ---------------------------------------------------------------------------


@celery_app.task(  # type: ignore[untyped-decorator]
    name="seekthreat.enrichment.sync_new_findings_cves",
    bind=True,
    max_retries=0,  # fire-and-forget; daily beat corrects stale mirrors
    queue="enrichment",
    ignore_result=True,
)
def sync_new_findings_cves(
    self: Any,
    artifact_id: str,
    engagement_id: str,
    scan_id: str,
) -> None:
    """Post-scan targeted feed sync & re-enrichment (fire-and-forget).

    Dispatched automatically upon scan completion.  Failures are audited
    but never propagate back to the scan result.

    Args:
        artifact_id: The ``RawArtifact.artifact_id`` produced by the scan.
        engagement_id: Parent engagement ID (for audit logging).
        scan_id: The scan record ID (for audit context).
    """
    logger.info(
        "post_scan_enrichment: task started for scan %s / artifact %s",
        scan_id,
        artifact_id,
    )

    try:
        summary = run_post_scan_enrichment(
            artifact_id=artifact_id,
            engagement_id=engagement_id,
            scan_id=scan_id,
        )
    except Exception as exc:  # noqa: BLE001  — must never bubble up
        logger.error(
            "post_scan_enrichment: unhandled error for scan %s: %s",
            scan_id,
            exc,
            exc_info=True,
        )
        log_audit_event(
            event="post_scan_enrichment.error",
            actor=SYSTEM_ACTOR,
            target=artifact_id,
            engagement_id=engagement_id,
            scanner=AUDIT_SCANNER,
            status="error",
            details={"scan_id": scan_id, "error": f"{type(exc).__name__}: {exc}"},
        )
        return

    event = "post_scan_enrichment.completed" if summary["ok"] else "post_scan_enrichment.partial"
    log_audit_event(
        event=event,
        actor=SYSTEM_ACTOR,
        target=artifact_id,
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
