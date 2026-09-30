"""Celery task: asynchronous batch vulnerability enrichment.

This module provides the Celery worker task for executing multi-source
intelligence fusion, Exposure Risk Score (ERS) evaluation, and persistent
idempotent database storage outside of the HTTP request-response cycle.

Design principles:
- Findings are received as JSON-safe dictionaries and reconstructed via
  ``Finding.model_validate()``.
- The task manages its own isolated SQLAlchemy session via ``SessionLocal()``.
- Idempotent upsert guarantees repeat runs never produce duplicate records.
- Transient database errors are retried up to 3 times with exponential/linear back-off.
- Permanent validation errors fail immediately without retry.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import EnrichedFindingRepository
from apps.api.db.session import SessionLocal
from apps.api.worker import celery_app
from packages.schema.models.finding import Finding
from services.enrichment.service import EnrichmentService

logger = logging.getLogger(__name__)

PERMANENT_ERRORS = (
    ValueError,
    TypeError,
    ValidationError,
)


def run_enrichment(
    findings_data: list[dict[str, Any]],
    engagement_id: str | None = None,
    task: Any = None,
) -> list[str]:
    """Execute batch enrichment and persist results within an isolated DB session.

    Args:
        findings_data: List of raw finding dictionaries.
        engagement_id: Optional parent engagement ID for audit tracking.
        task: Optional Celery task instance for retry dispatch.

    Returns:
        List of enriched finding IDs.
    """
    if not findings_data:
        return []

    # 1. Reconstruct validated domain models
    try:
        findings = [Finding.model_validate(f) for f in findings_data]
    except Exception as exc:
        logger.error("Failed to validate finding payloads for enrichment: %s", exc)
        raise

    db: Session = SessionLocal()
    try:
        repo = EnrichedFindingRepository(db)
        service = EnrichmentService(repository=repo)

        enriched_list = service.enrich_batch(findings, persist=True)
        db.commit()

        finding_ids = [ef.finding.finding_id for ef in enriched_list]

        if engagement_id:
            log_audit_event(
                event="enrichment.complete",
                actor="celery_worker",
                target=f"{len(finding_ids)} findings",
                engagement_id=engagement_id,
                scanner="enrichment_pipeline",
                status="success",
                details={"finding_ids": finding_ids},
            )

        logger.info(
            "Successfully enriched and persisted %d findings (engagement_id=%s)",
            len(finding_ids),
            engagement_id or "unspecified",
        )
        return finding_ids

    except Exception as exc:
        db.rollback()
        is_celery = task is not None and hasattr(task, "retry") and callable(task.retry)
        if is_celery and not isinstance(exc, PERMANENT_ERRORS):
            logger.warning(
                "Transient error during enrichment execution; scheduling retry: %s", exc
            )
            raise task.retry(exc=exc) from exc

        logger.error("Permanent failure during enrichment execution: %s", exc)
        if engagement_id:
            log_audit_event(
                event="enrichment.failed",
                actor="celery_worker",
                target=f"{len(findings_data)} findings",
                engagement_id=engagement_id,
                scanner="enrichment_pipeline",
                status="failed",
                details={"error": str(exc)},
            )
        raise
    finally:
        db.close()


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    name="seekthreat.enrichment.enrich",
    max_retries=3,
    default_retry_delay=30,
)
def enrich_findings(
    self: Any,
    findings_data: list[dict[str, Any]],
    engagement_id: str | None = None,
) -> list[str]:
    """Celery task entry point for async batch enrichment.

    Args:
        findings_data: Serialized list of Finding models.
        engagement_id: Optional parent engagement ID for audit logging.

    Returns:
        List of enriched finding IDs.
    """
    return run_enrichment(
        findings_data=findings_data,
        engagement_id=engagement_id,
        task=self,
    )
