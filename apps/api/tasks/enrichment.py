"""Celery task: asynchronous batch vulnerability enrichment.

This module provides the Celery worker task for executing multi-source
intelligence fusion, Exposure Risk Score (ERS) evaluation, and persistent
idempotent database storage outside of the HTTP request-response cycle.

Design principles:
- Findings are received as JSON-safe dictionaries and reconstructed via
  ``Finding.model_validate()``.
- The task manages its own isolated SQLAlchemy session via ``SessionLocal()``.
- Idempotent upsert guarantees repeat runs never produce duplicate records.
- Transient errors are retried up to ``max_retries`` (3) times with exponential
  back-off: ``countdown = 30 * 2**retries`` seconds (30s, 60s, 120s).
- Permanent validation errors fail immediately without retry.
- Every terminal outcome -- success, payload validation failure, permanent
  error, retries exhausted -- writes an audit event carrying the requesting
  actor and engagement (the authorization reference).
"""

from __future__ import annotations

import logging
from typing import Any

from celery.exceptions import MaxRetriesExceededError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
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

DEFAULT_ACTOR = "celery_worker"
RETRY_BASE_DELAY_SECONDS = 30
UNSPECIFIED_ENGAGEMENT = "unspecified"


def _audit_failure(
    *,
    actor: str,
    engagement_id: str | None,
    count: int,
    reason: str,
    exc: BaseException,
    retries: int | None = None,
) -> None:
    details: dict[str, Any] = {"reason": reason, "error_type": type(exc).__name__}
    if retries is not None:
        details["retries"] = retries
    log_audit_event(
        event="enrichment.failed",
        actor=actor,
        target=f"{count} findings",
        engagement_id=engagement_id or UNSPECIFIED_ENGAGEMENT,
        scanner="enrichment_pipeline",
        status="failed",
        details=details,
    )


def _current_retries(task: Any) -> int:
    try:
        return int(task.request.retries or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


def run_enrichment(
    findings_data: list[dict[str, Any]],
    engagement_id: str | None = None,
    task: Any = None,
    actor: str | None = None,
) -> list[str]:
    """Execute batch enrichment and persist results within an isolated DB session.

    Args:
        findings_data: List of raw finding dictionaries.
        engagement_id: Parent engagement ID; the authorization reference for audit.
        task: Optional Celery task instance for retry dispatch.
        actor: Who requested the enrichment (the API passes the engagement's
            named authorizer). Defaults to ``"celery_worker"``.

    Returns:
        List of enriched finding IDs.
    """
    if not findings_data:
        return []

    effective_actor = actor or DEFAULT_ACTOR

    # 1. Reconstruct validated domain models
    try:
        findings = [Finding.model_validate(f) for f in findings_data]
    except ValidationError as exc:
        logger.error("Failed to validate finding payloads for enrichment: %s", exc)
        _audit_failure(
            actor=effective_actor,
            engagement_id=engagement_id,
            count=len(findings_data),
            reason="payload_validation",
            exc=exc,
        )
        raise

    db: Session = SessionLocal()
    try:
        repo = EnrichedFindingRepository(db)
        service = EnrichmentService(repository=repo, cache_dir=settings.enrichment_cache_dir)

        enriched_list = service.enrich_batch(findings, persist=True)
        db.commit()

        finding_ids = [ef.finding.finding_id for ef in enriched_list]

        log_audit_event(
            event="enrichment.complete",
            actor=effective_actor,
            target=f"{len(finding_ids)} findings",
            engagement_id=engagement_id or UNSPECIFIED_ENGAGEMENT,
            scanner="enrichment_pipeline",
            status="success",
            details={"finding_ids": finding_ids},
        )

        logger.info(
            "Successfully enriched and persisted %d findings (engagement_id=%s)",
            len(finding_ids),
            engagement_id or UNSPECIFIED_ENGAGEMENT,
        )
        return finding_ids

    except Exception as exc:
        db.rollback()
        is_celery = task is not None and hasattr(task, "retry") and callable(task.retry)
        if is_celery and not isinstance(exc, PERMANENT_ERRORS):
            retries = _current_retries(task)
            max_retries = getattr(task, "max_retries", None)
            if max_retries is None or retries < int(max_retries):
                countdown = RETRY_BASE_DELAY_SECONDS * 2**retries
                logger.warning(
                    "Transient error during enrichment (attempt %d); retrying in %ds: %s",
                    retries + 1,
                    countdown,
                    exc,
                )
                try:
                    retry_signal = task.retry(exc=exc, countdown=countdown)
                except BaseException as retry_exc:
                    # task.retry() normally raises celery's Retry signal. When
                    # Celery itself decides retries are exhausted it instead
                    # re-raises ``exc`` or raises MaxRetriesExceededError --
                    # a terminal failure that must still be audited.
                    if retry_exc is exc or isinstance(retry_exc, MaxRetriesExceededError):
                        _audit_failure(
                            actor=effective_actor,
                            engagement_id=engagement_id,
                            count=len(findings_data),
                            reason="retries_exhausted",
                            exc=exc,
                            retries=retries,
                        )
                    raise
                raise retry_signal from exc

            logger.error("Enrichment failed after %d retries: %s", retries, exc)
            _audit_failure(
                actor=effective_actor,
                engagement_id=engagement_id,
                count=len(findings_data),
                reason="retries_exhausted",
                exc=exc,
                retries=retries,
            )
            raise

        logger.error("Permanent failure during enrichment execution: %s", exc)
        _audit_failure(
            actor=effective_actor,
            engagement_id=engagement_id,
            count=len(findings_data),
            reason="permanent_error",
            exc=exc,
        )
        raise
    finally:
        db.close()


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    name="seekthreat.enrichment.enrich",
    max_retries=3,
    default_retry_delay=RETRY_BASE_DELAY_SECONDS,
)
def enrich_findings(
    self: Any,
    findings_data: list[dict[str, Any]],
    engagement_id: str | None = None,
    actor: str | None = None,
) -> list[str]:
    """Celery task entry point for async batch enrichment.

    Args:
        findings_data: Serialized list of Finding models.
        engagement_id: Parent engagement ID for audit logging.
        actor: Requesting actor recorded in the audit trail.

    Returns:
        List of enriched finding IDs.
    """
    return run_enrichment(
        findings_data=findings_data,
        engagement_id=engagement_id,
        task=self,
        actor=actor,
    )
