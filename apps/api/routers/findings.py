"""Enriched finding endpoints.

Provides HTTP access to enriched vulnerability findings:
- GET /findings/{finding_id} : Retrieve one enriched finding within an engagement.
- GET /findings              : Query paginated enriched findings by engagement ID.
- POST /findings/enrich      : Synchronously enrich a single finding.
- POST /findings/enrich/batch: Batch enrich findings synchronously or asynchronously via Celery.

Every endpoint is scoped to an existing engagement and writes an audit event
carrying the actor (the engagement's named authorizer), the target, and the
engagement ID as the authorization reference -- CLAUDE.md requires every scan
and query to be logged. Enrichment requests are additionally gated on
provenance: each finding must belong to the request's engagement and cite only
observations recorded under that engagement.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
)
from apps.api.db.session import get_db
from packages.schema.models.engagement import Engagement
from packages.schema.models.finding import EnrichedFinding, Finding
from services.enrichment.service import EnrichmentService

logger = logging.getLogger(__name__)

router = APIRouter()

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
MAX_BATCH_SIZE = 1000

AUDIT_SCANNER = "enrichment_pipeline"


class EnrichedFindingListResponse(BaseModel):
    """Paginated collection of enriched findings."""

    items: list[EnrichedFinding]
    total: int
    limit: int
    offset: int


class BatchEnrichRequest(BaseModel):
    """Payload for batch enrichment."""

    findings: list[Finding] = Field(..., max_length=MAX_BATCH_SIZE)
    engagement_id: str = Field(..., description="Engagement every finding must belong to")
    async_dispatch: bool = False


class BatchEnrichResponse(BaseModel):
    """Result of batch enrichment dispatch or execution."""

    status: str
    count: int
    finding_ids: list[str] = Field(default_factory=list)
    items: list[EnrichedFinding] = Field(default_factory=list)


def _build_service(repo: EnrichedFindingRepository) -> EnrichmentService:
    """Construct the enrichment service with the configured feed-mirror cache."""
    return EnrichmentService(repository=repo, cache_dir=settings.enrichment_cache_dir)


def _require_engagement(
    db: Session,
    engagement_id: str,
    *,
    event: str,
    target: str,
) -> Engagement:
    """Return the engagement, or audit the rejection and raise 404 as scans.py does."""
    engagement = EngagementRepository(db).get(engagement_id)
    if engagement is None:
        log_audit_event(
            event=event,
            actor="unknown",
            target=target,
            engagement_id=engagement_id,
            scanner=AUDIT_SCANNER,
            status="not_found",
            details={"reason": f"Engagement {engagement_id!r} not found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {engagement_id!r} not found",
        )
    return engagement


def _reject(
    engagement: Engagement,
    target: str,
    reason: str,
    details: dict[str, Any],
) -> HTTPException:
    """Audit an enrichment rejection and build the 422 to raise."""
    log_audit_event(
        event="enrichment.rejected",
        actor=engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status="rejected",
        details={"reason": reason, **details},
    )
    return HTTPException(status_code=422, detail=reason)  # Unprocessable Content


def _verify_findings_provenance(
    db: Session,
    engagement: Engagement,
    findings: Sequence[Finding],
    target: str,
) -> None:
    """Every finding must belong to the engagement and cite only its observations."""
    foreign = [f.finding_id for f in findings if f.engagement_id != engagement.engagement_id]
    if foreign:
        raise _reject(
            engagement,
            target,
            f"Findings {foreign} do not belong to engagement {engagement.engagement_id!r}",
            {"finding_ids": foreign},
        )

    cited = {obs_id for f in findings for obs_id in f.observation_ids}
    known = ObservationRepository(db).existing_ids(engagement.engagement_id, cited)
    missing = sorted(cited - known)
    if missing:
        raise _reject(
            engagement,
            target,
            (
                f"Observations {missing} are not recorded under engagement "
                f"{engagement.engagement_id!r}; findings must trace to observed scan facts"
            ),
            {"observation_ids": missing},
        )


def _audit_query(engagement: Engagement, target: str, details: dict[str, Any]) -> None:
    log_audit_event(
        event="findings.queried",
        actor=engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details=details,
    )


@router.get(
    "",
    response_model=EnrichedFindingListResponse,
    summary="List enriched findings for an engagement with pagination",
)
def list_enriched_findings(
    engagement_id: str = Query(..., description="Filter by engagement ID"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> EnrichedFindingListResponse:
    """Return a page of enriched findings for an engagement, ordered by finding_id."""
    engagement = _require_engagement(
        db, engagement_id, event="findings.query_rejected", target="enriched_findings"
    )
    repo = EnrichedFindingRepository(db)
    total = repo.count_by_engagement(engagement_id)
    items = repo.get_by_engagement(engagement_id, limit=limit, offset=offset)
    _audit_query(
        engagement,
        "enriched_findings",
        {"limit": limit, "offset": offset, "returned": len(items), "total": total},
    )
    return EnrichedFindingListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{finding_id}",
    response_model=EnrichedFinding,
    summary="Get an enriched finding by engagement and finding_id",
)
def get_enriched_finding(
    finding_id: str,
    engagement_id: str = Query(..., description="Engagement the finding belongs to"),
    db: Session = Depends(get_db),
) -> EnrichedFinding:
    """Retrieve a single enriched finding record within an engagement."""
    engagement = _require_engagement(
        db, engagement_id, event="findings.query_rejected", target=finding_id
    )
    finding = EnrichedFindingRepository(db).get(finding_id, engagement_id=engagement_id)
    _audit_query(engagement, finding_id, {"found": finding is not None})
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Enriched finding not found: {finding_id}",
        )
    return finding


@router.post(
    "/enrich",
    response_model=EnrichedFinding,
    summary="Synchronously enrich a single finding and persist the result",
)
def enrich_single_finding(
    finding: Finding,
    persist: bool = Query(True, description="Whether to persist the result"),
    db: Session = Depends(get_db),
) -> EnrichedFinding:
    """Enrich a single finding through multi-source intelligence fusion and ERS.

    The finding's own engagement_id is the request engagement.
    """
    target = finding.finding_id
    engagement = _require_engagement(
        db, finding.engagement_id, event="enrichment.rejected", target=target
    )
    _verify_findings_provenance(db, engagement, [finding], target)

    service = _build_service(EnrichedFindingRepository(db))
    enriched = service.enrich_finding(finding, persist=persist)
    if persist:
        db.commit()

    log_audit_event(
        event="enrichment.complete",
        actor=engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details={"finding_ids": [finding.finding_id], "persisted": persist},
    )
    return enriched


@router.post(
    "/enrich/batch",
    response_model=BatchEnrichResponse,
    summary="Enrich a batch of findings synchronously or dispatch to Celery",
)
def enrich_batch_findings(
    request: BatchEnrichRequest,
    db: Session = Depends(get_db),
) -> BatchEnrichResponse:
    """Batch enrich findings, optionally dispatching to Celery worker."""
    target = f"{len(request.findings)} findings"
    engagement = _require_engagement(
        db, request.engagement_id, event="enrichment.rejected", target=target
    )
    if not request.findings:
        return BatchEnrichResponse(status="empty", count=0)

    _verify_findings_provenance(db, engagement, request.findings, target)
    actor = engagement.authorization.authorized_by
    finding_ids = [f.finding_id for f in request.findings]

    if request.async_dispatch:
        from apps.api.tasks.enrichment import enrich_findings

        findings_data = [f.model_dump(mode="json") for f in request.findings]
        try:
            enrich_findings.delay(
                findings_data=findings_data,
                engagement_id=engagement.engagement_id,
                actor=actor,
            )
        except Exception as exc:
            # The full error goes to the log and audit trail, never to the
            # client: broker exceptions can carry connection URLs and hostnames.
            logger.error(
                "Celery broker unavailable; enrichment for engagement %s not dispatched: %s",
                engagement.engagement_id,
                exc,
            )
            log_audit_event(
                event="enrichment.dispatch_failed",
                actor=actor,
                target=target,
                engagement_id=engagement.engagement_id,
                scanner=AUDIT_SCANNER,
                status="error",
                details={"finding_ids": finding_ids, "error": f"Dispatch failed: {exc}"},
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Enrichment queue unavailable; the findings were not dispatched.",
            ) from exc

        log_audit_event(
            event="enrichment.dispatched",
            actor=actor,
            target=target,
            engagement_id=engagement.engagement_id,
            scanner=AUDIT_SCANNER,
            status="accepted",
            details={"finding_ids": finding_ids},
        )
        return BatchEnrichResponse(
            status="dispatched",
            count=len(request.findings),
            finding_ids=finding_ids,
        )

    service = _build_service(EnrichedFindingRepository(db))
    results = service.enrich_batch(request.findings, persist=True)
    db.commit()

    enriched_ids = [ef.finding.finding_id for ef in results]
    log_audit_event(
        event="enrichment.complete",
        actor=actor,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details={"finding_ids": enriched_ids},
    )
    return BatchEnrichResponse(
        status="completed",
        count=len(results),
        finding_ids=enriched_ids,
        items=results,
    )
