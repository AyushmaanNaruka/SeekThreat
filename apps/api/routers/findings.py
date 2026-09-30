"""Enriched finding endpoints.

Provides HTTP access to enriched vulnerability findings:
- GET /findings/{finding_id} : Retrieve a single enriched finding by ID.
- GET /findings              : Query paginated enriched findings by engagement ID.
- POST /findings/enrich      : Synchronously enrich a single finding.
- POST /findings/enrich/batch: Batch enrich findings synchronously or asynchronously via Celery.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.db.repositories import EnrichedFindingRepository
from apps.api.db.session import get_db
from packages.schema.models.finding import EnrichedFinding, Finding
from services.enrichment.service import EnrichmentService

logger = logging.getLogger(__name__)

router = APIRouter()

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


class EnrichedFindingListResponse(BaseModel):
    """Paginated collection of enriched findings."""

    items: list[EnrichedFinding]
    total: int
    limit: int
    offset: int


class BatchEnrichRequest(BaseModel):
    """Payload for batch enrichment."""

    findings: list[Finding]
    engagement_id: str | None = None
    async_dispatch: bool = False


class BatchEnrichResponse(BaseModel):
    """Result of batch enrichment dispatch or execution."""

    status: str
    count: int
    finding_ids: list[str] = Field(default_factory=list)
    items: list[EnrichedFinding] = Field(default_factory=list)


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
    """Return a paginated list of enriched findings for a specified engagement."""
    repo = EnrichedFindingRepository(db)
    total = repo.count_by_engagement(engagement_id)
    items = repo.get_by_engagement(engagement_id, limit=limit, offset=offset)
    return EnrichedFindingListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{finding_id}",
    response_model=EnrichedFinding,
    summary="Get an enriched finding by its primary key finding_id",
)
def get_enriched_finding(
    finding_id: str,
    db: Session = Depends(get_db),
) -> EnrichedFinding:
    """Retrieve a single enriched finding record."""
    repo = EnrichedFindingRepository(db)
    finding = repo.get(finding_id)
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
    """Enrich a single finding through multi-source intelligence fusion and ERS."""
    repo = EnrichedFindingRepository(db)
    service = EnrichmentService(repository=repo)
    enriched = service.enrich_finding(finding, persist=persist)
    if persist:
        db.commit()
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
    if not request.findings:
        return BatchEnrichResponse(status="empty", count=0)

    if request.async_dispatch:
        from apps.api.tasks.enrichment import enrich_findings

        findings_data = [f.model_dump(mode="json") for f in request.findings]
        try:
            enrich_findings.delay(
                findings_data=findings_data,
                engagement_id=request.engagement_id,
            )
        except Exception as exc:
            logger.error("Failed to dispatch async enrichment task: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Celery broker unavailable: {exc}",
            ) from exc

        return BatchEnrichResponse(
            status="dispatched",
            count=len(request.findings),
            finding_ids=[f.finding_id for f in request.findings],
        )

    repo = EnrichedFindingRepository(db)
    service = EnrichmentService(repository=repo)
    results = service.enrich_batch(request.findings, persist=True)
    db.commit()

    return BatchEnrichResponse(
        status="completed",
        count=len(results),
        finding_ids=[ef.finding.finding_id for ef in results],
        items=results,
    )
