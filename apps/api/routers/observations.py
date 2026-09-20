"""Observation read endpoints.

The write path has existed since Layer 1 shipped -- every completed scan
writes rows into the `observations` table -- but nothing returned them over
HTTP. GET /scans/{id} only ever reported an integer count. These endpoints
close that gap.

Both endpoints are paginated: a /24 nmap scan can produce thousands of rows,
and this project does not do unbounded list endpoints (see the identical
concern already handled by GET /engagements and GET /scans, which currently
have none -- this module does not repeat that gap).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.db.repositories import ObservationRepository
from apps.api.db.session import get_db
from packages.schema.models.observation import Observation, ObservationKind

router = APIRouter()

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


class ObservationProvenanceResponse(BaseModel):
    source: str
    confidence: str
    retrieved_at: datetime
    note: str | None = None


class ObservationResponse(BaseModel):
    observation_id: str
    engagement_id: str
    scanner: str
    kind: str
    subject: str
    attributes: dict[str, str]
    artifact_id: str
    observed_at: datetime
    provenance: ObservationProvenanceResponse

    @classmethod
    def from_schema(cls, observation: Observation) -> ObservationResponse:
        prov = observation.provenance
        return cls(
            observation_id=observation.observation_id,
            engagement_id=observation.engagement_id,
            scanner=observation.scanner,
            kind=observation.kind.value,
            subject=observation.subject,
            attributes=dict(observation.attributes),
            artifact_id=observation.artifact_id,
            observed_at=observation.observed_at,
            provenance=ObservationProvenanceResponse(
                source=prov.source.value,
                confidence=prov.confidence.value,
                retrieved_at=prov.retrieved_at,
                note=prov.note,
            ),
        )


class ObservationListResponse(BaseModel):
    items: list[ObservationResponse]
    total: int
    limit: int
    offset: int


@router.get(
    "",
    response_model=ObservationListResponse,
    summary="List observations for an engagement, optionally filtered by kind",
)
def list_observations(
    engagement_id: str = Query(..., description="Filter by engagement ID"),
    kind: ObservationKind | None = Query(None, description="Filter by observation kind"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> ObservationListResponse:
    """Return a page of observations for an engagement.

    An unknown engagement_id returns an empty page (total=0), not a 404 --
    it is a filter value, not a resource lookup, matching GET /scans.
    """
    repo = ObservationRepository(db)
    total = repo.count_by_engagement(engagement_id, kind=kind)
    items = repo.get_by_engagement(engagement_id, kind=kind, limit=limit, offset=offset)
    return ObservationListResponse(
        items=[ObservationResponse.from_schema(o) for o in items],
        total=total,
        limit=limit,
        offset=offset,
    )
