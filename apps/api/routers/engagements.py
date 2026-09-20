"""Engagements and authorization management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import EngagementRepository
from apps.api.db.session import get_db
from packages.schema.models._time import require_aware
from packages.schema.models.engagement import Authorization, Engagement

router = APIRouter()


class CreateEngagementRequest(BaseModel):
    engagement_id: str = Field(..., description="Unique engagement identifier (e.g. eng-001)")
    name: str = Field(..., description="Human-readable assessment or project name")
    authorized_by: str = Field(..., description="Named authorizer (must not be blank)")
    allowlist: list[str] = Field(
        ..., min_length=1, description="IP, CIDR, or hostname allowlist entries"
    )
    granted_at: datetime = Field(..., description="Start of authorization window (UTC)")
    expires_at: datetime = Field(..., description="End of authorization window (UTC)")


class EngagementResponse(BaseModel):
    engagement_id: str
    name: str
    authorized_by: str
    allowlist: list[str]
    granted_at: datetime
    expires_at: datetime
    created_at: datetime

    @classmethod
    def from_schema(cls, engagement: Engagement) -> EngagementResponse:
        auth = engagement.authorization
        return cls(
            engagement_id=engagement.engagement_id,
            name=engagement.name,
            authorized_by=auth.authorized_by,
            allowlist=list(auth.allowlist),
            granted_at=auth.granted_at,
            expires_at=auth.expires_at,
            created_at=engagement.created_at,
        )


@router.post(
    "",
    response_model=EngagementResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an engagement and register target allowlist",
)
def create_engagement(
    payload: CreateEngagementRequest,
    db: Session = Depends(get_db),
) -> EngagementResponse:
    """Register a new authorized engagement scoping scan boundaries."""
    granted_at = require_aware(payload.granted_at)
    expires_at = require_aware(payload.expires_at)

    if expires_at <= granted_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must be strictly after granted_at",
        )

    # Validate against core schema domain models
    auth = Authorization(
        engagement_id=payload.engagement_id,
        authorized_by=payload.authorized_by,
        allowlist=tuple(payload.allowlist),
        granted_at=granted_at,
        expires_at=expires_at,
    )

    engagement = Engagement(
        engagement_id=payload.engagement_id,
        name=payload.name,
        authorization=auth,
        created_at=datetime.now(UTC),
    )

    repo = EngagementRepository(db)
    saved = repo.save(engagement)
    db.commit()

    log_audit_event(
        event="engagement.created",
        actor=payload.authorized_by,
        target=",".join(payload.allowlist),
        engagement_id=payload.engagement_id,
        scanner="none",
        status="success",
        details={"name": payload.name, "allowlist": payload.allowlist},
    )

    return EngagementResponse.from_schema(saved)


@router.get(
    "/{engagement_id}",
    response_model=EngagementResponse,
    summary="Get engagement metadata and authorization scope",
)
def get_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
) -> EngagementResponse:
    """Retrieve an engagement and its authorization parameters by ID."""
    repo = EngagementRepository(db)
    engagement = repo.get(engagement_id)
    if engagement is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {engagement_id!r} not found",
        )
    return EngagementResponse.from_schema(engagement)


@router.get(
    "",
    response_model=list[EngagementResponse],
    summary="List all registered engagements",
)
def list_engagements(
    db: Session = Depends(get_db),
) -> list[EngagementResponse]:
    """Return all engagements ordered newest first."""
    repo = EngagementRepository(db)
    return [EngagementResponse.from_schema(e) for e in repo.list_all()]
