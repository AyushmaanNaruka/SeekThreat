"""Scan dispatch and status monitoring endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.core.authorization import verify_scan_authorization
from apps.api.db.repositories import (
    EngagementRepository,
    ObservationRepository,
    ScanRepository,
)
from apps.api.db.session import get_db, get_session_factory
from apps.api.routers.observations import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    ObservationListResponse,
    ObservationResponse,
)
from apps.api.tasks.scans import execute_scan, run_scan
from packages.schema.models.observation import ObservationKind

logger = logging.getLogger(__name__)

router = APIRouter()


class CreateScanRequest(BaseModel):
    engagement_id: str = Field(..., description="Target engagement identifier")
    scanner: str = Field(default="nmap", description="Scanner identifier (e.g. nmap)")
    target: str = Field(..., description="IP address, CIDR, or hostname to scan")
    options: dict[str, Any] = Field(default_factory=dict, description="Scanner execution options")


class ScanStatusResponse(BaseModel):
    scan_id: str
    engagement_id: str
    scanner: str
    target: str
    status: str
    options: dict[str, Any]
    observation_count: int
    artifact_id: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None


@router.post(
    "",
    response_model=ScanStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Accept scan request, validate authorization, dispatch Celery job",
)
def create_scan(
    payload: CreateScanRequest,
    db: Session = Depends(get_db),
) -> ScanStatusResponse:
    """Validate authorization choke point and dispatch background scanner execution."""
    eng_repo = EngagementRepository(db)
    engagement = eng_repo.get(payload.engagement_id)

    if engagement is None:
        log_audit_event(
            event="scan.rejected",
            actor="unknown",
            target=payload.target,
            engagement_id=payload.engagement_id,
            scanner=payload.scanner,
            status="forbidden",
            details={"reason": f"Engagement {payload.engagement_id!r} not found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {payload.engagement_id!r} not found",
        )

    # 1. Strict API-layer authorization gate
    auth = verify_scan_authorization(
        engagement=engagement,
        target=payload.target,
        scanner=payload.scanner,
    )

    # 2. Register pending scan record
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    scan_repo = ScanRepository(db)
    scan = scan_repo.create(
        scan_id=scan_id,
        engagement_id=payload.engagement_id,
        scanner=payload.scanner,
        target=payload.target,
        options=payload.options,
    )
    db.commit()

    # 3. Dispatch Celery task — authorization serialized as JSON-safe dict.
    # The scan row is already committed, so an unguarded dispatch failure (a
    # broker outage, say) would leave it at 'pending' forever with nothing
    # scheduled to advance it, and hand the caller a 500.
    try:
        execute_scan.delay(
            scan_id,
            payload.engagement_id,
            payload.scanner,
            payload.target,
            payload.options,
            auth.model_dump(mode="json"),
        )
    except Exception as exc:
        logger.warning(
            "Celery queue unavailable (%s); executing scan %s in background worker thread.",
            exc,
            scan_id,
        )
        import threading

        session_factory = get_session_factory(db.get_bind())

        def _run_bg() -> None:
            thread_db = session_factory()
            try:
                run_scan(
                    scan_id=scan_id,
                    engagement_id=payload.engagement_id,
                    scanner=payload.scanner,
                    target=payload.target,
                    options=payload.options,
                    authorization_dict=auth.model_dump(mode="json"),
                    db=thread_db,
                )
            except Exception as thread_exc:
                logger.error("Background scan execution error for %s: %s", scan_id, thread_exc)
            finally:
                thread_db.close()

        t = threading.Thread(target=_run_bg, daemon=True)
        t.start()

    return ScanStatusResponse(
        scan_id=scan.scan_id,
        engagement_id=scan.engagement_id,
        scanner=scan.scanner,
        target=scan.target,
        status=scan.status,
        options=scan.options,
        observation_count=0,
        artifact_id=scan.artifact_id,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Check scan status and observation counts",
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanStatusResponse:
    """Retrieve scan execution status and produced observation counts."""
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id!r} not found",
        )

    obs_count = 0
    if scan.artifact_id:
        obs_repo = ObservationRepository(db)
        obs_count = len(obs_repo.get_by_artifact(scan.artifact_id))

    return ScanStatusResponse(
        scan_id=scan.scan_id,
        engagement_id=scan.engagement_id,
        scanner=scan.scanner,
        target=scan.target,
        status=scan.status,
        options=scan.options,
        observation_count=obs_count,
        artifact_id=scan.artifact_id,
        error_message=scan.error_message,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@router.get(
    "/{scan_id}/observations",
    response_model=ObservationListResponse,
    summary="List observations produced by a scan, optionally filtered by kind",
)
def get_scan_observations(
    scan_id: str,
    kind: ObservationKind | None = Query(None, description="Filter by observation kind"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> ObservationListResponse:
    """Return a page of observations produced by this scan's artifact.

    A scan with no artifact yet (still pending or running) returns an empty
    page rather than an error -- that is the normal state before completion,
    not a failure.
    """
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id!r} not found",
        )

    if not scan.artifact_id:
        return ObservationListResponse(items=[], total=0, limit=limit, offset=offset)

    obs_repo = ObservationRepository(db)
    total = obs_repo.count_by_artifact(scan.artifact_id, kind=kind)
    items = obs_repo.get_by_artifact(scan.artifact_id, kind=kind, limit=limit, offset=offset)
    return ObservationListResponse(
        items=[ObservationResponse.from_schema(o) for o in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "",
    response_model=list[ScanStatusResponse],
    summary="List scans for an engagement or all scans",
)
def list_scans(
    engagement_id: str | None = Query(None, description="Optional filter scans by engagement ID"),
    limit: int | None = Query(None, ge=1, le=500, description="Max number of scans to return"),
    db: Session = Depends(get_db),
) -> list[ScanStatusResponse]:
    """Return all scans recorded for an engagement or across all engagements."""
    scan_repo = ScanRepository(db)
    obs_repo = ObservationRepository(db)
    if engagement_id:
        scans = scan_repo.list_by_engagement(engagement_id)
    else:
        scans = scan_repo.list_all(limit=limit)

    results = []
    for s in scans:
        obs_count = len(obs_repo.get_by_artifact(s.artifact_id)) if s.artifact_id else 0
        results.append(
            ScanStatusResponse(
                scan_id=s.scan_id,
                engagement_id=s.engagement_id,
                scanner=s.scanner,
                target=s.target,
                status=s.status,
                options=s.options,
                observation_count=obs_count,
                artifact_id=s.artifact_id,
                error_message=s.error_message,
                created_at=s.created_at,
                completed_at=s.completed_at,
            )
        )
    return results
