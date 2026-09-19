"""Scan dispatch and status monitoring endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
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
from apps.api.db.session import get_db
from apps.api.tasks.scans import execute_scan

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

    # 3. Dispatch Celery task — authorization serialized as JSON-safe dict
    execute_scan.delay(
        scan_id,
        payload.engagement_id,
        payload.scanner,
        payload.target,
        payload.options,
        auth.model_dump(mode="json"),
    )

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
    "",
    response_model=list[ScanStatusResponse],
    summary="List scans for an engagement",
)
def list_scans(
    engagement_id: str = Query(..., description="Filter scans by engagement ID"),
    db: Session = Depends(get_db),
) -> list[ScanStatusResponse]:
    """Return all scans recorded for an engagement."""
    scan_repo = ScanRepository(db)
    obs_repo = ObservationRepository(db)
    scans = scan_repo.list_by_engagement(engagement_id)

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
