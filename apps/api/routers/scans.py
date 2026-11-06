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
from apps.api.core.authorization import AuthorizationDeniedError, verify_scan_authorization
from apps.api.core.targets import (
    MAX_SCANS_PER_BATCH,
    TargetPlan,
    TargetPlanError,
    plan_targets,
)
from apps.api.db.repositories import (
    EngagementRepository,
    ObservationRepository,
    ScanRepository,
)
from apps.api.db.session import get_db
from apps.api.routers.observations import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    ObservationListResponse,
    ObservationResponse,
)
from apps.api.tasks.scans import execute_scan
from packages.schema.models.engagement import Authorization, Engagement
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

    # 2. Register and dispatch
    return _register_and_dispatch(
        db,
        engagement_id=payload.engagement_id,
        scanner=payload.scanner,
        target=payload.target,
        options=payload.options,
        auth=auth,
    )


def _register_and_dispatch(
    db: Session,
    *,
    engagement_id: str,
    scanner: str,
    target: str,
    options: dict[str, Any],
    auth: Authorization,
) -> ScanStatusResponse:
    """Record a pending scan for a gate-approved target and queue it on Celery."""
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    scan_repo = ScanRepository(db)
    scan = scan_repo.create(
        scan_id=scan_id,
        engagement_id=engagement_id,
        scanner=scanner,
        target=target,
        options=options,
    )
    db.commit()

    # Dispatch Celery task — authorization serialized as JSON-safe dict.
    # If the broker is unavailable, mark the scan failed and return 503.
    # The scan.dispatch_failed audit event is logged so every failure is
    # traceable. The worker container is the one attached to the lab network;
    # the API container must never scan anything.
    try:
        execute_scan.delay(
            scan_id,
            engagement_id,
            scanner,
            target,
            options,
            auth.model_dump(mode="json"),
        )
    except Exception as exc:
        error_msg = f"Dispatch failed: {exc}"
        logger.error(
            "Celery broker unavailable; scan %s not dispatched: %s",
            scan_id,
            exc,
        )
        try:
            scan_repo.update_status(
                scan_id=scan_id,
                status="failed",
                error_message=error_msg,
                completed_at=datetime.now(UTC),
            )
            db.commit()
        except Exception:
            db.rollback()
        log_audit_event(
            event="scan.dispatch_failed",
            actor=auth.authorized_by,
            target=target,
            engagement_id=engagement_id,
            scanner=scanner,
            status="error",
            details={"scan_id": scan_id, "error": error_msg},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable; the scan was not dispatched.",
        ) from exc

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


class BatchScanRequest(BaseModel):
    engagement_id: str = Field(..., description="Target engagement identifier")
    scanner: str = Field(default="nmap", description="Scanner identifier (e.g. nmap)")
    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description=(
            "IPs, CIDR blocks, IPv4 ranges (10.0.0.1-20), hostnames, host:port or "
            "http(s) URLs. Each string may hold several, separated by commas, "
            "semicolons or whitespace."
        ),
    )
    options: dict[str, Any] = Field(
        default_factory=dict, description="Scanner options shared by every planned scan"
    )


class PlannedScanItem(BaseModel):
    input: str
    target: str
    options: dict[str, Any]
    kind: str
    note: str | None = None


class ScanRejectionItem(BaseModel):
    input: str
    target: str | None = None
    reason: str


class ScanPlanResponse(BaseModel):
    planned: list[PlannedScanItem]
    rejected: list[ScanRejectionItem]
    total_planned: int
    max_scans: int


class BatchScanResponse(BaseModel):
    accepted: list[ScanStatusResponse]
    rejected: list[ScanRejectionItem]


def _plan_or_422(payload: BatchScanRequest) -> TargetPlan:
    if sum(len(t) for t in payload.targets) > 100_000:
        raise HTTPException(status_code=422, detail="targets input is too large")
    try:
        return plan_targets(payload.scanner, payload.targets, payload.options)
    except TargetPlanError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _engagement_or_404(db: Session, payload: BatchScanRequest) -> Engagement:
    engagement = EngagementRepository(db).get(payload.engagement_id)
    if engagement is None:
        log_audit_event(
            event="scan.rejected",
            actor="unknown",
            target=",".join(payload.targets)[:500],
            engagement_id=payload.engagement_id,
            scanner=payload.scanner,
            status="forbidden",
            details={"reason": f"Engagement {payload.engagement_id!r} not found"},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {payload.engagement_id!r} not found",
        )
    return engagement


def _window_open(auth: Authorization) -> bool:
    now = datetime.now(UTC)
    return auth.granted_at <= now <= auth.expires_at


def _out_of_scope(auth: Authorization) -> str:
    return f"outside the engagement's allowlist ({', '.join(auth.allowlist)})"


def _rejections(plan: TargetPlan) -> list[ScanRejectionItem]:
    return [
        ScanRejectionItem(input=r.input, target=r.target, reason=r.reason) for r in plan.rejected
    ]


@router.post(
    "/plan",
    response_model=ScanPlanResponse,
    summary="Dry run: expand targets and check each against the allowlist",
)
def plan_scans(
    payload: BatchScanRequest,
    db: Session = Depends(get_db),
) -> ScanPlanResponse:
    """Show what `POST /scans/batch` would launch. Nothing is recorded or dispatched.

    This is a preview for the operator, not an authorization decision: the batch
    endpoint re-plans and runs every target through the gate itself.
    """
    engagement = _engagement_or_404(db, payload)
    plan = _plan_or_422(payload)
    auth = engagement.authorization
    rejected = _rejections(plan)
    planned: list[PlannedScanItem] = []
    window_open = _window_open(auth)
    for item in plan.planned:
        if not window_open:
            reason = "engagement authorization is not active (outside its time window)"
        elif not auth.permits(item.target):
            reason = _out_of_scope(auth)
        else:
            planned.append(
                PlannedScanItem(
                    input=item.input,
                    target=item.target,
                    options=item.options,
                    kind=item.kind,
                    note=item.note,
                )
            )
            continue
        rejected.append(ScanRejectionItem(input=item.input, target=item.target, reason=reason))
    return ScanPlanResponse(
        planned=planned,
        rejected=rejected,
        total_planned=len(planned),
        max_scans=MAX_SCANS_PER_BATCH,
    )


@router.post(
    "/batch",
    response_model=BatchScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Expand many targets, gate each one, and dispatch a scan per approved target",
)
def create_scan_batch(
    payload: BatchScanRequest,
    db: Session = Depends(get_db),
) -> BatchScanResponse:
    """Launch scans for every authorized target in the input.

    Each planned target goes through the same `verify_scan_authorization` gate
    as `POST /scans`, one at a time, with its own audit event and scan record.
    Targets the gate refuses are reported back and never dispatched. If nothing
    at all is approved the request fails with 422 and the reasons.
    """
    engagement = _engagement_or_404(db, payload)
    plan = _plan_or_422(payload)
    auth = engagement.authorization
    rejected = _rejections(plan)

    if plan.planned and not _window_open(auth):
        # Same 403 and audit event as a single scan; the window is shared.
        verify_scan_authorization(engagement, plan.planned[0].target, payload.scanner)

    log_audit_event(
        event="scan.batch_requested",
        actor=auth.authorized_by,
        target=",".join(payload.targets)[:500],
        engagement_id=payload.engagement_id,
        scanner=payload.scanner,
        status="received",
        details={"planned": len(plan.planned), "unparseable": len(plan.rejected)},
    )

    accepted: list[ScanStatusResponse] = []
    for index, item in enumerate(plan.planned):
        try:
            gate_auth = verify_scan_authorization(engagement, item.target, payload.scanner)
        except AuthorizationDeniedError:
            rejected.append(
                ScanRejectionItem(input=item.input, target=item.target, reason=_out_of_scope(auth))
            )
            continue
        try:
            accepted.append(
                _register_and_dispatch(
                    db,
                    engagement_id=payload.engagement_id,
                    scanner=payload.scanner,
                    target=item.target,
                    options=item.options,
                    auth=gate_auth,
                )
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE or not accepted:
                raise
            # Broker went away mid-batch: report the rest rather than hide them.
            rejected.extend(
                ScanRejectionItem(
                    input=rest.input,
                    target=rest.target,
                    reason="scan queue unavailable; not dispatched",
                )
                for rest in plan.planned[index:]
            )
            break

    if not accepted:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "No target in the input is both valid and authorized.",
                "rejected": [r.model_dump() for r in rejected],
            },
        )
    return BatchScanResponse(accepted=accepted, rejected=rejected)


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
    limit: int = Query(50, ge=1, le=500, description="Max number of scans to return"),
    offset: int = Query(0, ge=0, description="Number of scans to skip"),
    db: Session = Depends(get_db),
) -> list[ScanStatusResponse]:
    """Return all scans recorded for an engagement or across all engagements."""
    scan_repo = ScanRepository(db)
    obs_repo = ObservationRepository(db)
    if engagement_id:
        scans = scan_repo.list_by_engagement(engagement_id)
    else:
        scans = scan_repo.list_all(limit=limit, offset=offset)

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
