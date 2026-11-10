"""Engagement report export (DECISIONS.md D-051).

- GET /engagements/{engagement_id}/report?format=md|json

Reads the engagement's stored facts, builds the attack graph and the top-chokepoint
remediation simulation exactly as the attack-graph endpoints do, and hands everything
to the pure builder in `services.report`. Nothing here edits, filters or adds graph
edges (CLAUDE.md, Hard Rule 1), and no model is called: assistant narrations are not
stored, so this export never carries one.

Every request writes an audit event with the actor, the target and the engagement ID as
the authorization reference. The success event records the SHA-256 of the bytes served,
so a handed-over report can be matched to the request that produced it.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    ScanRepository,
    TopologyRepository,
)
from apps.api.db.session import get_db
from packages.schema.models.graph import AttackGraphResult, SimulationResult
from services.graph import analyze, simulate_remediation
from services.graph.engine import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATHS
from services.report import MEDIA_TYPES, ScanRecord, build_report, render

router = APIRouter()

AUDIT_SCANNER = "report"
MAX_DEPTH_LIMIT = 20
MAX_PATHS_LIMIT = 5000

_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _filename(engagement_id: str, fmt: str) -> str:
    safe = _FILENAME_UNSAFE.sub("_", engagement_id).strip("._") or "engagement"
    return f"seekthreat-report-{safe}.{fmt}"


@router.get(
    "/{engagement_id}/report",
    summary="Export the engagement report (Markdown or JSON) from the deterministic builder",
    responses={
        200: {
            "content": {"text/markdown": {}, "application/json": {}},
            "description": "The report, as a file download.",
        }
    },
)
def get_report(
    engagement_id: str,
    format: Literal["md", "json"] = Query("md", description="md or json"),
    max_depth: int = Query(DEFAULT_MAX_DEPTH, ge=1, le=MAX_DEPTH_LIMIT),
    max_paths: int = Query(DEFAULT_MAX_PATHS, ge=1, le=MAX_PATHS_LIMIT),
    db: Session = Depends(get_db),
) -> Response:
    """Same stored facts and limits give the same report; only `generated_at` (the
    request time) differs between two downloads."""
    target = f"engagement:{engagement_id}/report"
    engagement = EngagementRepository(db).get(engagement_id)
    if engagement is None:
        log_audit_event(
            event="report.rejected",
            actor="unknown",
            target=target,
            engagement_id=engagement_id,
            scanner=AUDIT_SCANNER,
            status="not_found",
            details={"reason": f"Engagement {engagement_id!r} not found", "format": format},
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Engagement {engagement_id!r} not found",
        )

    observations = ObservationRepository(db).get_by_engagement(engagement_id)
    finding_repo = EnrichedFindingRepository(db)
    enriched = finding_repo.get_by_engagement(engagement_id)
    skipped = max(finding_repo.count_by_engagement(engagement_id) - len(enriched), 0)
    scans = [
        ScanRecord(
            scan_id=s.scan_id,
            scanner=s.scanner,
            target=s.target,
            status=s.status,
            artifact_id=s.artifact_id,
            error_message=s.error_message,
            created_at=_aware(s.created_at),
            completed_at=_aware(s.completed_at) if s.completed_at else None,
        )
        for s in ScanRepository(db).list_by_engagement(engagement_id)
    ]
    topology = TopologyRepository(db).get(engagement_id)

    graph: AttackGraphResult | None = None
    simulation: SimulationResult | None = None
    unavailable: str | None = None
    if topology is None:
        unavailable = (
            "no network topology is declared for this engagement, so the engine cannot "
            f"tell which zones reach which. Declare one with PUT /engagements/"
            f"{engagement_id}/topology."
        )
    else:
        common: dict[str, Any] = {
            "engagement_id": engagement_id,
            "observations": observations,
            "findings": [e.finding for e in enriched],
            "topology": topology,
            "enriched": enriched,
        }
        graph = analyze(**common, max_depth=max_depth, max_paths=max_paths)
        if graph.chokepoints:
            top = min(graph.chokepoints, key=lambda c: (c.rank, c.finding_id))
            simulation = simulate_remediation(
                baseline=graph, fixed_finding_ids=[top.finding_id], **common
            )

    report = build_report(
        engagement=engagement,
        scans=scans,
        observations=observations,
        enriched=enriched,
        topology=topology,
        graph=graph,
        simulation=simulation,
        generated_at=datetime.now(UTC),
        attack_graph_unavailable=unavailable,
        skipped_findings=skipped,
    )
    body = render(report, format).encode("utf-8")

    log_audit_event(
        event="report.generated",
        actor=engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details={
            "format": format,
            "generated_at": report.generated_at.isoformat(),
            "sha256": hashlib.sha256(body).hexdigest(),
            "bytes": len(body),
            "scans": len(report.scans),
            "findings": len(report.findings),
            "skipped_findings": skipped,
            "topology_id": topology.topology_id if topology else None,
            "rules_digest": graph.rules_digest if graph else None,
            "paths": len(graph.paths) if graph else None,
            "truncated": graph.truncated if graph else None,
            "simulated_finding_ids": list(simulation.fixed_finding_ids) if simulation else [],
            "max_depth": max_depth,
            "max_paths": max_paths,
        },
    )
    return Response(
        content=body,
        media_type=MEDIA_TYPES[format],
        headers={
            "Content-Disposition": f'attachment; filename="{_filename(engagement_id, format)}"'
        },
    )


def _aware(value: datetime) -> datetime:
    """SQLite drops tzinfo on read; every stored timestamp is written in UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
