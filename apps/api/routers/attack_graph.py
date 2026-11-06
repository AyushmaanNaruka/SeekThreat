"""Layer 3 endpoints: the declared network topology and the attack graph built on it.

- PUT  /engagements/{engagement_id}/topology               declare (or replace) the topology
- GET  /engagements/{engagement_id}/topology               read the declared topology
- GET  /engagements/{engagement_id}/attack-graph           build and enumerate paths
- POST /engagements/{engagement_id}/attack-graph/simulate  rebuild with findings fixed

The graph is computed on every request by `services.graph.analyze` from the facts in
the database: the engagement's observations, its findings (stored inside the enriched
finding rows) and its declared topology. Nothing here creates, edits or filters edges;
the engine is the only producer (CLAUDE.md, Hard Rule 1). The engine is pure, so the
same stored facts always produce byte-identical responses.

Every request writes an audit event carrying the actor, the target and the engagement
ID as the authorization reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    TopologyRepository,
)
from apps.api.db.session import get_db
from packages.schema.models.engagement import Engagement
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import AttackGraphResult, SimulationResult
from packages.schema.models.observation import Observation
from packages.schema.models.topology import NetworkTopology
from services.graph import analyze, simulate_remediation
from services.graph.engine import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATHS

router = APIRouter()

AUDIT_SCANNER = "attack_graph"

MAX_DEPTH_LIMIT = 20
MAX_PATHS_LIMIT = 5000
MAX_FIXED_FINDINGS = 1000


class SimulateRequest(BaseModel):
    """Findings to treat as remediated. Ids are plain finding ids (as in
    `Chokepoint.finding_id` and `PathEdge.finding_ids`), without a `finding:` prefix."""

    fixed_finding_ids: list[str] = Field(..., min_length=1, max_length=MAX_FIXED_FINDINGS)


def _require_engagement(db: Session, engagement_id: str, *, event: str) -> Engagement:
    """Return the engagement, or audit the miss and raise 404."""
    engagement = EngagementRepository(db).get(engagement_id)
    if engagement is None:
        log_audit_event(
            event=event,
            actor="unknown",
            target=f"engagement:{engagement_id}",
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


def _audit(
    engagement: Engagement,
    event: str,
    target: str,
    result: str,
    details: dict[str, Any],
    actor: str | None = None,
) -> None:
    log_audit_event(
        event=event,
        actor=actor or engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status=result,
        details=details,
    )


def _no_topology(engagement: Engagement, event: str, target: str) -> HTTPException:
    _audit(engagement, event, target, "no_topology", {"reason": "no topology declared"})
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"No network topology is declared for engagement {engagement.engagement_id!r}. "
            "The attack graph needs one to know which zones reach which: declare it with "
            f"PUT /engagements/{engagement.engagement_id}/topology, or load a YAML file with "
            "`python -m apps.api.cli.load_topology --engagement-id "
            f"{engagement.engagement_id} <topology.yaml>`."
        ),
    )


@dataclass(frozen=True)
class _Facts:
    topology: NetworkTopology
    observations: list[Observation]
    findings: list[Finding]
    enriched: list[EnrichedFinding]


def _load_facts(db: Session, engagement: Engagement, event: str, target: str) -> _Facts:
    """Everything the engine needs for one engagement, read from the database."""
    topology = TopologyRepository(db).get(engagement.engagement_id)
    if topology is None:
        raise _no_topology(engagement, event, target)
    observations = ObservationRepository(db).get_by_engagement(engagement.engagement_id)
    # Findings are persisted only inside their enriched rows (EnrichedFinding.finding).
    enriched = EnrichedFindingRepository(db).get_by_engagement(engagement.engagement_id)
    findings = [e.finding for e in enriched]
    return _Facts(topology, observations, findings, enriched)


def _graph_summary(result: AttackGraphResult) -> dict[str, Any]:
    return {
        "topology_id": result.topology_id,
        "rules_digest": result.rules_digest,
        "nodes": len(result.nodes),
        "edges": len(result.edges),
        "paths": len(result.paths),
        "truncated": result.truncated,
        "max_depth": result.max_depth,
        "max_paths": result.max_paths,
    }


@router.put(
    "/{engagement_id}/topology",
    response_model=NetworkTopology,
    summary="Declare (or replace) the engagement's network topology",
)
def put_topology(
    engagement_id: str,
    topology: NetworkTopology,
    db: Session = Depends(get_db),
) -> NetworkTopology:
    """Store the declared network model the attack graph is built against. Replaces any
    earlier declaration. The response carries the computed `topology_id`."""
    engagement = _require_engagement(db, engagement_id, event="topology.declare_rejected")
    target = f"engagement:{engagement_id}/topology"
    if topology.engagement_id != engagement_id:
        reason = (
            f"Topology declares engagement_id {topology.engagement_id!r} but was sent to "
            f"engagement {engagement_id!r}"
        )
        _audit(
            engagement,
            "topology.declare_rejected",
            target,
            "rejected",
            {"reason": reason},
            actor=topology.declared_by,
        )
        raise HTTPException(status_code=422, detail=reason)  # Unprocessable Content

    previous = TopologyRepository(db).get(engagement_id)
    stored = TopologyRepository(db).upsert(topology)
    db.commit()
    _audit(
        engagement,
        "topology.declared",
        target,
        "success",
        {
            "topology_id": stored.topology_id,
            "previous_topology_id": previous.topology_id if previous else None,
            "declared_by": stored.declared_by,
            "zones": [z.name for z in stored.zones],
        },
        actor=stored.declared_by,
    )
    return stored


@router.get(
    "/{engagement_id}/topology",
    response_model=NetworkTopology,
    summary="Get the engagement's declared network topology",
)
def get_topology(engagement_id: str, db: Session = Depends(get_db)) -> NetworkTopology:
    engagement = _require_engagement(db, engagement_id, event="topology.read_rejected")
    target = f"engagement:{engagement_id}/topology"
    topology = TopologyRepository(db).get(engagement_id)
    _audit(
        engagement,
        "topology.read",
        target,
        "success" if topology else "not_found",
        {"topology_id": topology.topology_id if topology else None},
    )
    if topology is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No network topology is declared for engagement {engagement_id!r}. "
                f"Declare one with PUT /engagements/{engagement_id}/topology."
            ),
        )
    return topology


@router.get(
    "/{engagement_id}/attack-graph",
    response_model=AttackGraphResult,
    summary="Build the attack graph and enumerate attack paths for an engagement",
)
def get_attack_graph(
    engagement_id: str,
    max_depth: int = Query(DEFAULT_MAX_DEPTH, ge=1, le=MAX_DEPTH_LIMIT),
    max_paths: int = Query(DEFAULT_MAX_PATHS, ge=1, le=MAX_PATHS_LIMIT),
    db: Session = Depends(get_db),
) -> AttackGraphResult:
    """Deterministic: the same stored facts and limits always give byte-identical
    output. `truncated` says when `max_paths` or `max_depth` cut enumeration short."""
    engagement = _require_engagement(db, engagement_id, event="attack_graph.read_rejected")
    target = f"engagement:{engagement_id}/attack-graph"
    facts = _load_facts(db, engagement, "attack_graph.read_rejected", target)
    result = analyze(
        engagement_id=engagement_id,
        observations=facts.observations,
        findings=facts.findings,
        topology=facts.topology,
        enriched=facts.enriched,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    _audit(engagement, "attack_graph.read", target, "success", _graph_summary(result))
    return result


@router.post(
    "/{engagement_id}/attack-graph/simulate",
    response_model=SimulationResult,
    summary="Simulate remediating findings: rebuild the graph and report what disappears",
)
def simulate_attack_graph(
    engagement_id: str,
    request: SimulateRequest,
    max_depth: int = Query(DEFAULT_MAX_DEPTH, ge=1, le=MAX_DEPTH_LIMIT),
    max_paths: int = Query(DEFAULT_MAX_PATHS, ge=1, le=MAX_PATHS_LIMIT),
    db: Session = Depends(get_db),
) -> SimulationResult:
    """The baseline uses the same `max_depth`/`max_paths` as the post-fix rebuild, so
    pass the values the caller used for GET .../attack-graph to compare like with like."""
    engagement = _require_engagement(db, engagement_id, event="attack_graph.simulate_rejected")
    target = f"engagement:{engagement_id}/attack-graph"
    facts = _load_facts(db, engagement, "attack_graph.simulate_rejected", target)

    known = {f.finding_id for f in facts.findings}
    unknown = sorted(set(request.fixed_finding_ids) - known)
    if unknown:
        reason = f"Findings {unknown} are not recorded under engagement {engagement_id!r}"
        _audit(
            engagement,
            "attack_graph.simulate_rejected",
            target,
            "rejected",
            {"reason": reason, "finding_ids": unknown},
        )
        raise HTTPException(status_code=422, detail=reason)  # Unprocessable Content

    common: dict[str, Any] = {
        "engagement_id": engagement_id,
        "observations": facts.observations,
        "findings": facts.findings,
        "topology": facts.topology,
        "enriched": facts.enriched,
    }
    baseline = analyze(**common, max_depth=max_depth, max_paths=max_paths)
    simulation = simulate_remediation(
        baseline=baseline, fixed_finding_ids=request.fixed_finding_ids, **common
    )
    _audit(
        engagement,
        "attack_graph.simulated",
        target,
        "success",
        {
            "fixed_finding_ids": list(simulation.fixed_finding_ids),
            "baseline_path_count": simulation.baseline_path_count,
            "remaining_path_count": simulation.remaining_path_count,
            "goals_no_longer_reachable": list(simulation.goals_no_longer_reachable),
            **_graph_summary(baseline),
        },
    )
    return simulation
