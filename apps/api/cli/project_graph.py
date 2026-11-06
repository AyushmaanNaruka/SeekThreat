"""Write an engagement's attack graph to the read-only Neo4j projection.

The same work as POST /engagements/{engagement_id}/attack-graph/project, for operators
at a shell. Needs the `viz` compose profile running and NEO4J_URI / NEO4J_USER /
NEO4J_PASSWORD set (see .env.example). Neo4j is a disposable view (D-003): this replaces
the engagement's previous projection and touches no other engagement.

Usage:
    python -m apps.api.cli.project_graph --engagement-id eng-lab-demo
"""

from __future__ import annotations

import argparse
import logging
import sys

from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    TopologyRepository,
)
from apps.api.db.session import SessionLocal
from apps.api.graph_projection import (
    Neo4jProjector,
    ProjectionFailed,
    ProjectionSummary,
    ProjectionUnavailable,
)
from services.graph import analyze
from services.graph.engine import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATHS

logger = logging.getLogger("project_graph")

AUDIT_SCANNER = "attack_graph"


class ProjectGraphError(Exception):
    """The graph cannot be projected; the message says why."""


def project_graph(
    session: Session,
    engagement_id: str,
    projector: Neo4jProjector,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> ProjectionSummary:
    engagement = EngagementRepository(session).get(engagement_id)
    if engagement is None:
        raise ProjectGraphError(f"engagement {engagement_id!r} not found")
    topology = TopologyRepository(session).get(engagement_id)
    if topology is None:
        raise ProjectGraphError(
            f"no topology declared for {engagement_id!r}; load one with "
            f"`python -m apps.api.cli.load_topology --engagement-id {engagement_id} <file>`"
        )
    enriched = EnrichedFindingRepository(session).get_by_engagement(engagement_id)
    result = analyze(
        engagement_id=engagement_id,
        observations=ObservationRepository(session).get_by_engagement(engagement_id),
        findings=[e.finding for e in enriched],
        topology=topology,
        enriched=enriched,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    target = f"engagement:{engagement_id}/attack-graph/projection"
    details = {
        "topology_id": result.topology_id,
        "rules_digest": result.rules_digest,
        "nodes": len(result.nodes),
        "edges": len(result.edges),
        "paths": len(result.paths),
        "truncated": result.truncated,
        "neo4j": projector.target,
        "via": "cli",
    }
    actor = engagement.authorization.authorized_by
    try:
        summary = projector.project(result)
    except (ProjectionUnavailable, ProjectionFailed) as exc:
        log_audit_event(
            event="attack_graph.project_rejected",
            actor=actor,
            target=target,
            engagement_id=engagement_id,
            scanner=AUDIT_SCANNER,
            status="neo4j_unavailable"
            if isinstance(exc, ProjectionUnavailable)
            else "neo4j_failed",
            details={**details, "reason": str(exc)},
        )
        raise ProjectGraphError(str(exc)) from exc
    log_audit_event(
        event="attack_graph.projected",
        actor=actor,
        target=target,
        engagement_id=engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details=details,
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write an engagement's attack graph to the Neo4j projection."
    )
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-paths", type=int, default=DEFAULT_MAX_PATHS)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    projector = Neo4jProjector.from_settings()
    session = SessionLocal()
    try:
        projector.require_configured()
        summary = project_graph(
            session,
            args.engagement_id,
            projector,
            max_depth=args.max_depth,
            max_paths=args.max_paths,
        )
    except (ProjectGraphError, ProjectionUnavailable) as exc:
        logger.error("%s", exc)
        return 1
    finally:
        session.close()
    logger.info(
        "Projected %d nodes, %d relationships, %d paths for %s to %s%s",
        summary.nodes,
        summary.relationships,
        summary.paths,
        summary.engagement_id,
        summary.neo4j_uri,
        " (truncated)" if summary.truncated else "",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
