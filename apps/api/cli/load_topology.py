"""Load a declared network topology (YAML) into an engagement.

The same write as PUT /engagements/{engagement_id}/topology, for operators working
from a file such as `lab/topology.yaml`. The `--engagement-id` flag overrides the
file's own `engagement_id`, so one topology file can serve several engagements.

Usage:
    python -m apps.api.cli.load_topology --engagement-id eng-lab-demo lab/topology.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError
from sqlalchemy.orm import Session

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import EngagementRepository, TopologyRepository
from apps.api.db.session import SessionLocal
from packages.schema.models.topology import NetworkTopology

logger = logging.getLogger("load_topology")

AUDIT_SCANNER = "attack_graph"


class TopologyLoadError(Exception):
    """The file cannot be loaded into the engagement; the message says why."""


def read_topology(path: Path, engagement_id: str) -> NetworkTopology:
    """Parse and validate a topology YAML file, with `engagement_id` overriding the file's."""
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise TopologyLoadError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise TopologyLoadError(f"{path} does not contain a YAML mapping")
    document["engagement_id"] = engagement_id
    try:
        return NetworkTopology.model_validate(document)
    except ValidationError as exc:
        raise TopologyLoadError(f"{path} is not a valid topology:\n{exc}") from exc


def load_topology(session: Session, path: Path, engagement_id: str) -> NetworkTopology:
    """Store the topology in `path` as `engagement_id`'s declaration and commit."""
    engagement = EngagementRepository(session).get(engagement_id)
    if engagement is None:
        raise TopologyLoadError(
            f"engagement {engagement_id!r} not found; create it with POST /engagements first"
        )
    topology = read_topology(path, engagement_id)
    stored = TopologyRepository(session).upsert(topology)
    session.commit()
    log_audit_event(
        event="topology.declared",
        actor=stored.declared_by,
        target=f"engagement:{engagement_id}/topology",
        engagement_id=engagement_id,
        scanner=AUDIT_SCANNER,
        status="success",
        details={
            "topology_id": stored.topology_id,
            "declared_by": stored.declared_by,
            "zones": [z.name for z in stored.zones],
            "source_file": str(path),
            "via": "cli",
        },
    )
    return stored


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Load a topology YAML into an engagement.")
    parser.add_argument("topology_file", type=Path, help="Path to the topology YAML file")
    parser.add_argument(
        "--engagement-id",
        required=True,
        help="Engagement to declare the topology for (overrides the file's engagement_id)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    session = SessionLocal()
    try:
        stored = load_topology(session, args.topology_file, args.engagement_id)
    except TopologyLoadError as exc:
        logger.error("%s", exc)
        return 1
    finally:
        session.close()
    logger.info(
        "Declared topology %s for engagement %s (%d zones)",
        stored.topology_id,
        stored.engagement_id,
        len(stored.zones),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
