"""Cypher for the read-only Neo4j projection of one attack graph (DECISIONS.md D-003).

Neo4j is a disposable visualization of what the engine already proved. It is written
only from an `AttackGraphResult`, never read back by the engine, and can be dropped and
rebuilt from Postgres facts at any time. This module builds the statements and nothing
else: no driver import, no I/O. The writer in `apps/api/graph_projection.py` runs them.

Model (every element carries `engagement_id`; one engagement never touches another):

    (:GraphProjection)                         one per engagement: topology, rules, limits
    (:AttackState:<Kind>[:Goal])               one per GraphNode
        <Kind> is Attacker | NetworkAccess | CodeExecution | FileRead | Credentials
    (:AttackState)-[:STEP]->(:AttackState)     one per PathEdge, with rule and evidence
    (:AttackPath)                              one per enumerated path, edge_ids in order
    (:AttackPath)-[:STARTS_AT]->(:AttackState) its entry node
    (:AttackPath)-[:ENDS_AT]->(:AttackState)   its goal node

Path membership is also denormalised onto `STEP.path_ids` and `AttackState.path_ids`, so
one path is a single `WHERE $path_id IN r.path_ids` filter in Neo4j Browser.

The output is deterministic: the same result always yields the same statements with the
same parameters in the same order. Labels cannot be Cypher parameters, so they are
inlined from the fixed `PROJECTION_LABELS` table only, never from data.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from packages.schema.models.graph import AttackGraphResult, GraphNode, NodeKind, PathEdge

Statement = tuple[str, dict[str, Any]]

#: Rows per UNWIND statement. Lab graphs fit in one batch; this bounds a large one.
BATCH_SIZE = 500

#: The only strings ever inlined into Cypher as labels.
PROJECTION_LABELS: dict[NodeKind, str] = {
    NodeKind.ATTACKER: "Attacker",
    NodeKind.NETWORK_ACCESS: "NetworkAccess",
    NodeKind.CODE_EXECUTION: "CodeExecution",
    NodeKind.FILE_READ: "FileRead",
    NodeKind.CREDENTIALS: "Credentials",
}

DELETE_ENGAGEMENT = (
    "MATCH (n) "
    "WHERE (n:AttackState OR n:AttackPath OR n:GraphProjection) "
    "AND n.engagement_id = $engagement_id "
    "DETACH DELETE n"
)

CREATE_PROJECTION = "CREATE (g:GraphProjection) SET g = $props, g.projected_at = datetime()"

_MERGE_NODES = (
    "UNWIND $rows AS row "
    "MERGE (n:AttackState {{engagement_id: $engagement_id, node_id: row.node_id}}) "
    "SET n:{label}, n.kind = row.kind, n.label = row.label, n.machine = row.machine, "
    "n.zones = row.zones, n.goal = row.goal, n.path_ids = row.path_ids "
    "FOREACH (_ IN CASE WHEN row.goal THEN [1] ELSE [] END | SET n:Goal)"
)

MERGE_EDGES = (
    "UNWIND $rows AS row "
    "MATCH (a:AttackState {engagement_id: $engagement_id, node_id: row.from_node}) "
    "MATCH (b:AttackState {engagement_id: $engagement_id, node_id: row.to_node}) "
    "MERGE (a)-[r:STEP {engagement_id: $engagement_id, edge_id: row.edge_id}]->(b) "
    "SET r.rule_name = row.rule_name, r.confidence = row.confidence, "
    "r.evidence = row.evidence, r.description = row.description, "
    "r.finding_ids = row.finding_ids, r.path_ids = row.path_ids, "
    "r.path_count = row.path_count"
)

CREATE_PATHS = (
    "UNWIND $rows AS row "
    "MATCH (s:AttackState {engagement_id: $engagement_id, node_id: row.entry_node}) "
    "MATCH (t:AttackState {engagement_id: $engagement_id, node_id: row.goal_node}) "
    "CREATE (p:AttackPath) SET p = row, p.engagement_id = $engagement_id "
    "CREATE (p)-[:STARTS_AT]->(s) "
    "CREATE (p)-[:ENDS_AT]->(t)"
)


def schema_statements() -> list[Statement]:
    """Indexes for the MERGE/MATCH keys. Idempotent; run outside the write transaction
    (Neo4j does not mix schema and data changes in one transaction)."""
    return [
        (
            "CREATE INDEX seekthreat_attack_state IF NOT EXISTS "
            "FOR (n:AttackState) ON (n.engagement_id, n.node_id)",
            {},
        ),
        (
            "CREATE INDEX seekthreat_attack_path IF NOT EXISTS "
            "FOR (n:AttackPath) ON (n.engagement_id, n.path_id)",
            {},
        ),
    ]


def _batches(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    return [rows[i : i + BATCH_SIZE] for i in range(0, len(rows), BATCH_SIZE)]


def _node_row(node: GraphNode, path_ids: list[str]) -> dict[str, Any]:
    return {
        "node_id": node.node_id,
        "kind": node.kind.value,
        "label": node.label,
        "machine": node.machine,
        "zones": list(node.zones),
        "goal": node.goal,
        "path_ids": path_ids,
    }


def _edge_row(edge: PathEdge, path_ids: list[str]) -> dict[str, Any]:
    return {
        "edge_id": edge.edge_id,
        "from_node": edge.from_node,
        "to_node": edge.to_node,
        "rule_name": edge.rule_name,
        "confidence": edge.confidence.value,
        "evidence": list(edge.evidence),
        "description": edge.description,
        "finding_ids": list(edge.finding_ids),
        "path_ids": path_ids,
        "path_count": len(path_ids),
    }


def projection_statements(result: AttackGraphResult) -> list[Statement]:
    """Parameterized Cypher that replaces `result.engagement_id`'s projection with
    `result`. Run in order, in one transaction, so a reader never sees half a graph.

    Raises ValueError if an edge or path names a node the result does not contain: the
    MATCH would otherwise drop it silently and the projection would under-report.
    """
    engagement_id = result.engagement_id
    node_ids = {n.node_id for n in result.nodes}
    for edge in result.edges:
        for end in (edge.from_node, edge.to_node):
            if end not in node_ids:
                raise ValueError(f"edge {edge.edge_id} references unknown node {end!r}")

    edge_paths: dict[str, list[str]] = defaultdict(list)
    node_paths: dict[str, list[str]] = defaultdict(list)
    path_rows: list[dict[str, Any]] = []
    for ordinal, path in enumerate(result.paths):
        on_path: list[str] = []
        for edge in path.edges:
            edge_paths[edge.edge_id].append(path.path_id)
            for end in (edge.from_node, edge.to_node):
                if end not in node_ids:
                    raise ValueError(f"path {path.path_id} references unknown node {end!r}")
                if end not in on_path:
                    on_path.append(end)
        for node_id in on_path:
            node_paths[node_id].append(path.path_id)
        row: dict[str, Any] = {
            "path_id": path.path_id,
            "ordinal": ordinal,
            "length": len(path.edges),
            "confidence": path.confidence.value,
            "entry_node": path.entry_node,
            "goal_node": path.goal_node,
            "edge_ids": [e.edge_id for e in path.edges],
            "finding_ids": sorted({f for e in path.edges for f in e.finding_ids}),
        }
        if path.score is not None:
            row["score"] = path.score
        if path.rank is not None:
            row["rank"] = path.rank
            row["rank_explanation"] = path.rank_explanation
        path_rows.append(row)

    props: dict[str, Any] = {
        "engagement_id": engagement_id,
        "topology_id": result.topology_id,
        "rules_digest": result.rules_digest,
        "max_depth": result.max_depth,
        "max_paths": result.max_paths,
        "truncated": result.truncated,
        "ordering": result.ordering,
        "node_count": len(result.nodes),
        "edge_count": len(result.edges),
        "path_count": len(result.paths),
        "unclassified_finding_ids": sorted(u.finding_id for u in result.unclassified_findings),
        "unzoned_addresses": sorted(result.unzoned_addresses),
    }
    scope = {"engagement_id": engagement_id}
    statements: list[Statement] = [
        (DELETE_ENGAGEMENT, dict(scope)),
        (CREATE_PROJECTION, {"props": props}),
    ]

    kind_order = list(PROJECTION_LABELS)
    nodes = sorted(result.nodes, key=lambda n: (kind_order.index(n.kind), n.node_id))
    for kind, label in PROJECTION_LABELS.items():
        rows = [_node_row(n, node_paths.get(n.node_id, [])) for n in nodes if n.kind == kind]
        for batch in _batches(rows):
            statements.append((_MERGE_NODES.format(label=label), {**scope, "rows": batch}))

    edges = sorted(result.edges, key=lambda e: e.edge_id)
    edge_rows = [_edge_row(e, edge_paths.get(e.edge_id, [])) for e in edges]
    for batch in _batches(edge_rows):
        statements.append((MERGE_EDGES, {**scope, "rows": batch}))

    for batch in _batches(path_rows):
        statements.append((CREATE_PATHS, {**scope, "rows": batch}))
    return statements
