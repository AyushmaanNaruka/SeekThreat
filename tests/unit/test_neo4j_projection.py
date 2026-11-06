"""The Neo4j projection statement builder (services/graph/sinks/neo4j_projection.py).

Pure: no driver, no Neo4j. Built on the lab observation fixtures and lab/topology.yaml,
the same facts the engine tests use.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from packages.schema.models.graph import AttackGraphResult, NodeKind
from packages.schema.models.observation import Observation
from packages.schema.models.topology import NetworkTopology
from services.graph import analyze
from services.graph.sinks import neo4j_projection
from services.graph.sinks.neo4j_projection import (
    CREATE_PATHS,
    CREATE_PROJECTION,
    DELETE_ENGAGEMENT,
    MERGE_EDGES,
    PROJECTION_LABELS,
    Statement,
    projection_statements,
    schema_statements,
)
from services.normalize.interim_bridge import findings_from_observations

ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENT = "eng-lab-baseline"
DETECTED = datetime(2026, 9, 20, tzinfo=UTC)


@pytest.fixture(scope="module")
def result() -> AttackGraphResult:
    observations: list[Observation] = []
    for path in sorted((ROOT / "tests/fixtures/observations").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        observations.extend(Observation.model_validate(o) for o in data["observations"])
    topology = NetworkTopology.model_validate(
        yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    )
    return analyze(
        engagement_id=ENGAGEMENT,
        observations=observations,
        findings=findings_from_observations(observations, DETECTED),
        topology=topology,
    )


def _rows(statements: list[Statement], query: str) -> list[dict[str, Any]]:
    return [row for q, p in statements if q == query for row in p["rows"]]


def _node_statements(statements: list[Statement]) -> list[Statement]:
    return [(q, p) for q, p in statements if q.startswith("UNWIND $rows AS row MERGE (n:")]


def test_lab_result_is_not_trivial(result: AttackGraphResult) -> None:
    assert result.nodes and result.edges and result.paths


def test_first_statement_deletes_only_this_engagement(result: AttackGraphResult) -> None:
    statements = projection_statements(result)
    query, params = statements[0]
    assert query == DELETE_ENGAGEMENT
    assert "n.engagement_id = $engagement_id" in query
    assert params == {"engagement_id": ENGAGEMENT}
    assert sum(1 for q, _ in statements if "DELETE" in q) == 1


def test_every_pattern_is_scoped_by_engagement_parameter(result: AttackGraphResult) -> None:
    statements = projection_statements(result)
    for query, params in statements:
        assert ENGAGEMENT not in query, "engagement ids are parameters, never inlined"
        for pattern in re.findall(r"\((?:a|b|n|s|t):AttackState \{[^}]*\}\)", query):
            assert "engagement_id: $engagement_id" in pattern, pattern
        if query == CREATE_PROJECTION:
            assert params["props"]["engagement_id"] == ENGAGEMENT
        else:
            assert params["engagement_id"] == ENGAGEMENT


def test_another_engagement_gets_its_own_scope(result: AttackGraphResult) -> None:
    other = result.model_copy(update={"engagement_id": "eng-other"})
    statements = projection_statements(other)
    assert statements[0] == (DELETE_ENGAGEMENT, {"engagement_id": "eng-other"})
    blob = json.dumps([p for _, p in statements])
    assert f'"engagement_id": "{ENGAGEMENT}"' not in blob


def test_output_is_deterministic_and_order_independent(result: AttackGraphResult) -> None:
    first = projection_statements(result)
    assert projection_statements(result) == first
    shuffled = result.model_copy(
        update={"nodes": tuple(reversed(result.nodes)), "edges": tuple(reversed(result.edges))}
    )
    assert projection_statements(shuffled) == first


def test_parameters_are_json_serializable(result: AttackGraphResult) -> None:
    for _, params in projection_statements(result) + schema_statements():
        json.dumps(params)


def test_every_node_is_projected_once_with_its_kind_label(result: AttackGraphResult) -> None:
    statements = projection_statements(result)
    seen: dict[str, dict[str, Any]] = {}
    for query, params in _node_statements(statements):
        label = re.search(r"SET n:(\w+),", query)
        assert label is not None
        for row in params["rows"]:
            assert PROJECTION_LABELS[NodeKind(row["kind"])] == label.group(1)
            assert row["node_id"] not in seen
            seen[row["node_id"]] = row
    assert set(seen) == {n.node_id for n in result.nodes}
    for node in result.nodes:
        row = seen[node.node_id]
        assert (row["label"], row["machine"], row["zones"], row["goal"]) == (
            node.label,
            node.machine,
            list(node.zones),
            node.goal,
        )


def test_labels_come_only_from_the_fixed_table(result: AttackGraphResult) -> None:
    allowed = set(PROJECTION_LABELS.values()) | {
        "AttackState",
        "AttackPath",
        "GraphProjection",
        "Goal",
        "STEP",
        "STARTS_AT",
        "ENDS_AT",
    }
    for query, _ in projection_statements(result):
        for name in re.findall(r"[(\[]\w*:(\w+)", query):
            assert name in allowed, name
        for name in re.findall(r"SET \w+:(\w+)", query):
            assert name in allowed, name


def test_every_edge_is_projected_with_its_provenance(result: AttackGraphResult) -> None:
    rows = _rows(projection_statements(result), MERGE_EDGES)
    assert [r["edge_id"] for r in rows] == sorted(e.edge_id for e in result.edges)
    by_id = {r["edge_id"]: r for r in rows}
    for edge in result.edges:
        row = by_id[edge.edge_id]
        assert row["from_node"] == edge.from_node and row["to_node"] == edge.to_node
        assert row["rule_name"] == edge.rule_name
        assert row["confidence"] == edge.confidence.value
        assert row["evidence"] == list(edge.evidence) and row["evidence"]
        assert row["description"] == edge.description
        assert row["finding_ids"] == list(edge.finding_ids)
        assert row["path_count"] == len(row["path_ids"])


def test_paths_and_membership(result: AttackGraphResult) -> None:
    statements = projection_statements(result)
    path_rows = _rows(statements, CREATE_PATHS)
    assert [r["path_id"] for r in path_rows] == [p.path_id for p in result.paths]
    edge_rows = {r["edge_id"]: r for r in _rows(statements, MERGE_EDGES)}
    node_rows = {r["node_id"]: r for _, p in _node_statements(statements) for r in p["rows"]}
    for ordinal, (path, row) in enumerate(zip(result.paths, path_rows, strict=True)):
        assert row["ordinal"] == ordinal
        assert row["edge_ids"] == [e.edge_id for e in path.edges]
        assert row["entry_node"] == path.entry_node and row["goal_node"] == path.goal_node
        assert row["confidence"] == path.confidence.value
        assert "score" not in row  # unranked (D-039): absent, never zero
        for edge in path.edges:
            assert path.path_id in edge_rows[edge.edge_id]["path_ids"]
            assert path.path_id in node_rows[edge.from_node]["path_ids"]
            assert path.path_id in node_rows[edge.to_node]["path_ids"]
    on_some_path = {e.edge_id for p in result.paths for e in p.edges}
    for edge_id, row in edge_rows.items():
        assert bool(row["path_ids"]) == (edge_id in on_some_path)


def test_projection_metadata(result: AttackGraphResult) -> None:
    statements = projection_statements(result)
    assert statements[1][0] == CREATE_PROJECTION
    props = statements[1][1]["props"]
    assert props["topology_id"] == result.topology_id
    assert props["rules_digest"] == result.rules_digest
    assert props["truncated"] == result.truncated
    assert (props["node_count"], props["edge_count"], props["path_count"]) == (
        len(result.nodes),
        len(result.edges),
        len(result.paths),
    )


def test_large_inputs_are_batched_without_loss(
    result: AttackGraphResult, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(neo4j_projection, "BATCH_SIZE", 2)
    statements = projection_statements(result)
    assert all(len(p["rows"]) <= 2 for q, p in statements if "rows" in p)
    assert len(_rows(statements, MERGE_EDGES)) == len(result.edges)
    assert len(_rows(statements, CREATE_PATHS)) == len(result.paths)
    node_count = sum(len(p["rows"]) for _, p in _node_statements(statements))
    assert node_count == len(result.nodes)


def test_dangling_edge_is_rejected(result: AttackGraphResult) -> None:
    missing = result.edges[0].to_node
    broken = result.model_copy(
        update={"nodes": tuple(n for n in result.nodes if n.node_id != missing)}
    )
    with pytest.raises(ValueError, match="unknown node"):
        projection_statements(broken)


def test_empty_graph_still_clears_the_old_projection(result: AttackGraphResult) -> None:
    empty = result.model_copy(update={"nodes": (), "edges": (), "paths": (), "chokepoints": ()})
    statements = projection_statements(empty)
    assert [q for q, _ in statements] == [DELETE_ENGAGEMENT, CREATE_PROJECTION]
