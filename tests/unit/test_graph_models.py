import pytest
from pydantic import ValidationError

from packages.schema.models.citation import Citation
from packages.schema.models.graph import AttackPath, Chokepoint, PathEdge, Rule


def _edge() -> PathEdge:
    return PathEdge(
        from_node="internet",
        to_node="ast-001",
        rule_name="remote_code_execution_on_exposed_service",
        evidence=["fnd-001", "obs-001"],
        description="Apache 2.4.49 path traversal reachable from outside",
    )


def test_edge_requires_evidence() -> None:
    with pytest.raises(ValidationError, match="evidence"):
        PathEdge(
            from_node="internet",
            to_node="ast-001",
            rule_name="some_rule",
            evidence=[],
        )


def test_edge_requires_a_named_rule() -> None:
    with pytest.raises(ValidationError, match="rule_name"):
        PathEdge(
            from_node="internet",
            to_node="ast-001",
            rule_name="   ",
            evidence=["fnd-001"],
        )


def test_edge_is_immutable() -> None:
    with pytest.raises(ValidationError):
        _edge().rule_name = "something_else"  # type: ignore[misc]


def test_evidence_cannot_be_mutated_in_place() -> None:
    edge = _edge()
    with pytest.raises(AttributeError):
        edge.evidence.append("obs-002")  # type: ignore[attr-defined]


def test_path_edges_cannot_be_mutated_in_place() -> None:
    path = AttackPath(path_id="path-1", edges=[_edge()])
    with pytest.raises(AttributeError):
        path.edges.append(_edge())  # type: ignore[attr-defined]


def test_attack_path_is_immutable() -> None:
    path = AttackPath(path_id="path-1", edges=[_edge()])
    with pytest.raises(ValidationError):
        path.path_id = "path-2"  # type: ignore[misc]


def test_rule_preconditions_cannot_be_mutated_in_place() -> None:
    rule = Rule(
        name="remote_code_execution_on_exposed_service",
        description="An exposed service with a known RCE grants code execution",
        preconditions=[{"kind": "service_version"}, {"kind": "vuln_candidate"}],
        effect="code_execution",
        citation="CAPEC-233",
    )
    with pytest.raises(AttributeError):
        rule.preconditions.append({"kind": "reachability"})  # type: ignore[attr-defined]


def test_attack_path_has_no_narration_by_default() -> None:
    path = AttackPath(path_id="path-1", edges=[_edge()])
    assert path.narration is None


def test_attack_path_requires_at_least_one_edge() -> None:
    with pytest.raises(ValidationError, match="edge"):
        AttackPath(path_id="path-1", edges=[])


def test_rule_is_data_and_can_cite_itself() -> None:
    rule = Rule(
        name="remote_code_execution_on_exposed_service",
        description="An exposed service with a known RCE grants code execution",
        preconditions=[{"kind": "service_version"}, {"kind": "vuln_candidate"}],
        effect="code_execution",
        citation="CAPEC-233",
    )
    assert rule.citation == "CAPEC-233"


def test_chokepoint_names_the_paths_it_breaks() -> None:
    cp = Chokepoint(
        finding_id="fnd-001",
        paths_broken=["path-1", "path-2"],
        remediation="Upgrade Apache to 2.4.51",
        rank=1,
    )
    assert len(cp.paths_broken) == 2


def test_citation_points_at_a_real_kind() -> None:
    c = Citation(kind="observation", ref_id="obs-001", excerpt="apache 2.4.49")
    assert c.kind == "observation"
    with pytest.raises(ValidationError):
        Citation(kind="vibes", ref_id="obs-001")


def test_schema_package_reexports_every_model() -> None:
    import packages.schema as schema

    for name in (
        "Asset",
        "AttackPath",
        "Attributed",
        "Authorization",
        "Chokepoint",
        "Citation",
        "Confidence",
        "Engagement",
        "EnrichedFinding",
        "ExposureRiskScore",
        "Finding",
        "Observation",
        "PathEdge",
        "Provenance",
        "RawArtifact",
        "Rule",
        "ScanResult",
        "ScoreComponent",
        "Service",
        "Source",
    ):
        assert hasattr(schema, name), f"packages.schema does not export {name}"
