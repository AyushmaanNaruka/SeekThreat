"""Layer 3 engine: rules, determinism, enumeration, chokepoints, simulation.

Built on the observation fixtures (tests/fixtures/observations/) and the declared lab
topology (lab/topology.yaml). No scanning, no network.
"""

from __future__ import annotations

import json
import random
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import AttackGraphResult, NodeKind
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.provenance import Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent
from packages.schema.models.topology import NetworkTopology
from services.graph import analyze, build_attack_graph, load_ruleset, simulate_remediation
from services.graph.builder import MATCHERS, parse_endpoint
from services.graph.engine import enumerate_paths
from services.normalize.interim_bridge import findings_from_observations

ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENT = "eng-lab-baseline"
DETECTED = datetime(2026, 9, 20, tzinfo=UTC)


def _observations() -> list[Observation]:
    out: list[Observation] = []
    for path in sorted((ROOT / "tests/fixtures/observations").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        out.extend(Observation.model_validate(o) for o in data["observations"])
    return out


def _topology(**overrides: Any) -> NetworkTopology:
    raw = yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    raw.update(overrides)
    return NetworkTopology.model_validate(raw)


@pytest.fixture(scope="module")
def facts() -> tuple[list[Observation], list[Finding]]:
    obs = _observations()
    return obs, findings_from_observations(obs, DETECTED)


@pytest.fixture(scope="module")
def result(facts: tuple[list[Observation], list[Finding]]) -> AttackGraphResult:
    obs, fnd = facts
    return analyze(engagement_id=ENGAGEMENT, observations=obs, findings=fnd, topology=_topology())


def _finding_for(fnd: list[Finding], cve: str) -> Finding:
    return next(f for f in fnd if cve in f.cve_ids)


# ------------------------------------------------------------------- rules as data


def test_every_yaml_rule_has_a_matcher_and_vice_versa() -> None:
    assert set(load_ruleset().rules) == MATCHERS


def test_assumption_rules_are_low_confidence() -> None:
    for rule in load_ruleset().rules.values():
        if rule.assumption:
            assert rule.confidence == Confidence.LOW, rule.name


def test_every_edge_cites_a_known_rule_and_real_facts(
    result: AttackGraphResult, facts: tuple[list[Observation], list[Finding]]
) -> None:
    obs, fnd = facts
    obs_ids = {o.observation_id for o in obs}
    finding_ids = {f.finding_id for f in fnd}
    rules = load_ruleset().rules
    assert result.edges
    for edge in result.edges:
        assert edge.rule_name in rules
        assert edge.evidence
        for ref in edge.evidence:
            if ref.startswith("obs:"):
                assert ref in obs_ids, ref
            elif ref.startswith("topology:"):
                assert ref == result.topology_id
            elif ref.startswith("finding:"):
                assert ref.removeprefix("finding:") in finding_ids
            else:
                pytest.fail(f"unprefixed evidence id {ref!r}")
        for finding_id in edge.finding_ids:
            assert finding_id in finding_ids


# ------------------------------------------------------------------- determinism


def test_same_facts_in_any_order_give_byte_identical_output(
    facts: tuple[list[Observation], list[Finding]], result: AttackGraphResult
) -> None:
    obs, fnd = facts
    rng = random.Random(20261106)
    for _ in range(3):
        o, f = obs[:], fnd[:]
        rng.shuffle(o)
        rng.shuffle(f)
        again = analyze(engagement_id=ENGAGEMENT, observations=o, findings=f, topology=_topology())
        assert again.model_dump_json() == result.model_dump_json()


def test_build_makes_no_network_calls(
    monkeypatch: pytest.MonkeyPatch, facts: tuple[list[Observation], list[Finding]]
) -> None:
    def refuse(*_: object, **__: object) -> None:
        raise AssertionError("graph build attempted a network call")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    obs, fnd = facts
    analyze(engagement_id=ENGAGEMENT, observations=obs, findings=fnd, topology=_topology())


# ------------------------------------------------------------------- paths


def test_paths_are_simple_chains_from_an_attacker_to_a_goal(result: AttackGraphResult) -> None:
    nodes = {n.node_id: n for n in result.nodes}
    edge_ids = {e.edge_id for e in result.edges}
    assert result.paths
    for path in result.paths:
        assert nodes[path.entry_node].kind == NodeKind.ATTACKER
        assert nodes[path.goal_node].goal
        visited = [path.entry_node] + [e.to_node for e in path.edges]
        assert len(visited) == len(set(visited)), "path revisits a node"
        assert all(e.edge_id in edge_ids for e in path.edges)
        assert path.score is None
        assert path.narration is None  # narration is strictly downstream (Layer 4)


def test_paths_are_ranked_by_confidence_then_length_when_nothing_is_scored(
    result: AttackGraphResult,
) -> None:
    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    keys = [
        (order[p.confidence], len(p.edges), tuple(e.edge_id for e in p.edges)) for p in result.paths
    ]
    assert keys == sorted(keys)
    assert [p.rank for p in result.paths] == list(range(1, len(result.paths) + 1))
    assert len({p.path_id for p in result.paths}) == len(result.paths)
    for path in result.paths:
        assert path.score is None
        assert path.rank_explanation is not None
        assert path.rank_explanation.startswith(f"Rank {path.rank}:")
        assert "not scored" in path.rank_explanation


def _enriched(finding: Finding, ers_value: float) -> EnrichedFinding:
    prov = Provenance(source=Source.DERIVED, confidence=Confidence.HIGH, retrieved_at=DETECTED)
    component = ScoreComponent(
        name="test", value=ers_value, weight=1.0, explanation="test input", provenance=prov
    )
    return EnrichedFinding(
        finding=finding, ers=ExposureRiskScore(value=ers_value, components=(component,))
    )


def test_stored_ers_orders_paths_of_equal_confidence(
    facts: tuple[list[Observation], list[Finding]], result: AttackGraphResult
) -> None:
    obs, fnd = facts
    jenkins = _finding_for(fnd, "CVE-2024-23897")
    ranked = analyze(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(),
        enriched=[_enriched(jenkins, 9.5)],
    )
    # Same path set; ranking only reorders.
    assert sorted(p.path_id for p in ranked.paths) == sorted(p.path_id for p in result.paths)
    low = [p for p in ranked.paths if p.confidence == Confidence.LOW]
    uses = [any(jenkins.finding_id in e.finding_ids for e in p.edges) for p in low]
    # Every low-confidence path through the scored Jenkins finding precedes every one
    # that has no scored finding.
    assert uses == sorted(uses, reverse=True)
    assert uses[0], "no low-confidence path exploits the scored finding"
    first = low[0]
    assert first.rank_explanation is not None
    assert "9.5" in first.rank_explanation
    assert "CVE-2024-23897" in first.rank_explanation
    # Confidence still dominates ERS: high-confidence paths come first.
    assert ranked.paths[0].confidence == Confidence.HIGH


def test_lab_paths_reach_the_data_tier_and_the_wiki(result: AttackGraphResult) -> None:
    goals = {p.goal_node for p in result.paths}
    assert "access:172.20.3.20:6379/tcp" in goals  # cache-redis
    assert "access:172.20.3.10:5432/tcp" in goals  # db-primary
    assert "exec:host:172.20.2.40" in goals  # internal-wiki
    # Gateway RCE -> wiki RCE is fully observed: no assumption on it.
    high = [p for p in result.paths if p.confidence == Confidence.HIGH]
    assert any(p.goal_node == "exec:host:172.20.2.40" for p in high)


def test_data_tier_is_reached_only_through_the_dual_homed_bastion(
    result: AttackGraphResult,
) -> None:
    for path in result.paths:
        if path.goal_node.startswith("access:172.20.3."):
            assert any(e.to_node == "exec:bastion-ssh" for e in path.edges)
            # Getting onto the bastion rests on the credential-reuse assumption.
            assert path.confidence == Confidence.LOW


def test_truncation_is_reported_and_keeps_the_shortest_prefix(
    facts: tuple[list[Observation], list[Finding]], result: AttackGraphResult
) -> None:
    assert not result.truncated
    obs, fnd = facts
    small = analyze(
        engagement_id=ENGAGEMENT, observations=obs, findings=fnd, topology=_topology(), max_paths=5
    )
    assert small.truncated
    graph = build_attack_graph(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(),
        ruleset=load_ruleset(),
    )
    shortest = enumerate_paths(graph).paths[:5]
    # Truncation keeps the shortest-first enumeration prefix; ranking then reorders it.
    assert sorted(p.path_id for p in small.paths) == sorted(p.path_id for p in shortest)
    shallow = analyze(
        engagement_id=ENGAGEMENT, observations=obs, findings=fnd, topology=_topology(), max_depth=3
    )
    assert shallow.truncated
    assert all(len(p.edges) <= 3 for p in shallow.paths)


def test_enumeration_budget_stops_with_truncation(
    facts: tuple[list[Observation], list[Finding]],
) -> None:
    obs, fnd = facts
    graph = build_attack_graph(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(),
        ruleset=load_ruleset(),
    )
    assert enumerate_paths(graph, max_expansions=10).truncated


# ------------------------------------------------------------------- classification


def test_smuggling_finding_is_listed_as_unclassified_with_its_evidence(
    result: AttackGraphResult,
) -> None:
    (entry,) = [u for u in result.unclassified_findings if "CVE-2022-29361" in u.cve_ids]
    assert "CWE-444" in entry.reason


def test_classification_confidence_follows_the_strongest_signal(
    result: AttackGraphResult,
) -> None:
    by_target = {
        (e.to_node, e.rule_name): e for e in result.edges if e.rule_name.startswith("exploit_")
    }
    # nuclei 'rce' tag -> high
    assert by_target[("exec:spring-gateway", "exploit_grants_code_execution")].confidence == (
        Confidence.HIGH
    )
    # only CWE-787 (memory corruption) -> low
    assert by_target[("exec:dmz-proxy", "exploit_grants_code_execution")].confidence == (
        Confidence.LOW
    )
    # nuclei 'lfi' tag -> file read, not code execution
    assert ("read:host:172.20.2.25", "exploit_grants_file_read") in by_target
    assert ("exec:host:172.20.2.25", "exploit_grants_code_execution") not in by_target


def _vuln_obs(attrs: dict[str, str]) -> Observation:
    base = {
        "endpoint": "172.20.1.10:80/tcp",
        "cve_ids": "CVE-2021-41773",
    }
    return Observation(
        observation_id="obs:test:1",
        engagement_id=ENGAGEMENT,
        scanner="nuclei",
        kind=ObservationKind.VULN_CANDIDATE,
        subject="http://172.20.1.10:80/",
        attributes={**base, **attrs},
        artifact_id="sha256:test",
        observed_at=DETECTED,
        provenance=Provenance(
            source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=DETECTED
        ),
    )


def _single(attrs: dict[str, str]) -> AttackGraphResult:
    obs = [_vuln_obs(attrs)]
    return analyze(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=findings_from_observations(obs, DETECTED),
        topology=_topology(),
    )


def test_cwe_alone_gives_medium_confidence() -> None:
    res = _single({"cwe_ids": "CWE-22"})
    (edge,) = [e for e in res.edges if e.rule_name == "exploit_grants_file_read"]
    assert edge.confidence == Confidence.MEDIUM


def test_free_text_is_never_read() -> None:
    res = _single({"description": "remote code execution, rce, full compromise"})
    assert not [e for e in res.edges if e.rule_name.startswith("exploit_")]
    assert len(res.unclassified_findings) == 1


# ------------------------------------------------------------------- chokepoints & simulation


def test_chokepoint_counts_match_the_paths_that_use_the_finding(
    result: AttackGraphResult,
) -> None:
    for cp in result.chokepoints:
        expected = [
            p.path_id for p in result.paths if any(cp.finding_id in e.finding_ids for e in p.edges)
        ]
        assert cp.paths_broken == expected
    ranks = [cp.rank for cp in result.chokepoints]
    assert ranks == list(range(1, len(ranks) + 1))


def test_fixing_the_gateway_rce_cuts_the_gateway(
    facts: tuple[list[Observation], list[Finding]], result: AttackGraphResult
) -> None:
    obs, fnd = facts
    gateway = _finding_for(fnd, "CVE-2022-22947")
    cp = next(c for c in result.chokepoints if c.finding_id == gateway.finding_id)
    assert "exec:spring-gateway" in cp.goals_cut

    sim = simulate_remediation(
        baseline=result,
        fixed_finding_ids=[gateway.finding_id],
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(),
    )
    assert sorted(sim.removed_path_ids) == sorted(cp.paths_broken)
    assert sim.remaining_path_count == sim.baseline_path_count - len(cp.paths_broken)
    assert "exec:spring-gateway" in sim.goals_no_longer_reachable
    for path in sim.after.paths:
        assert all(gateway.finding_id not in e.finding_ids for e in path.edges)


def test_fixing_every_entry_point_leaves_no_paths(
    facts: tuple[list[Observation], list[Finding]], result: AttackGraphResult
) -> None:
    obs, fnd = facts
    entry_findings = [
        _finding_for(fnd, "CVE-2022-22947").finding_id,
        _finding_for(fnd, "CVE-2021-23017").finding_id,
    ]
    sim = simulate_remediation(
        baseline=result,
        fixed_finding_ids=entry_findings,
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(),
    )
    assert sim.remaining_path_count == 0


# ------------------------------------------------------------------- topology semantics


def test_without_intra_zone_reach_or_flows_nothing_moves_laterally(
    facts: tuple[list[Observation], list[Finding]],
) -> None:
    obs, fnd = facts
    res = analyze(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(intra_zone_reachable=False),
    )
    assert {p.goal_node for p in res.paths} == {"exec:spring-gateway", "exec:dmz-proxy"}


def test_declared_flow_respects_its_ports(
    facts: tuple[list[Observation], list[Finding]],
) -> None:
    obs, fnd = facts
    flows = [{"from_zone": "dmz", "to_zone": "data", "ports": [5432]}]
    res = analyze(
        engagement_id=ENGAGEMENT,
        observations=obs,
        findings=fnd,
        topology=_topology(intra_zone_reachable=False, flows=flows),
    )
    flow_edges = [e for e in res.edges if e.rule_name == "declared_flow_service_access"]
    assert flow_edges
    assert {e.to_node for e in flow_edges} == {"access:172.20.3.10:5432/tcp"}


def test_topology_must_declare_an_entry_zone() -> None:
    raw = yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    for zone in raw["zones"]:
        zone["attacker_entry"] = False
    with pytest.raises(ValidationError, match="attacker_entry"):
        NetworkTopology.model_validate(raw)


def test_topology_rejects_flows_to_unknown_zones() -> None:
    with pytest.raises(ValidationError, match="unknown zone"):
        _topology(flows=[{"from_zone": "dmz", "to_zone": "moon"}])


def test_topology_id_changes_with_content() -> None:
    assert _topology().topology_id != _topology(intra_zone_reachable=False).topology_id
    assert _topology().topology_id == _topology().topology_id


def test_facts_from_another_engagement_are_rejected(
    facts: tuple[list[Observation], list[Finding]],
) -> None:
    obs, fnd = facts
    with pytest.raises(ValueError, match="engagement"):
        analyze(
            engagement_id="eng-other",
            observations=obs,
            findings=fnd,
            topology=_topology(engagement_id="eng-other"),
        )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("172.20.1.10:80/tcp", ("172.20.1.10", 80, "tcp")),
        ("[2001:db8::10]:443/tcp", ("2001:db8::10", 443, "tcp")),
        ("2001:db8::10:443/tcp", ("2001:db8::10", 443, "tcp")),
        ("http://172.20.1.13:8080/actuator", ("172.20.1.13", 8080, "tcp")),
        ("https://172.20.1.13/", ("172.20.1.13", 443, "tcp")),
        ("http://dvwa.lab.local/", None),
        ("unknown", None),
    ],
)
def test_parse_endpoint(text: str, expected: tuple[str, int, str] | None) -> None:
    assert parse_endpoint(text) == expected
