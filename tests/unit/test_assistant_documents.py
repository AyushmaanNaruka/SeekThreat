"""Layer 4 document builders: deterministic, one fact per document, engagement-scoped.

Fixtures: tests/fixtures/observations/*.json and lab/topology.yaml. The attack graph is
built with services.graph here, in the TEST only; services/assistant never imports it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

from packages.schema.models.assistant import AssistantDocument
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.graph import AttackGraphResult
from packages.schema.models.observation import Observation
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent
from packages.schema.models.topology import NetworkTopology
from services.assistant.documents import (
    chokepoint_document,
    documents_for_engagement,
    enriched_finding_document,
    observation_document,
    path_document,
    topology_document,
)
from services.graph import analyze
from services.normalize.interim_bridge import findings_from_observations

ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENT = "eng-lab-baseline"
DETECTED = datetime(2026, 9, 20, tzinfo=UTC)
RETRIEVED = datetime(2026, 9, 21, tzinfo=UTC)


@lru_cache(maxsize=1)
def lab_observations() -> tuple[Observation, ...]:
    out: list[Observation] = []
    for path in sorted((ROOT / "tests/fixtures/observations").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        out.extend(Observation.model_validate(o) for o in data["observations"])
    return tuple(out)


@lru_cache(maxsize=1)
def lab_findings() -> tuple[Finding, ...]:
    return tuple(findings_from_observations(lab_observations(), DETECTED))


@lru_cache(maxsize=1)
def lab_topology() -> NetworkTopology:
    raw = yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    return NetworkTopology.model_validate(raw)


@lru_cache(maxsize=1)
def lab_graph() -> AttackGraphResult:
    return analyze(
        engagement_id=ENGAGEMENT,
        observations=lab_observations(),
        findings=lab_findings(),
        topology=lab_topology(),
    )


def enriched(finding: Finding) -> EnrichedFinding:
    """A test enrichment record. The values are test inputs, not measurements."""

    def prov(source: Source) -> Provenance:
        return Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=RETRIEVED)

    fields: dict[str, Attributed[EnrichmentValue]] = {
        "cvss_score": Attributed[EnrichmentValue](value=9.8, provenance=prov(Source.CVE_ORG)),
        "in_kev": Attributed[EnrichmentValue](value=True, provenance=prov(Source.KEV)),
        "epss_score": Attributed[EnrichmentValue](value=0.5, provenance=prov(Source.EPSS)),
    }
    component = ScoreComponent(
        name="severity",
        value=4.0,
        weight=1.0,
        explanation="test component: severity input",
        provenance=prov(Source.DERIVED),
    )
    return EnrichedFinding(
        finding=finding,
        fields=fields,
        ers=ExposureRiskScore(value=4.0, components=(component,)),
    )


def lab_documents() -> list[AssistantDocument]:
    return documents_for_engagement(
        engagement_id=ENGAGEMENT,
        observations=lab_observations(),
        enriched_findings=[enriched(f) for f in lab_findings()],
        graph=lab_graph(),
        topology=lab_topology(),
    )


# ------------------------------------------------------------------------------ tests


def test_documents_are_deterministic_sorted_and_unique() -> None:
    first = lab_documents()
    second = lab_documents()
    assert [d.model_dump_json() for d in first] == [d.model_dump_json() for d in second]
    ids = [d.doc_id for d in first]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    # Duplicated input collapses to one document per id.
    doubled = documents_for_engagement(
        engagement_id=ENGAGEMENT, observations=[*lab_observations(), *lab_observations()]
    )
    assert len(doubled) == len({o.observation_id for o in lab_observations()})


def test_every_kind_is_present_with_the_expected_ids() -> None:
    docs = {d.doc_id: d for d in lab_documents()}
    graph = lab_graph()
    for obs in lab_observations():
        assert docs[obs.observation_id].kind == "observation"
    for f in lab_findings():
        assert docs[f"finding:{f.finding_id}"].kind == "finding"
    for p in graph.paths:
        assert docs[p.path_id].kind == "path"
    for cp in graph.chokepoints:
        assert docs[f"chokepoint:{cp.finding_id}"].kind == "finding"
    assert docs[lab_topology().topology_id].kind == "topology"
    assert all(d.engagement_id == ENGAGEMENT for d in docs.values())


def test_path_evidence_ids_resolve_to_documents() -> None:
    """Every evidence id a path edge cites is itself a citable document."""
    docs = {d.doc_id for d in lab_documents()}
    for path in lab_graph().paths:
        for edge in path.edges:
            for ref in edge.evidence:
                assert ref in docs, ref


def test_observation_document_carries_salient_attributes() -> None:
    obs = next(o for o in lab_observations() if o.attributes.get("template_name"))
    doc = observation_document(obs)
    assert doc.doc_id == obs.observation_id
    assert obs.scanner in doc.text
    assert obs.kind.value in doc.text
    assert obs.subject in doc.text
    assert obs.attributes["template_name"] in doc.text
    assert obs.observed_at.isoformat() in doc.text


def test_finding_document_attributes_every_field_and_explains_ers() -> None:
    finding = next(f for f in lab_findings() if f.cve_ids)
    doc = enriched_finding_document(enriched(finding))
    assert doc.doc_id == f"finding:{finding.finding_id}"
    assert finding.asset_id in doc.text
    assert finding.cve_ids[0] in doc.text
    assert "CVSS 9.8 (cve.org, high confidence)" in doc.text
    assert "In CISA KEV yes (cisa.kev" in doc.text
    assert "EPSS 0.5 (first.epss" in doc.text
    assert "Exposure Risk Score: 4.00" in doc.text
    assert "test component: severity input" in doc.text


def test_unscored_finding_says_so() -> None:
    finding = lab_findings()[0]
    doc = enriched_finding_document(EnrichedFinding(finding=finding))
    assert "Exposure Risk Score: not scored." in doc.text
    assert "Enrichment: none recorded." in doc.text


def test_path_document_renders_every_step_with_rule_and_evidence() -> None:
    graph = lab_graph()
    path = graph.paths[0]
    doc = path_document(path, graph.nodes, ENGAGEMENT)
    assert doc.doc_id == path.path_id and doc.kind == "path"
    assert path.rank_explanation and path.rank_explanation in doc.text
    labels = {n.node_id: n.label for n in graph.nodes}
    for n, edge in enumerate(path.edges, start=1):
        line = (
            f"Step {n}: {labels[edge.from_node]} -[{edge.rule_name}, "
            f"{edge.confidence.value}]-> {labels[edge.to_node]}: {edge.description}"
        )
        assert line in doc.text
        for ref in edge.evidence:
            assert ref in doc.text


def test_assumption_steps_are_marked() -> None:
    graph = lab_graph()
    path = next(
        p
        for p in graph.paths
        if any(e.rule_name == "credential_reuse_remote_login" for e in p.edges)
    )
    doc = path_document(path, graph.nodes, ENGAGEMENT)
    assert "Assumed, not observed" in doc.text
    assert "ASSUMPTION." in doc.text


def test_chokepoint_and_topology_documents() -> None:
    cp = lab_graph().chokepoints[0]
    doc = chokepoint_document(cp, ENGAGEMENT)
    assert doc.doc_id == f"chokepoint:{cp.finding_id}"
    assert f"breaks {len(cp.paths_broken)} of the enumerated attack paths" in doc.text
    assert cp.remediation in doc.text

    topo = topology_document(lab_topology())
    assert topo.doc_id == lab_topology().topology_id
    for zone in lab_topology().zones:
        assert zone.name in topo.text
        for cidr in zone.cidrs:
            assert cidr in topo.text


def test_records_from_another_engagement_are_rejected() -> None:
    obs = lab_observations()[0].model_copy(update={"engagement_id": "eng-other"})
    with pytest.raises(ValueError, match="eng-other"):
        documents_for_engagement(engagement_id=ENGAGEMENT, observations=[obs])
