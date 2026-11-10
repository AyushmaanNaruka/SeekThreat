"""Unit tests for the engagement report builder and renderers (services/report, D-049).

Inputs are the lab observation fixtures, the findings the interim bridge derives from
them, lab/topology.yaml and the real graph engine, so the report covers real paths,
chokepoints and a real remediation simulation. Every timestamp is fixed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from packages.schema.models.assistant import GroundingCheck, PathNarration
from packages.schema.models.citation import Citation
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import AttackGraphResult, SimulationResult
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent
from packages.schema.models.topology import NetworkTopology
from services.graph import analyze, simulate_remediation
from services.normalize import findings_from_observations
from services.report import (
    ReportInputError,
    ScanRecord,
    build_report,
    render_json,
    render_markdown,
)
from services.report.models import NARRATION_LABEL, EngagementReport

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "observations"
LAB_TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"

ENGAGEMENT_ID = "eng-lab-baseline"
T0 = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)
GENERATED_AT = datetime(2026, 11, 10, 9, 30, 0, tzinfo=UTC)
SPRING_GATEWAY_CVE = "CVE-2022-22947"


def _observations() -> tuple[list[Observation], list[str]]:
    observations: list[Observation] = []
    artifacts: list[str] = []
    for path in sorted(FIXTURES.glob("*.json")):
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        observations.extend(result.observations)
        artifacts.append(result.artifact.artifact_id)
    return observations, artifacts


def _score() -> ExposureRiskScore:
    prov = Provenance(source=Source.EPSS, confidence=Confidence.HIGH, retrieved_at=T0)
    kev = Provenance(source=Source.KEV, confidence=Confidence.HIGH, retrieved_at=T0)
    components = (
        ScoreComponent(
            name="epss", value=0.5, weight=0.4, explanation="EPSS 0.5 from feed", provenance=prov
        ),
        ScoreComponent(
            name="kev_listed", value=1.0, weight=0.3, explanation="Listed in KEV", provenance=kev
        ),
    )
    return ExposureRiskScore(value=0.5 * 0.4 + 1.0 * 0.3, components=components)


def _enriched(findings: list[Finding]) -> list[EnrichedFinding]:
    """The Spring Gateway finding is scored and carries an attributed field; the rest
    are stored unscored, as the interim bridge leaves them."""
    out: list[EnrichedFinding] = []
    for f in findings:
        if SPRING_GATEWAY_CVE in f.cve_ids:
            field = Attributed[Any](
                value=True,
                provenance=Provenance(
                    source=Source.KEV, confidence=Confidence.HIGH, retrieved_at=T0
                ),
            )
            out.append(EnrichedFinding(finding=f, fields={"kev_listed": field}, ers=_score()))
        else:
            out.append(EnrichedFinding(finding=f))
    return out


def _engagement(engagement_id: str = ENGAGEMENT_ID) -> Engagement:
    return Engagement(
        engagement_id=engagement_id,
        name="Lab engagement",
        authorization=Authorization(
            engagement_id=engagement_id,
            authorized_by="lab-operator",
            allowlist=("172.20.0.0/16",),
            granted_at=T0,
            expires_at=T0 + timedelta(days=30),
        ),
        created_at=T0,
    )


def _topology() -> NetworkTopology:
    document = yaml.safe_load(LAB_TOPOLOGY.read_text(encoding="utf-8"))
    document["engagement_id"] = ENGAGEMENT_ID
    return NetworkTopology.model_validate(document)


class Lab:
    def __init__(self) -> None:
        self.observations, artifacts = _observations()
        findings = findings_from_observations(self.observations, detected_at=T0)
        self.enriched = _enriched(findings)
        self.topology = _topology()
        self.scans = [
            ScanRecord(
                scan_id=f"scan-{i}",
                scanner="nmap",
                target="172.20.0.0/24",
                status="completed",
                artifact_id=artifact_id,
                created_at=T0 + timedelta(minutes=i),
                completed_at=T0 + timedelta(minutes=i, seconds=30),
            )
            for i, artifact_id in enumerate(artifacts)
        ]
        self.common: dict[str, Any] = {
            "engagement_id": ENGAGEMENT_ID,
            "observations": self.observations,
            "findings": [e.finding for e in self.enriched],
            "topology": self.topology,
            "enriched": self.enriched,
        }
        self.graph: AttackGraphResult = analyze(**self.common)
        top = min(self.graph.chokepoints, key=lambda c: c.rank)
        self.top_finding_id = top.finding_id
        self.simulation: SimulationResult = simulate_remediation(
            baseline=self.graph, fixed_finding_ids=[top.finding_id], **self.common
        )

    def build(self, **overrides: Any) -> EngagementReport:
        kwargs: dict[str, Any] = {
            "engagement": _engagement(),
            "scans": self.scans,
            "observations": self.observations,
            "enriched": self.enriched,
            "topology": self.topology,
            "graph": self.graph,
            "simulation": self.simulation,
            "generated_at": GENERATED_AT,
        }
        kwargs.update(overrides)
        return build_report(**kwargs)


@pytest.fixture(scope="module")
def lab() -> Lab:
    return Lab()


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_input_gives_identical_bytes(self, lab: Lab) -> None:
        first, second = lab.build(), lab.build()
        assert render_markdown(first).encode() == render_markdown(second).encode()
        assert render_json(first).encode() == render_json(second).encode()

    def test_input_order_does_not_matter(self, lab: Lab) -> None:
        shuffled = lab.build(
            observations=list(reversed(lab.observations)),
            enriched=list(reversed(lab.enriched)),
            scans=list(reversed(lab.scans)),
        )
        assert render_markdown(shuffled) == render_markdown(lab.build())
        assert render_json(shuffled) == render_json(lab.build())

    def test_generated_at_is_the_only_clock(self, lab: Lab) -> None:
        later = lab.build(generated_at=GENERATED_AT + timedelta(days=1))
        a = json.loads(render_json(lab.build()))
        b = json.loads(render_json(later))
        assert a.pop("generated_at") != b.pop("generated_at")
        assert a == b

    def test_naive_generated_at_is_rejected(self, lab: Lab) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            lab.build(generated_at=datetime(2026, 11, 10, 9, 30))

    def test_json_is_the_report_model(self, lab: Lab) -> None:
        report = lab.build()
        assert EngagementReport.model_validate_json(render_json(report)) == report


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


class TestContent:
    def test_engagement_and_authorization_reference(self, lab: Lab) -> None:
        report = lab.build()
        md = render_markdown(report)
        assert report.engagement.authorization.authorization_reference == ENGAGEMENT_ID
        assert "| Authorized by | lab-operator |" in md
        assert "`172.20.0.0/16`" in md

    def test_scan_inventory_counts_observations_per_artifact(self, lab: Lab) -> None:
        report = lab.build()
        assert [s.scan_id for s in report.scans] == [s.scan_id for s in lab.scans]
        assert sum(s.observation_count for s in report.scans) == len(lab.observations)

    def test_assets_carry_scanner_source_and_confidence(self, lab: Lab) -> None:
        report = lab.build()
        assets = {a.address: a for a in report.assets}
        gateway = assets["172.20.1.13"]
        assert gateway.hostnames == ("lab-spring-gateway-1.lab_dmz",)
        (svc,) = gateway.services
        assert svc.endpoint == "172.20.1.13:8080/tcp"
        assert svc.products == ("spring-cloud-gateway",)
        assert svc.attributions and all(a.source == Source.SCANNER for a in svc.attributions)
        assert svc.observation_ids

    def test_missing_score_renders_not_scored_never_zero(self, lab: Lab) -> None:
        report = lab.build()
        unscored = [f for f in report.findings if f.ers is None]
        assert unscored
        assert all(f.ers_status == "not scored" for f in unscored)
        md = render_markdown(report)
        assert "**Exposure Risk Score: not scored.**" in md
        assert md.count("**Exposure Risk Score: not scored.**") == len(unscored)
        assert "Exposure Risk Score: 0.00" not in md
        data = json.loads(render_json(report))
        for f in data["findings"]:
            if f["ers_status"] == "not scored":
                assert f["ers"] is None

    def test_scored_finding_renders_components_and_explanation(self, lab: Lab) -> None:
        report = lab.build()
        first = report.findings[0]
        assert SPRING_GATEWAY_CVE in first.cve_ids, "scored findings sort first"
        assert first.ers is not None
        assert first.ers.value == pytest.approx(0.5)
        assert [c.name for c in first.ers.components] == ["epss", "kev_listed"]
        assert first.ers.components[0].contribution == pytest.approx(0.2)
        assert first.ers.explanation.startswith("Exposure Risk Score: 0.50")
        md = render_markdown(report)
        assert "**Exposure Risk Score: 0.50**" in md
        assert "| epss | 0.50 | 0.40 | 0.20 | EPSS 0.5 from feed | first.epss | high |" in md
        (field,) = first.fields
        assert (field.name, field.source, field.confidence) == (
            "kev_listed",
            Source.KEV,
            Confidence.HIGH,
        )
        assert "| kev_listed | true | cisa.kev | high |" in md

    def test_paths_in_rank_order_with_rule_and_evidence(self, lab: Lab) -> None:
        report = lab.build()
        graph = report.attack_graph
        assert graph is not None
        assert [p.rank for p in graph.paths] == list(range(1, len(graph.paths) + 1))
        engine_edges = {
            p.path_id: [(e.rule_name, e.evidence) for e in p.edges] for p in lab.graph.paths
        }
        for path in graph.paths:
            assert [(s.rule_name, s.evidence) for s in path.steps] == engine_edges[path.path_id]
        md = render_markdown(report)
        top = graph.paths[0]
        assert f"`{top.steps[0].rule_name}`" in md
        assert md.index("### Rank 1:") < md.index("### Rank 2:")

    def test_report_adds_no_edge(self, lab: Lab) -> None:
        report = lab.build()
        assert report.attack_graph is not None
        report_edges = {s.edge_id for p in report.attack_graph.paths for s in p.steps}
        assert report_edges <= {e.edge_id for e in lab.graph.edges}
        assert len(report.attack_graph.paths) == len(lab.graph.paths)

    def test_chokepoints_and_top_simulation(self, lab: Lab) -> None:
        report = lab.build()
        assert report.attack_graph is not None
        assert report.attack_graph.chokepoints[0].finding_id == lab.top_finding_id
        sim = report.simulation
        assert sim is not None
        assert sim.fixed_finding_ids == (lab.top_finding_id,)
        assert sim.baseline_path_count == lab.simulation.baseline_path_count
        assert sim.remaining_path_count == lab.simulation.remaining_path_count
        assert "## 7. Remediation simulation (top chokepoint)" in render_markdown(report)

    def test_simulation_of_another_finding_is_rejected(self, lab: Lab) -> None:
        other = next(c for c in lab.graph.chokepoints if c.finding_id != lab.top_finding_id)
        wrong = simulate_remediation(
            baseline=lab.graph, fixed_finding_ids=[other.finding_id], **lab.common
        )
        with pytest.raises(ReportInputError, match="top chokepoint"):
            lab.build(simulation=wrong)

    def test_every_cited_evidence_id_is_in_the_appendix(self, lab: Lab) -> None:
        report = lab.build()
        assert report.attack_graph is not None
        appendix = {e.evidence_id: e for e in report.evidence}
        cited = {ref for p in report.attack_graph.paths for s in p.steps for ref in s.evidence}
        cited |= {oid for f in report.findings for oid in f.observation_ids}
        assert cited <= set(appendix)
        assert all(e.kind != "unresolved" for e in report.evidence)
        assert appendix[lab.topology.topology_id].kind == "topology"

    def test_limitations_always_listed(self, lab: Lab) -> None:
        report = lab.build()
        assert any("not scored" in n for n in report.limitations)
        assert any("No accuracy, recall or false-positive metric" in n for n in report.limitations)


# ---------------------------------------------------------------------------
# Missing graph, narrations, bad input
# ---------------------------------------------------------------------------


class TestEdges:
    def test_no_graph_renders_reason(self, lab: Lab) -> None:
        report = lab.build(
            topology=None, graph=None, simulation=None, attack_graph_unavailable="no topology"
        )
        assert report.attack_graph is None
        assert report.simulation is None
        md = render_markdown(report)
        assert "Not built: no topology" in md
        assert "Not run: no attack graph was built." in md
        assert all(f.on_path_ids == () for f in report.findings)

    def test_no_graph_without_reason_is_rejected(self, lab: Lab) -> None:
        with pytest.raises(ReportInputError, match="no reason"):
            lab.build(topology=None, graph=None, simulation=None)

    def test_records_from_another_engagement_are_rejected(self, lab: Lab) -> None:
        with pytest.raises(ReportInputError, match="do not belong"):
            lab.build(engagement=_engagement("eng-other"))

    def test_narration_is_attached_and_labelled(self, lab: Lab) -> None:
        path = lab.graph.paths[0]
        narration = PathNarration(
            path_id=path.path_id,
            engagement_id=ENGAGEMENT_ID,
            text="The attacker reaches the gateway <b>and</b> runs code.",
            citations=(Citation(kind="path", ref_id=path.path_id),),
            grounding=GroundingCheck(),
            model="test-model",
        )
        report = lab.build(narrations=[narration])
        assert report.attack_graph is not None
        entry = next(p for p in report.attack_graph.paths if p.path_id == path.path_id)
        assert entry.narration is not None
        assert entry.narration.label == NARRATION_LABEL
        assert entry.narration.model == "test-model"
        # Narration changes nothing about the proven steps.
        plain = lab.build()
        assert plain.attack_graph is not None
        plain_entry = next(p for p in plain.attack_graph.paths if p.path_id == path.path_id)
        assert entry.steps == plain_entry.steps
        md = render_markdown(report)
        assert "**Model-generated narration** (test-model)." in md
        assert "&lt;b&gt;and&lt;/b&gt;" in md

    def test_narration_of_unknown_path_is_rejected(self, lab: Lab) -> None:
        narration = PathNarration(
            path_id="path:not-in-graph", engagement_id=ENGAGEMENT_ID, text="x", model="m"
        )
        with pytest.raises(ReportInputError, match="not in this graph"):
            lab.build(narrations=[narration])

    def test_scanner_text_is_escaped_in_markdown(self, lab: Lab) -> None:
        obs = lab.observations[0]
        hostile = Finding(
            finding_id="fnd-hostile",
            engagement_id=ENGAGEMENT_ID,
            asset_id="host:172.20.1.10",
            scanner="nuclei",
            title="evil | <script>alert(1)</script>\n# heading",
            observation_ids=[obs.observation_id],
            detected_at=T0,
        )
        report = lab.build(
            enriched=[*lab.enriched, EnrichedFinding(finding=hostile)],
            graph=None,
            topology=None,
            simulation=None,
            attack_graph_unavailable="not needed here",
        )
        md = render_markdown(report)
        assert "<script>" not in md
        assert "evil \\| &lt;script&gt;alert(1)&lt;/script&gt; \\# heading" in md
