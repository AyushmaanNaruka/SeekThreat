"""Track 1 normalizer wired into the enrichment and graph pipeline (D-045 proposed).

Checks that:
- the scan task feeds enrichment with normalised, deduplicated findings, using the
  engagement's stored observations as context;
- a CVE reported by two scanners becomes one finding (both observation ids kept) and the
  graph built from it is the same graph a single report gives, apart from evidence;
- the graph stays deterministic over normalised findings, whatever the input order.

Built on tests/fixtures/observations/ and lab/topology.yaml. No scanning, no network.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from apps.api.tasks import scans as scans_task
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.provenance import Confidence, Provenance, Source
from packages.schema.models.topology import NetworkTopology
from services.graph.engine import analyze
from services.normalize import normalize_observations

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONFLUENCE_CVE = "CVE-2022-26134"


def _observations() -> list[Observation]:
    out: list[Observation] = []
    for path in sorted((ROOT / "tests/fixtures/observations").glob("*.json")):
        out.extend(ScanResult.model_validate_json(path.read_text(encoding="utf-8")).observations)
    return out


def _topology() -> NetworkTopology:
    raw = yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    return NetworkTopology.model_validate(raw)


def _second_scanner_report(observations: list[Observation]) -> Observation:
    """The fixture's Confluence CVE as a second scanner would report it."""
    [original] = [o for o in observations if o.attributes.get("cve_ids") == CONFLUENCE_CVE]
    return original.model_copy(
        update={
            "observation_id": "obs:test:second-scanner-confluence",
            "scanner": "nikto",
            "attributes": {
                "endpoint": original.attributes["endpoint"],
                "cve_ids": CONFLUENCE_CVE.lower(),
            },
            "provenance": Provenance(
                source=Source.SCANNER, confidence=Confidence.MEDIUM, retrieved_at=NOW
            ),
        }
    )


def _analyze(observations: list[Observation], topology: NetworkTopology) -> Any:
    findings = normalize_observations(observations, NOW).findings
    return analyze(
        engagement_id=topology.engagement_id,
        observations=observations,
        findings=findings,
        topology=topology,
    )


def _steps(result: Any) -> list[tuple[tuple[str, str, str, tuple[str, ...]], ...]]:
    """Each path as its steps, evidence left out."""
    return sorted(
        tuple((e.from_node, e.to_node, e.rule_name, e.finding_ids) for e in p.edges)
        for p in result.paths
    )


# --------------------------------------------------------------------------- graph


def test_cross_scanner_duplicate_is_one_finding_and_one_graph() -> None:
    topology = _topology()
    base_obs = _observations()
    extra = _second_scanner_report(base_obs)
    dup_obs = [*base_obs, extra]

    base_findings = normalize_observations(base_obs, NOW).findings
    dup_findings = normalize_observations(dup_obs, NOW).findings
    assert len(dup_findings) == len(base_findings)

    [merged] = [f for f in dup_findings if CONFLUENCE_CVE in f.cve_ids]
    [original] = [f for f in base_findings if CONFLUENCE_CVE in f.cve_ids]
    # The merge key, not the observation, names the finding, so the id is unchanged.
    assert merged.finding_id == original.finding_id
    assert extra.observation_id in merged.observation_ids
    assert set(original.observation_ids) < set(merged.observation_ids)
    assert "nikto" in merged.scanner.split(",")

    base = _analyze(base_obs, topology)
    dup = _analyze(dup_obs, topology)
    # Same steps, same chokepoints: a repeated report adds evidence, not attack steps.
    # (Path ids hash the evidence too, so they change; the steps must not.)
    assert _steps(dup) == _steps(base)
    assert [c.finding_id for c in dup.chokepoints] == [c.finding_id for c in base.chokepoints]
    merged_edges = [e for p in dup.paths for e in p.edges if merged.finding_id in e.finding_ids]
    assert merged_edges
    # Every contributing observation is cited on the step the merged finding enables.
    for edge in merged_edges:
        assert set(merged.observation_ids) <= set(edge.evidence)
    edge_findings = {fid for p in dup.paths for e in p.edges for fid in e.finding_ids}
    assert merged.finding_id in edge_findings
    assert edge_findings <= {f.finding_id for f in dup_findings}


def test_graph_over_normalised_findings_is_input_order_independent() -> None:
    topology = _topology()
    observations = [*_observations(), _second_scanner_report(_observations())]
    forward = _analyze(observations, topology)
    backward = _analyze(list(reversed(observations)), topology)
    assert forward.model_dump(mode="json") == backward.model_dump(mode="json")


# --------------------------------------------------------------------------- scan task


class _FakeObservationRepository:
    stored: list[Observation] = []

    def __init__(self, _db: Any) -> None:
        pass

    def get_by_engagement(self, _engagement_id: str) -> list[Observation]:
        return list(self.stored)


class _FakeDB:
    rolled_back = False

    def rollback(self) -> None:
        self.rolled_back = True


def test_scan_task_enqueues_deduplicated_findings_with_engagement_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.api.tasks import enrichment  # noqa: PLC0415

    stored = _observations()
    new_scan = (_second_scanner_report(stored),)
    _FakeObservationRepository.stored = stored
    monkeypatch.setattr(scans_task, "ObservationRepository", _FakeObservationRepository)
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        enrichment.enrich_findings,
        "apply_async",
        lambda kwargs, retry: sent.append(kwargs),
    )

    count = scans_task._dispatch_interim_findings(
        new_scan,
        engagement_id=stored[0].engagement_id,
        scan_id="scan-test",
        actor="tester",
        db=_FakeDB(),  # type: ignore[arg-type]
    )

    # Only the finding the new scan touched is enqueued, already merged with the
    # stored nuclei report of the same CVE.
    assert count == 1
    [payload] = sent
    [finding] = payload["findings_data"]
    assert finding["cve_ids"] == [CONFLUENCE_CVE]
    assert new_scan[0].observation_id in finding["observation_ids"]
    assert len(finding["observation_ids"]) == 2
    assert finding["scanner"] == "nikto,nuclei"


def test_scan_task_falls_back_to_scan_alone_when_context_load_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.api.tasks import enrichment  # noqa: PLC0415

    class _Broken(_FakeObservationRepository):
        def get_by_engagement(self, _engagement_id: str) -> list[Observation]:
            raise RuntimeError("db down")

    monkeypatch.setattr(scans_task, "ObservationRepository", _Broken)
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        enrichment.enrich_findings,
        "apply_async",
        lambda kwargs, retry: sent.append(kwargs),
    )
    db = _FakeDB()
    new_scan = (_second_scanner_report(_observations()),)

    count = scans_task._dispatch_interim_findings(
        new_scan,
        engagement_id=new_scan[0].engagement_id,
        scan_id="scan-test",
        actor="tester",
        db=db,  # type: ignore[arg-type]
    )

    assert db.rolled_back
    assert count == 1
    [finding] = sent[0]["findings_data"]
    assert finding["observation_ids"] == [new_scan[0].observation_id]
