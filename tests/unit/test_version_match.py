"""Version-match CVE candidates (services/normalize/version_match.py, DECISIONS.md D-049).

Covers the matcher itself and what it changes in the graph: a nmap-only scan of the lab
(no nuclei vuln_candidates) yields attack paths once version-matched findings carry
enriched CWE ids, every such edge is LOW, and without CWE ids nothing is invented.
No scanning, no network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import NodeKind
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.topology import NetworkTopology
from services.graph import analyze, load_ruleset
from services.normalize.version_match import (
    RULES_PATH,
    VERSION_MATCH_SCANNER,
    load_version_rules,
    match_observation,
    parse_version,
    version_match_cve_ids,
    version_match_findings,
)

ROOT = Path(__file__).resolve().parents[2]
DETECTED = datetime(2026, 9, 20, tzinfo=UTC)
NMAP_FIXTURES = ("lab_baseline.json", "lab_dmz_extended.json", "lab_internal.json", "lab_data.json")


def _nmap_observations() -> list[Observation]:
    out: list[Observation] = []
    for name in NMAP_FIXTURES:
        data = json.loads((ROOT / "tests/fixtures/observations" / name).read_text("utf-8"))
        out.extend(Observation.model_validate(o) for o in data["observations"])
    return out


def _topology() -> NetworkTopology:
    raw = yaml.safe_load((ROOT / "lab/topology.yaml").read_text(encoding="utf-8"))
    return NetworkTopology.model_validate(raw)


def _svc(
    product: str = "Apache httpd",
    version: str = "2.4.49",
    *,
    confidence: Confidence = Confidence.HIGH,
    cpe: str | None = None,
    subject: str = "172.20.1.10:80/tcp",
    obs_id: str = "obs:svc-1",
) -> Observation:
    attrs = {"service_name": "http", "product": product, "version": version, "conf": "10"}
    if cpe:
        attrs["cpe"] = cpe
    return Observation(
        observation_id=obs_id,
        engagement_id="eng-lab-baseline",
        scanner="nmap",
        kind=ObservationKind.SERVICE_VERSION,
        subject=subject,
        attributes=attrs,
        artifact_id="sha256:test",
        observed_at=DETECTED,
        provenance=Provenance(source=Source.SCANNER, confidence=confidence, retrieved_at=DETECTED),
    )


def _cves(obs: Observation) -> list[str]:
    return [m.rule.cve for m in match_observation(obs, load_version_rules())]


# ------------------------------------------------------------------- rule data


def test_rule_file_loads_and_every_rule_cites_a_reference() -> None:
    rules = load_version_rules()
    assert rules.rules
    assert rules.digest.startswith("version-rules:sha256:")
    for rule in rules.rules:
        assert rule.reference.startswith("https://"), rule.rule_id
        assert rule.affected, rule.rule_id


def test_rule_digest_ignores_line_endings(tmp_path: Path) -> None:
    crlf = tmp_path / "rules.yaml"
    crlf.write_bytes(RULES_PATH.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert load_version_rules(crlf).digest == load_version_rules().digest


def test_rule_with_inverted_interval_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\nrules:\n  - id: x\n    cve: CVE-2021-0001\n    products: [p]\n"
        "    affected: [{introduced: '2.0', fixed: '1.0'}]\n    reference: https://e\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="bad interval"):
        load_version_rules(bad)


def test_documented_exclusions_are_not_matched() -> None:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    excluded = {e["cve"] for e in raw["not_matched"]}
    assert excluded == {"CVE-2022-0543", "CVE-2020-15778", "CVE-2020-14349"}
    assert not excluded & {r.cve for r in load_version_rules().rules}


# ------------------------------------------------------------------- matching


def test_parse_version_accepts_only_numeric_dotted() -> None:
    assert parse_version("2.4.49") == (2, 4, 49)
    for text in ("8.3p1", "2.4.x", "1.18.0-alpine", "", "v2.0"):
        assert parse_version(text) is None


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.4.48", []),
        ("2.4.49", ["CVE-2021-41773", "CVE-2021-42013"]),
        ("2.4.50", ["CVE-2021-42013"]),
        ("2.4.51", []),
        ("2.4.25", []),
    ],
)
def test_interval_bounds_are_half_open(version: str, expected: list[str]) -> None:
    assert _cves(_svc(version=version)) == expected


@pytest.mark.parametrize(
    ("version", "vulnerable"),
    [("2.426.2", True), ("2.426.3", False), ("2.441", True), ("2.442", False)],
)
def test_multi_interval_rule_respects_each_fixed_line(version: str, vulnerable: bool) -> None:
    assert (_cves(_svc("jenkins", version)) == ["CVE-2024-23897"]) is vulnerable


def test_cpe_matches_when_product_string_does_not() -> None:
    obs = _svc("httpd-ish", "2.4.49", cpe="cpe:/a:apache:http_server:2.4.49")
    matches = match_observation(obs, load_version_rules())
    assert [m.matched_on for m in matches] == ["cpe", "cpe"]


def test_low_confidence_or_non_numeric_versions_are_not_matched() -> None:
    assert _cves(_svc(confidence=Confidence.LOW)) == []
    assert _cves(_svc(version="2.4.49-debian")) == []


def test_only_service_version_observations_are_considered() -> None:
    obs = _svc().model_copy(update={"kind": ObservationKind.VULN_CANDIDATE})
    assert _cves(obs) == []


def test_findings_cite_their_observation_source_and_confidence() -> None:
    obs = _svc()
    findings = version_match_findings([obs], DETECTED)
    assert sorted(c for f in findings for c in f.cve_ids) == ["CVE-2021-41773", "CVE-2021-42013"]
    digest = load_version_rules().digest
    for finding in findings:
        assert finding.scanner == VERSION_MATCH_SCANNER
        assert finding.observation_ids == [obs.observation_id]
        assert finding.asset_id == "host:172.20.1.10"
        assert "confidence: low" in finding.description
        assert f"Derived from observation {obs.observation_id}" in finding.description
        assert digest in finding.description
        assert "Derived by rule vm-apache-httpd-cve-" in finding.description
        assert "unconfirmed" in finding.title


def test_findings_are_deterministic_and_deduplicated() -> None:
    a = _svc(obs_id="obs:a")
    b = _svc(obs_id="obs:b")
    first = version_match_findings([a, b], DETECTED)
    second = version_match_findings([b, a], DETECTED)
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]
    assert len(first) == 2
    assert all(f.observation_ids == ["obs:a", "obs:b"] for f in first)


def test_real_dvwa_capture_yields_no_candidate() -> None:
    """The one real nmap capture: dvwa reports Apache httpd 2.4.25, outside
    CVE-2021-41773's range. Version matching must not claim it (see D-050)."""
    obs = [o for o in _nmap_observations() if o.subject.startswith("172.20.1.10:")]
    assert any(o.kind == ObservationKind.SERVICE_VERSION for o in obs)
    assert version_match_findings(obs, DETECTED) == []


def test_cve_ids_helper_matches_findings() -> None:
    obs = _nmap_observations()
    from_findings = sorted({c for f in version_match_findings(obs, DETECTED) for c in f.cve_ids})
    assert version_match_cve_ids(obs) == from_findings


# ------------------------------------------------------------------- graph effect

# CWE ids as enrichment would fuse them from CVE records. Test inputs: the same CWE the
# lab's nuclei fixture carries for each CVE, attributed to cve.org as fusion would.
_TEST_CWES = {
    "CVE-2022-22947": "CWE-94",
    "CVE-2024-23897": "CWE-22",
    "CVE-2022-26134": "CWE-917",
    "CVE-2021-23017": "CWE-787",
}


def _enriched(findings: list[Finding]) -> list[EnrichedFinding]:
    out: list[EnrichedFinding] = []
    for finding in findings:
        cwes = [_TEST_CWES[c] for c in finding.cve_ids if c in _TEST_CWES]
        fields = {}
        if cwes:
            fields["cwe_ids"] = Attributed(
                value=cwes,
                provenance=Provenance(
                    source=Source.CVE_ORG, confidence=Confidence.HIGH, retrieved_at=DETECTED
                ),
            )
        out.append(EnrichedFinding(finding=finding, fields=fields))
    return out


def test_nmap_only_scan_had_no_paths_before_version_match() -> None:
    """The live-scan symptom: service facts but no vuln_candidates, so no exploit edges."""
    result = analyze(
        engagement_id="eng-lab-baseline",
        observations=_nmap_observations(),
        findings=[],
        topology=_topology(),
    )
    assert not [p for p in result.paths if p.edges]


def test_version_match_findings_without_cwe_ids_stay_unclassified() -> None:
    obs = _nmap_observations()
    findings = version_match_findings(obs, DETECTED)
    result = analyze(
        engagement_id="eng-lab-baseline", observations=obs, findings=findings, topology=_topology()
    )
    assert not result.paths
    assert {u.finding_id for u in result.unclassified_findings} == {f.finding_id for f in findings}


def test_version_match_findings_with_enriched_cwes_give_low_confidence_paths() -> None:
    obs = _nmap_observations()
    findings = version_match_findings(obs, DETECTED)
    result = analyze(
        engagement_id="eng-lab-baseline",
        observations=obs,
        findings=findings,
        topology=_topology(),
        enriched=_enriched(findings),
    )
    assert result.paths
    by_id = {f.finding_id: f for f in findings}
    nodes = {n.node_id: n for n in result.nodes}
    derived_edges = [e for e in result.edges if set(e.finding_ids) & set(by_id)]
    assert derived_edges
    for edge in derived_edges:
        assert edge.confidence == Confidence.LOW
        assert "derived by version-match, not observed, capped low" in edge.description
        # Traces to the finding and to the service_version observation it came from.
        (fid,) = edge.finding_ids
        assert f"finding:{fid}" in edge.evidence
        assert set(by_id[fid].observation_ids) <= set(edge.evidence)
    for path in result.paths:
        assert path.confidence == Confidence.LOW
    exec_hosts = {
        nodes[e.to_node].label
        for e in derived_edges
        if nodes[e.to_node].kind == NodeKind.CODE_EXECUTION
    }
    assert any("spring-gateway" in h for h in exec_hosts)
    # Smuggling (CWE-444 / no CWE here) is not mapped: werkzeug stays unclassified.
    assert any("CVE-2022-29361" in u.cve_ids for u in result.unclassified_findings)


def test_cap_comes_from_rule_data() -> None:
    assert load_ruleset().derived_finding_caps == {VERSION_MATCH_SCANNER: Confidence.LOW}
