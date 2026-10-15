"""Interim observation -> Finding bridge (D-044)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from packages.schema.models.observation import Observation, ObservationKind, ScanResult
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.normalize import findings_from_observations

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _obs(
    obs_id: str,
    attrs: dict[str, str],
    *,
    kind: ObservationKind = ObservationKind.VULN_CANDIDATE,
    scanner: str = "nikto",
    subject: str = "172.20.1.10:80/tcp",
) -> Observation:
    return Observation(
        observation_id=obs_id,
        engagement_id="eng-1",
        scanner=scanner,
        kind=kind,
        subject=subject,
        attributes=attrs,
        artifact_id="sha256:abc",
        observed_at=NOW,
        provenance=Provenance(
            source=Source.SCANNER, confidence=Confidence.MEDIUM, retrieved_at=NOW
        ),
    )


def test_real_nuclei_snapshot_becomes_traceable_findings() -> None:
    result = ScanResult.model_validate_json(
        (FIXTURES / "observations" / "lab_extended_nuclei.json").read_text(encoding="utf-8")
    )
    findings = findings_from_observations(result.observations, detected_at=NOW)
    vulns = [o for o in result.observations if o.kind == ObservationKind.VULN_CANDIDATE]

    assert findings and len(findings) <= len(vulns)
    obs_ids = {o.observation_id for o in result.observations}
    for f in findings:
        assert f.asset_id.startswith("host:172.20.")
        assert set(f.observation_ids) <= obs_ids
        assert f.title
    assert any(f.cve_ids for f in findings)


def test_only_vuln_candidates_become_findings() -> None:
    obs = [
        _obs("o1", {"endpoint": "172.20.1.10:80/tcp"}, kind=ObservationKind.PORT_OPEN),
        _obs("o2", {"endpoint": "172.20.1.10:80/tcp", "msg": "Header missing", "nikto_id": "1"}),
    ]
    findings = findings_from_observations(obs, detected_at=NOW)
    assert [f.observation_ids for f in findings] == [["o2"]]
    assert findings[0].title == "Header missing"
    assert findings[0].cve_ids == []


def test_finding_id_is_stable_across_rescans_and_dedupes_within_a_scan() -> None:
    attrs = {"endpoint": "172.20.1.10:80/tcp", "nikto_id": "999957", "url": "/", "msg": "x"}
    first = findings_from_observations([_obs("a", attrs)], detected_at=NOW)
    rescan = findings_from_observations([_obs("b", attrs), _obs("c", attrs)], detected_at=NOW)
    assert first[0].finding_id == rescan[0].finding_id
    assert rescan[0].observation_ids == ["b", "c"]


def test_ipv6_endpoint_and_url_subject_give_d040_asset_ids() -> None:
    v6 = _obs(
        "o1",
        {
            "endpoint": "FD00::5:22/tcp",
            "finding_type": "weak_algorithm",
            "category": "kex",
            "algorithm": "diffie-hellman-group1-sha1",
        },
        scanner="ssh-audit",
    )
    url = _obs("o2", {"template_id": "t"}, scanner="nuclei", subject="http://Web.Lab.Local:8080/x")
    by_scanner = {f.scanner: f for f in findings_from_observations([v6, url], detected_at=NOW)}
    assert by_scanner["ssh-audit"].asset_id == "host:fd00::5"
    assert by_scanner["ssh-audit"].title == "Weak SSH kex algorithm: diffie-hellman-group1-sha1"
    assert by_scanner["nuclei"].asset_id == "host:web.lab.local"


def test_only_canonical_scanner_reported_cves_are_kept() -> None:
    obs = _obs(
        "o1", {"endpoint": "172.20.1.10:80/tcp", "cve_ids": "cve-2021-41773, GHSA-x, CVE-21-1"}
    )
    assert findings_from_observations([obs], detected_at=NOW)[0].cve_ids == ["CVE-2021-41773"]


def test_bare_host_port_subject_and_matcher_name_title() -> None:
    obs = _obs(
        "o1",
        {
            "template_id": "http-missing-security-headers",
            "template_name": "HTTP Missing Security Headers",
            "matcher_name": "x-frame-options",
        },
        scanner="nuclei",
        subject="172.20.1.10:80",
    )
    finding = findings_from_observations([obs], detected_at=NOW)[0]
    assert finding.asset_id == "host:172.20.1.10"
    assert finding.title == "HTTP Missing Security Headers: x-frame-options"


def test_scanner_confidence_is_carried_and_hostless_records_are_skipped() -> None:
    inferred = _obs("o1", {"endpoint": "172.20.2.50:2222/tcp", "cve_ids": "CVE-2020-15778"})
    inferred = inferred.model_copy(
        update={
            "provenance": Provenance(
                source=Source.SCANNER,
                confidence=Confidence.LOW,
                retrieved_at=NOW,
                note="banner-version CVE mapping (inference)",
            )
        }
    )
    hostless = _obs("o2", {"template_id": "t"}, scanner="nuclei", subject="unknown")
    findings = findings_from_observations([inferred, hostless], detected_at=NOW)
    assert len(findings) == 1
    assert (
        "Scanner confidence: low (banner-version CVE mapping (inference))"
        in findings[0].description
    )
