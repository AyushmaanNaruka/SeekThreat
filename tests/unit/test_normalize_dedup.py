"""Track 1 cross-scanner dedup and the normalize pipeline (D-045 proposed)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
    ScanResult,
)
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.normalize import normalize_observations, normalize_scan_observations
from services.normalize.identity import is_valid_asset_id
from services.scanners.ssh_audit_json import parse_ssh_audit_json

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
LAB_ENGAGEMENT = "eng-lab-baseline"


def vuln(
    obs_id: str,
    *,
    scanner: str,
    endpoint: str,
    subject: str | None = None,
    confidence: Confidence = Confidence.HIGH,
    engagement_id: str = "eng-1",
    **attrs: str,
) -> Observation:
    return Observation(
        observation_id=obs_id,
        engagement_id=engagement_id,
        scanner=scanner,
        kind=ObservationKind.VULN_CANDIDATE,
        subject=subject or endpoint,
        attributes={"endpoint": endpoint, **attrs},
        artifact_id="sha256:test",
        observed_at=NOW,
        provenance=Provenance(
            source=Source.SCANNER, confidence=confidence, retrieved_at=NOW, note=f"{scanner} note"
        ),
    )


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("normalization attempted a network/DNS call")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, boom)
    yield


def _lab_observations() -> list[Observation]:
    out: list[Observation] = []
    for path in sorted((FIXTURES / "observations").glob("*.json")):
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        out.extend(result.observations)
    return out


def _ssh_audit_bastion() -> tuple[Observation, ...]:
    artifact = RawArtifact(
        artifact_id="sha256:ssh-audit-bastion",
        scanner="ssh-audit",
        content=(FIXTURES / "ssh_audit" / "openssh_8.3_ssh-audit-3.9.0.json").read_text(
            encoding="utf-8"
        ),
        content_type="application/json",
        captured_at=NOW,
    )
    return parse_ssh_audit_json(artifact, engagement_id=LAB_ENGAGEMENT)


# --------------------------------------------------------------------------- #
# Merge rule
# --------------------------------------------------------------------------- #


def test_same_cve_from_two_scanners_merges_with_all_observations() -> None:
    a = vuln("o-nuc", scanner="nuclei", endpoint="172.20.2.50:2222/tcp", cve_ids="CVE-2023-48795")
    b = vuln(
        "o-ssh",
        scanner="ssh-audit",
        endpoint="172.20.2.50:2222/tcp",
        confidence=Confidence.LOW,
        cve_ids="cve-2023-48795",
    )
    [finding] = normalize_observations([a, b], NOW).findings
    assert finding.observation_ids == ["o-nuc", "o-ssh"]
    assert finding.cve_ids == ["CVE-2023-48795"]
    assert finding.scanner == "nuclei,ssh-audit"
    assert finding.asset_id == "host:172.20.2.50"
    # Per-scanner confidence survives the merge.
    assert "nuclei: confidence high" in finding.description
    assert "ssh-audit: confidence low" in finding.description


def test_same_cve_merges_across_hostname_and_ip_spellings() -> None:
    nmap = Observation(
        observation_id="h1",
        engagement_id="eng-1",
        scanner="nmap",
        kind=ObservationKind.HOST_UP,
        subject="172.20.1.10",
        attributes={"ipv4": "172.20.1.10", "hostnames": "dvwa.lab.local|user"},
        artifact_id="sha256:nmap",
        observed_at=NOW,
        provenance=Provenance(source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW),
    )
    a = vuln("o1", scanner="nuclei", endpoint="dvwa.lab.local:80/tcp", cve_ids="CVE-2021-41773")
    b = vuln("o2", scanner="nikto", endpoint="172.20.1.10:80/tcp", cve_ids="CVE-2021-41773")
    result = normalize_observations([nmap, a, b], NOW)
    [finding] = result.findings
    assert finding.asset_id == "host:172.20.1.10"
    assert finding.observation_ids == ["o1", "o2"]
    [merge] = result.merges
    assert {r.alias for r in merge.resolutions} == {"host:172.20.1.10", "host:dvwa.lab.local"}
    joined = [r for r in merge.resolutions if r.joined]
    assert joined[0].observation_ids == ("h1",)


def test_different_cves_do_not_merge() -> None:
    a = vuln("o1", scanner="ssh-audit", endpoint="172.20.2.50:2222/tcp", cve_ids="CVE-2023-48795")
    b = vuln("o2", scanner="ssh-audit", endpoint="172.20.2.50:2222/tcp", cve_ids="CVE-2021-41617")
    assert len(normalize_observations([a, b], NOW).findings) == 2


def test_overlapping_but_unequal_cve_sets_do_not_merge() -> None:
    a = vuln(
        "o1", scanner="nuclei", endpoint="10.0.0.1:80/tcp", cve_ids="CVE-2021-0001, CVE-2021-0002"
    )
    b = vuln("o2", scanner="nikto", endpoint="10.0.0.1:80/tcp", cve_ids="CVE-2021-0001")
    assert len(normalize_observations([a, b], NOW).findings) == 2


def test_same_cve_on_different_ports_or_hosts_does_not_merge() -> None:
    a = vuln("o1", scanner="nuclei", endpoint="10.0.0.1:80/tcp", cve_ids="CVE-2021-41773")
    b = vuln("o2", scanner="nuclei", endpoint="10.0.0.1:8080/tcp", cve_ids="CVE-2021-41773")
    c = vuln("o3", scanner="nuclei", endpoint="10.0.0.2:80/tcp", cve_ids="CVE-2021-41773")
    assert len(normalize_observations([a, b, c], NOW).findings) == 3


def test_no_cve_checks_from_different_scanners_never_merge() -> None:
    a = vuln("o1", scanner="nikto", endpoint="10.0.0.1:80/tcp", msg="X-Frame-Options missing")
    b = vuln(
        "o2",
        scanner="nuclei",
        endpoint="10.0.0.1:80/tcp",
        template_id="http-missing-security-headers",
        matcher_name="x-frame-options",
    )
    assert len(normalize_observations([a, b], NOW).findings) == 2


def test_same_scanner_check_reported_twice_merges() -> None:
    attrs = {"template_id": "tech-detect", "matcher_name": "apache"}
    a = vuln("o1", scanner="nuclei", endpoint="10.0.0.1:80/tcp", url="http://10.0.0.1:80", **attrs)
    b = vuln("o2", scanner="nuclei", endpoint="10.0.0.1:80/tcp", url="http://10.0.0.1:80", **attrs)
    [finding] = normalize_observations([a, b], NOW).findings
    assert finding.observation_ids == ["o1", "o2"]
    assert finding.scanner == "nuclei"


def test_non_vuln_observations_produce_no_findings() -> None:
    port = vuln("o1", scanner="nmap", endpoint="10.0.0.1:80/tcp").model_copy(
        update={"kind": ObservationKind.PORT_OPEN}
    )
    assert normalize_observations([port], NOW).findings == []


def test_unresolvable_host_is_reported_not_silently_dropped() -> None:
    a = vuln("o1", scanner="nuclei", endpoint="", subject="unknown", template_id="t")
    result = normalize_observations([a], NOW)
    assert result.findings == []
    assert result.unresolved_observation_ids == ["o1"]


def test_engagements_are_never_joined() -> None:
    a = vuln("o1", scanner="nuclei", endpoint="10.0.0.1:80/tcp", cve_ids="CVE-2021-41773")
    b = vuln(
        "o2",
        scanner="nikto",
        endpoint="10.0.0.1:80/tcp",
        cve_ids="CVE-2021-41773",
        engagement_id="eng-2",
    )
    findings = normalize_observations([a, b], NOW).findings
    assert sorted(f.engagement_id for f in findings) == ["eng-1", "eng-2"]


# --------------------------------------------------------------------------- #
# Idempotency and determinism
# --------------------------------------------------------------------------- #


def test_finding_ids_are_stable_across_reruns_and_new_evidence() -> None:
    a = vuln("o1", scanner="nuclei", endpoint="172.20.2.50:2222/tcp", cve_ids="CVE-2023-48795")
    first = normalize_observations([a], NOW).findings
    b = vuln("o2", scanner="ssh-audit", endpoint="172.20.2.50:2222/tcp", cve_ids="CVE-2023-48795")
    second = normalize_observations([b, a], LATER).findings
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert second[0].observation_ids == ["o1", "o2"]


def test_output_is_deterministic_regardless_of_input_order() -> None:
    observations = [*_lab_observations(), *_ssh_audit_bastion()]
    forward = normalize_observations(observations, NOW)
    backward = normalize_observations(list(reversed(observations)), NOW)
    assert forward.model_dump() == backward.model_dump()
    keys = [(f.asset_id, f.finding_id) for f in forward.findings]
    assert keys == sorted(keys)


# --------------------------------------------------------------------------- #
# Full fixture set through the pipeline
# --------------------------------------------------------------------------- #


def test_full_lab_fixture_set_normalizes_to_traceable_d040_findings() -> None:
    observations = [*_lab_observations(), *_ssh_audit_bastion()]
    by_id = {o.observation_id: o for o in observations}
    result = normalize_observations(observations, NOW)

    vulns = [o for o in observations if o.kind == ObservationKind.VULN_CANDIDATE]
    assert result.findings
    assert result.unresolved_observation_ids == []
    covered: set[str] = set()
    for f in result.findings:
        assert f.observation_ids, f.finding_id
        assert is_valid_asset_id(f.asset_id) and f.asset_id.startswith("host:"), f.asset_id
        assert f.engagement_id == LAB_ENGAGEMENT
        for oid in f.observation_ids:
            assert by_id[oid].kind == ObservationKind.VULN_CANDIDATE
            covered.add(oid)
    # Every vuln_candidate lands in exactly one finding.
    assert covered == {o.observation_id for o in vulns}
    assert sum(len(f.observation_ids) for f in result.findings) == len(vulns)
    assert result.ambiguities == []
    # nmap PTR names are joined to their hosts, with the observation that justified it.
    assert any(link.alias == "host:lab-bastion-ssh-1.lab_internal" for link in result.links)
    assert all(link.observation_ids for link in result.links)


def test_scan_normalisation_uses_engagement_context_and_returns_touched_findings() -> None:
    """A nuclei scan by hostname, after an nmap scan that named the host, joins to the
    IP and merges with ssh-audit's CVE; untouched findings are not re-enqueued."""
    context = [*_lab_observations(), *_ssh_audit_bastion()]
    nuclei = vuln(
        "o-nuclei-terrapin",
        scanner="nuclei",
        endpoint="lab-bastion-ssh-1.lab_internal:2222/tcp",
        engagement_id=LAB_ENGAGEMENT,
        template_id="CVE-2023-48795",
        cve_ids="CVE-2023-48795",
    )
    result = normalize_scan_observations([nuclei], NOW, engagement_observations=context)
    [finding] = result.findings
    assert finding.asset_id == "host:172.20.2.50"
    assert finding.cve_ids == ["CVE-2023-48795"]
    assert finding.scanner == "nuclei,ssh-audit"
    assert "o-nuclei-terrapin" in finding.observation_ids
    assert len(finding.observation_ids) == 2


def test_scan_without_context_behaves_like_single_scan() -> None:
    a = vuln("o1", scanner="nikto", endpoint="172.20.1.50:80/tcp", nikto_id="1", msg="m")
    result = normalize_scan_observations([a], NOW)
    [finding] = result.findings
    assert finding.asset_id == "host:172.20.1.50"
    assert finding.observation_ids == ["o1"]
