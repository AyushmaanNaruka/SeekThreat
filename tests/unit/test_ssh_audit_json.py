"""Tests for services.scanners.ssh_audit_json.

Fixtures live in tests/fixtures/ssh_audit/; see the README there for how each was made.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Source
from services.scanners import ssh_audit_json
from services.scanners.nmap_xml import parse_nmap_xml
from services.scanners.ssh_audit_json import SshAuditParseError, parse_ssh_audit_json

FIXTURES = Path(__file__).parent.parent / "fixtures" / "ssh_audit"
NMAP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"
ENGAGEMENT_ID = "eng-ssh-audit-001"
CAPTURED_AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)

V3 = "openssh_8.3_ssh-audit-3.9.0.json"
V2 = "openssh_8.3_ssh-audit-2.9.0.json"
BASTION = "172.20.2.50:2222/tcp"


def _artifact_from(raw: str, captured_at: datetime = CAPTURED_AT) -> RawArtifact:
    return RawArtifact(
        artifact_id="sha256:test-ssh-audit",
        scanner="ssh-audit",
        content=raw,
        content_type="application/json",
        captured_at=captured_at,
    )


def _artifact(name: str, captured_at: datetime = CAPTURED_AT) -> RawArtifact:
    return _artifact_from((FIXTURES / name).read_text(encoding="utf-8"), captured_at)


def _parse(name: str) -> tuple[Observation, ...]:
    return parse_ssh_audit_json(_artifact(name), engagement_id=ENGAGEMENT_ID)


def _nmap_ports(fixture: str) -> list[str]:
    nmap_artifact = RawArtifact(
        artifact_id="sha256:test-nmap",
        scanner="nmap",
        content=(NMAP_FIXTURES / fixture).read_text(encoding="utf-8"),
        content_type="application/xml",
        captured_at=CAPTURED_AT,
    )
    return [
        o.subject
        for o in parse_nmap_xml(nmap_artifact, engagement_id=ENGAGEMENT_ID)
        if o.kind == ObservationKind.PORT_OPEN
    ]


def _candidates(obs: tuple[Observation, ...], finding_type: str) -> list[Observation]:
    return [
        o
        for o in obs
        if o.kind == ObservationKind.VULN_CANDIDATE
        and o.attributes.get("finding_type") == finding_type
    ]


def _weak(obs: tuple[Observation, ...]) -> dict[tuple[str, str], Observation]:
    return {
        (o.attributes["category"], o.attributes["algorithm"]): o
        for o in _candidates(obs, "weak_algorithm")
    }


# --------------------------------------------------------------------------- #
# ssh-audit 3.x (real capture)
# --------------------------------------------------------------------------- #


def test_v3_service_version_describes_the_ssh_listener() -> None:
    obs = _parse(V3)
    services = [o for o in obs if o.kind == ObservationKind.SERVICE_VERSION]
    assert len(services) == 1
    svc = services[0]
    assert svc.subject == BASTION
    assert svc.scanner == "ssh-audit"
    assert svc.engagement_id == ENGAGEMENT_ID
    assert svc.attributes == {
        "service_name": "ssh",
        "product": "openssh",
        "version": "8.3",
        "banner": "SSH-2.0-OpenSSH_8.3",
        "protocol": "2.0",
    }
    assert svc.provenance.source == Source.SCANNER
    assert svc.provenance.confidence == Confidence.HIGH


def test_v3_reports_no_cve_candidates_because_ssh_audit_3_no_longer_emits_any() -> None:
    assert _candidates(_parse(V3), "cve") == []


def test_v3_weak_algorithms_are_direct_facts_with_ssh_audits_own_level() -> None:
    weak = _weak(_parse(V3))

    ssh_rsa = weak[("key", "ssh-rsa")]
    assert ssh_rsa.attributes["level"] == "fail"
    assert ssh_rsa.attributes["notes"] == "using broken SHA-1 hash algorithm"
    assert ssh_rsa.attributes["keysize"] == "3072"
    assert ssh_rsa.provenance.confidence == Confidence.HIGH
    assert ssh_rsa.provenance.source == Source.SCANNER

    umac = weak[("mac", "umac-64@openssh.com")]
    assert umac.attributes["level"] == "warn"
    assert umac.attributes["notes"] == "using encrypt-and-MAC mode; using small 64-bit tag size"

    nistp256 = weak[("kex", "ecdh-sha2-nistp256")]
    # fail outranks warn, and the warn text is kept separately rather than lost.
    assert nistp256.attributes["level"] == "fail"
    assert "backdoored" in nistp256.attributes["notes"]
    assert nistp256.attributes["warn_notes"] == (
        "does not provide protection against post-quantum attacks"
    )


def test_v3_info_only_algorithms_are_not_findings() -> None:
    weak = _weak(_parse(V3))
    assert ("enc", "aes128-ctr") not in weak
    assert ("key", "ssh-ed25519") not in weak
    assert ("mac", "hmac-sha2-256-etm@openssh.com") not in weak
    assert {o.attributes["level"] for o in weak.values()} <= {"fail", "warn"}


def test_v3_terrapin_note_surfaces_its_cve_id() -> None:
    chacha = _weak(_parse(V3))[("enc", "chacha20-poly1305@openssh.com")]
    assert chacha.attributes["cve_ids"] == "CVE-2023-48795"
    assert chacha.attributes["level"] == "warn"


def test_v3_recommendation_is_folded_into_the_algorithm_not_emitted_twice() -> None:
    obs = _parse(V3)
    assert _weak(obs)[("key", "ssh-rsa")].attributes["recommendation"] == "remove"
    keys = [
        (o.attributes["category"], o.attributes["algorithm"])
        for o in _candidates(obs, "weak_algorithm")
    ]
    assert len(keys) == len(set(keys))


def test_every_candidate_carries_the_endpoint_and_a_finding_type() -> None:
    for o in _parse(V3) + _parse(V2):
        if o.kind == ObservationKind.VULN_CANDIDATE:
            assert o.subject == BASTION
            assert o.attributes["endpoint"] == BASTION
            assert o.attributes["finding_type"] in {"cve", "weak_algorithm"}


def test_no_severity_is_assigned() -> None:
    for o in _parse(V3) + _parse(V2):
        assert not any("severity" in key for key in o.attributes)


# --------------------------------------------------------------------------- #
# ssh-audit 2.x (real capture): CVEs from the banner, algorithms from recommendations
# --------------------------------------------------------------------------- #


def test_v2_cve_candidates_keep_the_scanners_cvss_verbatim_and_are_low_confidence() -> None:
    cves = _candidates(_parse(V2), "cve")
    assert [o.attributes["cve_ids"] for o in cves] == [
        "CVE-2016-20012",
        "CVE-2020-15778",
        "CVE-2021-41617",
    ]
    by_id = {o.attributes["cve_ids"]: o for o in cves}
    assert by_id["CVE-2020-15778"].attributes["scanner_cvssv2"] == "7.8"
    assert by_id["CVE-2020-15778"].attributes["description"] == (
        "command injection via anomalous argument transfers"
    )
    assert by_id["CVE-2020-15778"].attributes["banner"] == "SSH-2.0-OpenSSH_8.3"
    for o in cves:
        assert o.provenance.confidence == Confidence.LOW
        assert o.provenance.source == Source.SCANNER
        assert "backport" in (o.provenance.note or "")
        assert "cvss_score" not in o.attributes  # not presented as a severity input


def test_v2_bare_string_algorithm_lists_are_understood() -> None:
    weak = _weak(_parse(V2))
    # enc/mac are plain strings in v2; their recommendation-rated members must still match
    assert ("mac", "umac-64@openssh.com") in weak
    assert ("enc", "aes128-ctr") not in weak


def test_v2_protocol_list_is_normalised_to_the_v3_spelling() -> None:
    svc = next(o for o in _parse(V2) if o.kind == ObservationKind.SERVICE_VERSION)
    assert svc.attributes["protocol"] == "2.0"


def test_v2_weak_algorithms_come_from_recommendations_with_the_matching_level() -> None:
    weak = _weak(_parse(V2))
    assert weak[("key", "ssh-rsa")].attributes["level"] == "fail"
    assert weak[("mac", "hmac-sha1")].attributes["level"] == "fail"
    assert weak[("kex", "diffie-hellman-group14-sha256")].attributes["level"] == "warn"
    # v2 gives no reason text, and none is invented
    assert "notes" not in weak[("key", "ssh-rsa")].attributes
    assert weak[("key", "ssh-rsa")].attributes["recommendation"] == "remove"


# --------------------------------------------------------------------------- #
# Hand-written edge cases
# --------------------------------------------------------------------------- #


def test_ipv6_target_is_bracketed_and_the_hardened_server_has_no_findings() -> None:
    obs = _parse("hardened_ipv6_dropbear.json")
    assert [o.kind for o in obs] == [ObservationKind.SERVICE_VERSION]
    svc = obs[0]
    assert svc.subject == "[fd00::5]:22/tcp"
    assert svc.attributes["product"] == "dropbear"
    assert svc.attributes["version"] == "2022.83"


def test_distro_banner_comments_survive_for_backport_reasoning() -> None:
    obs = _parse("distro_banner_comments.json")
    svc = next(o for o in obs if o.kind == ObservationKind.SERVICE_VERSION)
    assert svc.attributes["version"] == "8.2p1"
    assert svc.attributes["banner_comments"] == "Ubuntu-4ubuntu0.5"
    assert svc.attributes["banner"] == "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"


def test_duplicate_and_malformed_cve_entries_are_dropped() -> None:
    cves = _candidates(_parse("distro_banner_comments.json"), "cve")
    assert [o.attributes["cve_ids"] for o in cves] == ["CVE-2020-15778"]


def test_fail_and_warn_on_one_algorithm_make_one_fail_candidate() -> None:
    weak = _weak(_parse("distro_banner_comments.json"))
    des = weak[("enc", "3des-cbc")]
    assert des.attributes["level"] == "fail"
    assert des.attributes["notes"] == "using weak cipher"
    assert "Sweet32" in des.attributes["warn_notes"]
    assert des.attributes["cve_ids"] == "CVE-2016-2183"
    assert des.attributes["keysize"] == "168"
    assert weak[("kex", "diffie-hellman-group1-sha1")].attributes["notes"] == (
        "using broken SHA-1 hash algorithm; using small 1024-bit modulus"
    )


def test_recommendations_about_algorithms_the_server_does_not_advertise_are_ignored() -> None:
    weak = _weak(_parse("distro_banner_comments.json"))
    assert ("mac", "hmac-md5") not in weak
    assert ("kex", "diffie-hellman-group-exchange-sha256") not in weak
    assert len(weak) == 2


def test_control_characters_are_stripped_and_long_values_capped() -> None:
    obs = _parse("malicious_attributes.json")
    for o in obs:
        for value in o.attributes.values():
            assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value), value
            assert len(value) <= 512
        note = o.provenance.note or ""
        assert not any(ord(ch) < 0x20 for ch in note)
    svc = next(o for o in obs if o.kind == ObservationKind.SERVICE_VERSION)
    assert svc.attributes["banner"].startswith("SSH-2.0-OpenSSH_8.3")
    assert "\x1b" not in svc.attributes["banner"]
    weak = _weak(obs)
    assert weak[("enc", "huge")].attributes["notes"].endswith("…[truncated]")
    assert ("enc", "weirdalg[0m") in weak


# --------------------------------------------------------------------------- #
# Join with nmap
# --------------------------------------------------------------------------- #


def test_endpoint_is_spelled_exactly_like_nmaps_port_subject() -> None:
    assert BASTION in _nmap_ports("lab_internal.xml")
    assert {o.subject for o in _parse(V3)} == {BASTION}


def test_ipv6_endpoint_matches_nmaps_compressed_bracketed_spelling() -> None:
    nmap_subject = _nmap_ports("ipv6_only.xml")[0]
    assert nmap_subject == "[2001:db8::10]:80/tcp"
    # ssh-audit spells the same address unbracketed and uncompressed
    content = (FIXTURES / "hardened_ipv6_dropbear.json").read_text(encoding="utf-8")
    content = content.replace("fd00::5:22", "2001:0db8:0000:0000:0000:0000:0000:0010:80")
    svc = parse_ssh_audit_json(_artifact_from(content), ENGAGEMENT_ID)[0]
    assert svc.subject == nmap_subject


# --------------------------------------------------------------------------- #
# Purity and determinism
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", [V3, V2, "distro_banner_comments.json"])
def test_parse_is_deterministic(name: str) -> None:
    first = _parse(name)
    second = _parse(name)
    assert first == second
    assert [o.model_dump_json() for o in first] == [o.model_dump_json() for o in second]


def test_observation_ids_are_content_addressed_and_unique() -> None:
    obs = _parse(V3)
    ids = [o.observation_id for o in obs]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("obs:sha256:") for i in ids)
    other_engagement = parse_ssh_audit_json(_artifact(V3), engagement_id="eng-other")
    assert not set(ids) & {o.observation_id for o in other_engagement}


def test_output_order_is_independent_of_the_input_order() -> None:
    data = json.loads((FIXTURES / V3).read_text(encoding="utf-8"))
    for category in ("kex", "enc", "mac", "key"):
        data[category].reverse()
    shuffled = parse_ssh_audit_json(_artifact_from(json.dumps(data)), ENGAGEMENT_ID)
    assert [o.observation_id for o in shuffled] == [o.observation_id for o in _parse(V3)]


def test_timestamps_derive_from_the_artifact_only() -> None:
    later = datetime(2027, 1, 1, tzinfo=UTC)
    obs = parse_ssh_audit_json(_artifact(V3, captured_at=later), ENGAGEMENT_ID)
    assert {o.observed_at for o in obs} == {later}
    assert {o.provenance.retrieved_at for o in obs} == {later}
    assert {o.artifact_id for o in obs} == {"sha256:test-ssh-audit"}


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "content",
    [
        "",
        "   \n",
        "[]",
        '"just a string"',
        "{not json",
        "{}",
        '{"banner": {"raw": "SSH-2.0-x"}}',
        '{"banner": {}, "target": "no-port"}',
        '{"banner": {}, "target": "host:0"}',
        '{"banner": {}, "target": "host:99999"}',
        '{"banner": {}, "target": ":22"}',
        '{"banner": {}, "target": "bad host:22"}',
        '{"banner": {}, "target": 22}',
        '{"client_ip": "10.0.0.1", "banner": {}}',
    ],
)
def test_unusable_output_raises_a_parse_error(content: str) -> None:
    with pytest.raises(SshAuditParseError):
        parse_ssh_audit_json(_artifact_from(content), ENGAGEMENT_ID)


def test_truncated_json_fixture_raises_a_parse_error() -> None:
    with pytest.raises(SshAuditParseError, match="Malformed"):
        _parse("truncated.json")


def test_connection_error_text_is_not_parseable_as_a_result() -> None:
    raw = (FIXTURES / "connection_refused.txt").read_text(encoding="utf-8")
    assert "cannot connect" in raw
    with pytest.raises(SshAuditParseError):
        parse_ssh_audit_json(_artifact_from(raw), ENGAGEMENT_ID)


def test_oversized_output_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ssh_audit_json, "_MAX_CONTENT_BYTES", 100)
    with pytest.raises(SshAuditParseError, match="maximum allowed size"):
        _parse(V3)


def test_structurally_odd_fields_are_tolerated_not_fatal() -> None:
    content = (
        '{"target": "10.0.0.1:22", "banner": "oops", "cves": "none", "kex": {"x": 1},'
        ' "enc": [1, null, {"algorithm": ["a"]}, {"algorithm": "x", "notes": "bad"}],'
        ' "recommendations": []}'
    )
    assert parse_ssh_audit_json(_artifact_from(content), ENGAGEMENT_ID) == ()
