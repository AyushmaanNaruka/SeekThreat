"""Tests for services.scanners.nmap_xml — the pure nmap XML -> Observation parser.

Fixtures live in tests/fixtures/nmap/. lab_baseline.xml is real nmap -sV output captured
against the lab's dvwa and juiceshop containers (see lab/README.md for the capture
procedure); everything else is hand-written against nmap's XML shape to exercise
conditions a real scan will not conveniently produce.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from packages.schema.models.observation import ObservationKind, RawArtifact, ScanResult
from packages.schema.models.provenance import Confidence
from services.scanners.nmap_adapter import NmapAdapter
from services.scanners.nmap_xml import NmapParseError, parse_nmap_xml, parse_run_timestamp

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"
OBSERVATION_FIXTURES = Path(__file__).parent.parent / "fixtures" / "observations"
ENGAGEMENT_ID = "eng-001"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _artifact(name: str, captured_at: datetime | None = None) -> RawArtifact:
    raw = _load(name)
    if captured_at is None:
        captured_at = parse_run_timestamp(raw)
    return RawArtifact(
        artifact_id=f"sha256:test-{name}",
        scanner="nmap",
        content=raw,
        content_type="application/xml",
        captured_at=captured_at,
    )


def _parse(name: str, captured_at: datetime | None = None):
    artifact = _artifact(name, captured_at)
    return parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)


# --------------------------------------------------------------------------- #
# The real lab fixture
# --------------------------------------------------------------------------- #


def test_lab_baseline_emits_expected_observation_kinds() -> None:
    observations = _parse("lab_baseline.xml")
    kinds = [o.kind for o in observations]
    assert kinds.count(ObservationKind.HOST_UP) == 2
    assert kinds.count(ObservationKind.PORT_OPEN) == 2
    # juiceshop's port 3000 is method="table" — no SERVICE_VERSION for it.
    assert kinds.count(ObservationKind.SERVICE_VERSION) == 1


def test_lab_baseline_hosts_are_sorted_by_address() -> None:
    observations = _parse("lab_baseline.xml")
    host_subjects = [o.subject for o in observations if o.kind is ObservationKind.HOST_UP]
    assert host_subjects == ["172.20.1.10", "172.20.1.11"]


def test_lab_baseline_probed_service_is_high_confidence_with_product() -> None:
    observations = _parse("lab_baseline.xml")
    service = next(o for o in observations if o.kind is ObservationKind.SERVICE_VERSION)
    assert service.subject == "172.20.1.10:80/tcp"
    assert service.attributes["product"] == "Apache httpd"
    assert service.attributes["version"] == "2.4.25"
    assert service.attributes["cpe"] == "cpe:/a:apache:http_server:2.4.25"
    assert service.provenance.confidence is Confidence.HIGH


def test_lab_baseline_table_method_service_has_no_service_version() -> None:
    observations = _parse("lab_baseline.xml")
    juiceshop_ports = [
        o
        for o in observations
        if o.kind is ObservationKind.PORT_OPEN and o.subject.startswith("172.20.1.11:")
    ]
    assert len(juiceshop_ports) == 1
    port = juiceshop_ports[0]
    assert port.attributes["service_name_guess"] == "ppp"
    assert port.attributes["service_method"] == "table"
    # servicefp is huge and attacker-controlled — never transcribed.
    assert "servicefp" not in port.attributes
    assert not any(
        o.kind is ObservationKind.SERVICE_VERSION and o.subject.startswith("172.20.1.11:")
        for o in observations
    )


def test_lab_baseline_host_carries_extraports_and_hostname() -> None:
    observations = _parse("lab_baseline.xml")
    dvwa = next(
        o for o in observations if o.kind is ObservationKind.HOST_UP and o.subject == "172.20.1.10"
    )
    assert dvwa.attributes["extraports_closed"] == "999"
    assert dvwa.attributes["hostname"] == "lab-dvwa-1.lab_dmz"
    assert dvwa.attributes["hostnames"] == "lab-dvwa-1.lab_dmz|PTR"
    assert dvwa.provenance.confidence is Confidence.HIGH  # reason=arp-response


def test_lab_baseline_is_deterministic_across_reparses() -> None:
    first = _parse("lab_baseline.xml")
    second = _parse("lab_baseline.xml")
    assert first == second
    assert [o.model_dump_json() for o in first] == [o.model_dump_json() for o in second]


def test_snapshotted_fixture_matches_what_the_adapter_produces_today() -> None:
    """tests/fixtures/observations/lab_baseline.json is what layers above collection
    read instead of running a scan. If it drifts from what the adapter actually
    produces, every layer built against it would be testing a fiction.
    """
    snapshot = ScanResult.model_validate_json(
        (OBSERVATION_FIXTURES / "lab_baseline.json").read_text(encoding="utf-8")
    )

    adapter = NmapAdapter()
    artifact = adapter._artifact(snapshot.artifact.content)
    observations = parse_nmap_xml(artifact, engagement_id=snapshot.observations[0].engagement_id)

    assert artifact.artifact_id == snapshot.artifact.artifact_id
    assert observations == snapshot.observations


# --------------------------------------------------------------------------- #
# Taxonomy edge cases
# --------------------------------------------------------------------------- #


def test_empty_scan_yields_no_observations() -> None:
    assert _parse("empty.xml") == ()


def test_down_host_yields_no_observations() -> None:
    assert _parse("host_down.xml") == ()


def test_table_method_port_never_emits_service_version() -> None:
    observations = _parse("multi_host_unsorted.xml")
    table_port = next(
        o
        for o in observations
        if o.kind is ObservationKind.PORT_OPEN and o.subject == "172.20.1.11:8080/tcp"
    )
    assert table_port.attributes["service_method"] == "table"
    assert not any(
        o.subject == "172.20.1.11:8080/tcp" and o.kind is ObservationKind.SERVICE_VERSION
        for o in observations
    )


def test_hosts_are_sorted_by_address_regardless_of_document_order() -> None:
    observations = _parse("multi_host_unsorted.xml")
    host_subjects = [o.subject for o in observations if o.kind is ObservationKind.HOST_UP]
    assert host_subjects == ["172.20.1.10", "172.20.1.11"]


def test_ports_are_sorted_within_a_host() -> None:
    observations = _parse("multi_host_unsorted.xml")
    port_subjects = [
        o.subject
        for o in observations
        if o.kind is ObservationKind.PORT_OPEN and o.subject.startswith("172.20.1.11:")
    ]
    assert port_subjects == ["172.20.1.11:80/tcp", "172.20.1.11:8080/tcp"]


def test_multiple_cpe_children_are_sorted_and_joined() -> None:
    observations = _parse("multiple_cpe.xml")
    service = next(o for o in observations if o.kind is ObservationKind.SERVICE_VERSION)
    assert service.attributes["cpe"] == (
        "cpe:/a:apache:http_server:2.4.49,cpe:/a:openssl:openssl:1.1.1k"
    )
    assert service.attributes["tunnel"] == "ssl"


# --------------------------------------------------------------------------- #
# Addressing
# --------------------------------------------------------------------------- #


def test_ipv6_only_host_uses_compressed_bracketed_port_subject() -> None:
    observations = _parse("ipv6_only.xml")
    host = next(o for o in observations if o.kind is ObservationKind.HOST_UP)
    assert host.subject == "2001:db8::10"
    assert host.attributes["address_type"] == "ipv6"
    port = next(o for o in observations if o.kind is ObservationKind.PORT_OPEN)
    assert port.subject == "[2001:db8::10]:80/tcp"


def test_dual_stack_host_prefers_ipv4_and_records_aliases() -> None:
    observations = _parse("dual_stack.xml")
    host = next(o for o in observations if o.kind is ObservationKind.HOST_UP)
    assert host.subject == "172.20.1.50"
    assert host.attributes["address_type"] == "ipv4"
    assert host.attributes["ipv6"] == "2001:db8::50"
    assert host.attributes["mac"] == "aa:bb:cc:dd:ee:ff"
    assert host.attributes["mac_vendor"] == "Example Vendor"
    assert host.attributes["hostname"] == "dual.lab.local"


def test_mac_only_host_uses_mac_subject() -> None:
    observations = _parse("mac_only.xml")
    host = next(o for o in observations if o.kind is ObservationKind.HOST_UP)
    assert host.subject == "mac:11:22:33:44:55:66"
    assert host.attributes["address_type"] == "mac"
    assert host.attributes["mac_vendor"] == "Layer2 Only Corp"


# --------------------------------------------------------------------------- #
# Confidence and the -Pn case
# --------------------------------------------------------------------------- #


def test_pn_scan_host_is_low_confidence_with_note() -> None:
    observations = _parse("pn_scan.xml")
    host = next(o for o in observations if o.kind is ObservationKind.HOST_UP)
    assert host.provenance.confidence is Confidence.LOW
    assert host.provenance.note == "host assumed up (-Pn); never probed"
    # The port itself was still actually probed, so it is unaffected.
    port = next(o for o in observations if o.kind is ObservationKind.PORT_OPEN)
    assert port.provenance.confidence is Confidence.HIGH


# --------------------------------------------------------------------------- #
# Timestamps: fallback chain and the raise-instead-of-now() rule
# --------------------------------------------------------------------------- #


def test_host_with_no_times_falls_back_to_run_level_timestamp() -> None:
    raw = _load("missing_host_times.xml")
    artifact = _artifact("missing_host_times.xml")
    observations = parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)
    host = next(o for o in observations if o.kind is ObservationKind.HOST_UP)
    assert host.observed_at == parse_run_timestamp(raw)


def test_run_timestamp_prefers_runstats_finished() -> None:
    ts = parse_run_timestamp(_load("runstats_finished.xml"))
    assert ts == datetime.fromtimestamp(1700000010, tz=UTC)


def test_run_timestamp_falls_back_to_nmaprun_start() -> None:
    ts = parse_run_timestamp(_load("nmaprun_start_only.xml"))
    assert ts == datetime.fromtimestamp(1700000000, tz=UTC)


def test_run_timestamp_falls_back_to_max_host_endtime() -> None:
    ts = parse_run_timestamp(_load("max_host_endtime_fallback.xml"))
    assert ts == datetime.fromtimestamp(1700000009, tz=UTC)


def test_run_timestamp_raises_rather_than_using_wall_clock() -> None:
    with pytest.raises(NmapParseError, match="no timestamp found"):
        parse_run_timestamp(_load("no_timestamps_at_all.xml"))


def test_invalid_starttime_raises() -> None:
    with pytest.raises(NmapParseError, match="invalid epoch timestamp"):
        # captured_at must itself succeed to construct the artifact; the run-level
        # fallback chain in this fixture works, only the host's own starttime is bad.
        _parse("invalid_starttime.xml", captured_at=datetime.fromtimestamp(1700000010, tz=UTC))


# --------------------------------------------------------------------------- #
# Sanitization
# --------------------------------------------------------------------------- #


def test_control_characters_and_oversized_values_are_sanitized() -> None:
    observations = _parse("malicious_banner.xml")
    service = next(o for o in observations if o.kind is ObservationKind.SERVICE_VERSION)
    assert "\n" not in service.attributes["product"]
    assert service.attributes["product"] == 'Weird"BannerName'
    assert service.attributes["version"].endswith("…[truncated]")
    assert len(service.attributes["version"]) == 512 + len("…[truncated]")


# --------------------------------------------------------------------------- #
# Malformed / hostile input
# --------------------------------------------------------------------------- #


def test_truncated_xml_raises_parse_error() -> None:
    with pytest.raises(NmapParseError, match="malformed nmap XML"):
        parse_run_timestamp(_load("truncated.xml"))


def test_doctype_with_internal_subset_is_rejected() -> None:
    with pytest.raises(NmapParseError, match="internal subset"):
        parse_run_timestamp(_load("doctype_internal_subset.xml"))


def test_doctype_with_external_system_identifier_is_rejected() -> None:
    with pytest.raises(NmapParseError, match="SYSTEM/PUBLIC"):
        parse_run_timestamp(_load("doctype_external_entity.xml"))


def test_real_nmap_doctype_is_allowed() -> None:
    # nmap always emits `<!DOCTYPE nmaprun>` with no internal subset and no external
    # identifier — the guard must not reject nmap's own output.
    parse_run_timestamp(_load("lab_baseline.xml"))


def test_oversized_content_is_rejected_before_parsing() -> None:
    huge = '<nmaprun start="1700000000">' + ("x" * (65 * 1024 * 1024)) + "</nmaprun>"
    with pytest.raises(NmapParseError, match="maximum allowed size"):
        parse_run_timestamp(huge)


def test_malformed_ipv4_address_raises() -> None:
    artifact = RawArtifact(
        artifact_id="sha256:test-bad-ipv4",
        scanner="nmap",
        content=(
            '<?xml version="1.0"?><!DOCTYPE nmaprun>'
            '<nmaprun start="1700000000">'
            '<host><status state="up" reason="syn-ack" reason_ttl="64"/>'
            '<address addr="999.999.999.999" addrtype="ipv4"/>'
            "</host></nmaprun>"
        ),
        content_type="application/xml",
        captured_at=datetime.fromtimestamp(1700000000, tz=UTC),
    )
    with pytest.raises(NmapParseError, match="invalid ipv4 address"):
        parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)


def test_malformed_mac_address_raises() -> None:
    artifact = RawArtifact(
        artifact_id="sha256:test-bad-mac",
        scanner="nmap",
        content=(
            '<?xml version="1.0"?><!DOCTYPE nmaprun>'
            '<nmaprun start="1700000000">'
            '<host><status state="up" reason="syn-ack" reason_ttl="64"/>'
            '<address addr="not-a-mac" addrtype="mac"/>'
            "</host></nmaprun>"
        ),
        content_type="application/xml",
        captured_at=datetime.fromtimestamp(1700000000, tz=UTC),
    )
    with pytest.raises(NmapParseError, match="invalid mac address"):
        parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)


def test_host_with_no_usable_address_raises() -> None:
    artifact = RawArtifact(
        artifact_id="sha256:test-no-address",
        scanner="nmap",
        content=(
            '<?xml version="1.0"?><!DOCTYPE nmaprun>'
            '<nmaprun start="1700000000">'
            '<host><status state="up" reason="syn-ack" reason_ttl="64"/></host>'
            "</nmaprun>"
        ),
        content_type="application/xml",
        captured_at=datetime.fromtimestamp(1700000000, tz=UTC),
    )
    with pytest.raises(NmapParseError, match="no usable address"):
        parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)


# --------------------------------------------------------------------------- #
# Observation identity
# --------------------------------------------------------------------------- #


def test_observation_ids_are_stable_and_unique_within_a_host() -> None:
    observations = _parse("lab_baseline.xml")
    ids = [o.observation_id for o in observations]
    assert len(ids) == len(set(ids)), "observation ids must not collide"
    for obs in observations:
        assert obs.observation_id.startswith("obs:sha256:")


def test_observation_id_changes_if_the_artifact_changes() -> None:
    artifact_a = _artifact("lab_baseline.xml")
    artifact_b = RawArtifact(
        artifact_id="sha256:different-artifact",
        scanner="nmap",
        content=artifact_a.content,
        content_type="application/xml",
        captured_at=artifact_a.captured_at,
    )
    ids_a = {o.observation_id for o in parse_nmap_xml(artifact_a, engagement_id=ENGAGEMENT_ID)}
    ids_b = {o.observation_id for o in parse_nmap_xml(artifact_b, engagement_id=ENGAGEMENT_ID)}
    assert ids_a.isdisjoint(ids_b)


def test_every_observation_references_the_parsed_artifact() -> None:
    artifact = _artifact("lab_baseline.xml")
    observations = parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)
    assert all(o.artifact_id == artifact.artifact_id for o in observations)
