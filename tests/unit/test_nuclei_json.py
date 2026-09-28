"""Tests for services.scanners.nuclei_json and services.scanners.nuclei_adapter.

Fixtures live in tests/fixtures/nuclei/.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packages.schema import Authorization, ScanRequest
from packages.schema.models.observation import ObservationKind, RawArtifact, ScanResult
from packages.schema.models.provenance import Confidence, Source
from services.scanners.nuclei_adapter import NucleiAdapter
from services.scanners.nuclei_json import (
    NucleiParseError,
    parse_nuclei_json,
    parse_run_timestamp,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nuclei"
ENGAGEMENT_ID = "eng-nuclei-001"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _artifact(name: str, captured_at: datetime | None = None) -> RawArtifact:
    raw = _load(name)
    if captured_at is None:
        captured_at = parse_run_timestamp(raw)
    return RawArtifact(
        artifact_id=f"sha256:test-{name}",
        scanner="nuclei",
        content=raw,
        content_type="application/x-ndjson",
        captured_at=captured_at,
    )


def _parse(name: str, captured_at: datetime | None = None):
    artifact = _artifact(name, captured_at)
    return parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)


# --------------------------------------------------------------------------- #
# Baseline fixture tests
# --------------------------------------------------------------------------- #


def test_lab_baseline_emits_expected_observations() -> None:
    observations = _parse("lab_baseline.jsonl")
    assert len(observations) == 3

    # All Nuclei findings are VULN_CANDIDATE
    for obs in observations:
        assert obs.kind == ObservationKind.VULN_CANDIDATE
        assert obs.scanner == "nuclei"
        assert obs.engagement_id == ENGAGEMENT_ID
        assert obs.artifact_id == "sha256:test-lab_baseline.jsonl"
        assert obs.provenance.source == Source.SCANNER


def test_cve_extraction_and_attributes() -> None:
    observations = _parse("lab_baseline.jsonl")

    # Map by template_id
    by_template = {obs.attributes["template_id"]: obs for obs in observations}
    assert "cve-2021-44228" in by_template
    assert "cve-2021-41773" in by_template
    assert "nginx-version" in by_template

    # 1. Log4j Critical
    log4j = by_template["cve-2021-44228"]
    assert log4j.attributes["cve_ids"] == "CVE-2021-44228"
    assert log4j.attributes["cwe_ids"] == "CWE-502"
    assert log4j.attributes["cvss_score"] == "10.0"
    assert log4j.attributes["scanner_severity"] == "critical"
    assert log4j.attributes["matcher_name"] == "ldap-jndi"
    assert log4j.provenance.confidence == Confidence.HIGH
    assert log4j.subject == "http://172.20.1.10:8080/login"

    # 2. Apache HTTP Path Traversal High
    apache = by_template["cve-2021-41773"]
    assert apache.attributes["cve_ids"] == "CVE-2021-41773"
    assert apache.attributes["cwe_ids"] == "CWE-22"
    assert apache.attributes["cvss_score"] == "7.5"
    assert apache.attributes["scanner_severity"] == "high"
    assert "etc/passwd" in apache.attributes["matched_at"]
    assert apache.provenance.confidence == Confidence.HIGH

    # 3. Nginx Version Info
    nginx = by_template["nginx-version"]
    assert nginx.attributes["scanner_severity"] == "info"
    assert nginx.attributes["extracted_results"] == "nginx/1.18.0"
    assert nginx.provenance.confidence == Confidence.LOW


def test_empty_output_produces_empty_tuple() -> None:
    assert _parse("empty.jsonl") == ()


def test_single_cve_fixture() -> None:
    observations = _parse("single_cve.jsonl")
    assert len(observations) == 1
    obs = observations[0]
    assert obs.attributes["template_id"] == "cve-2021-44228"
    assert obs.attributes["curl_command"].startswith("curl")


def test_json_array_format() -> None:
    observations = _parse("json_array.json")
    assert len(observations) == 1
    assert observations[0].attributes["template_id"] == "cve-2021-44228"


def test_malformed_json_raises_nuclei_parse_error() -> None:
    with pytest.raises(NucleiParseError, match="Malformed Nuclei JSONL"):
        _parse("malformed.jsonl")


def test_malicious_attributes_sanitized_and_truncated() -> None:
    observations = _parse("malicious_attributes.jsonl")
    assert len(observations) == 1
    obs = observations[0]

    # Null bytes and control characters stripped
    assert "\x00" not in obs.subject
    assert "\x00" not in obs.attributes["template_name"]
    assert "\x1f" not in obs.attributes["template_name"]

    # Oversized description truncated with marker
    desc = obs.attributes["description"]
    assert desc.endswith("…[truncated]")
    assert len(desc) <= 512


def test_pure_function_deterministic_output() -> None:
    artifact = _artifact("lab_baseline.jsonl")
    run1 = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)
    run2 = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)

    assert len(run1) == len(run2)
    for o1, o2 in zip(run1, run2, strict=True):
        assert o1.observation_id == o2.observation_id
        assert o1.attributes == o2.attributes
        assert o1.subject == o2.subject


def test_size_limit_guard() -> None:
    huge = "a" * (65 * 1024 * 1024)
    huge_artifact = RawArtifact(
        artifact_id="sha256:huge",
        scanner="nuclei",
        content=huge,
        content_type="application/x-ndjson",
        captured_at=datetime.now(UTC),
    )
    with pytest.raises(NucleiParseError, match="exceeds maximum allowed size"):
        parse_nuclei_json(huge_artifact, engagement_id=ENGAGEMENT_ID)


def test_parse_run_timestamp() -> None:
    raw = _load("lab_baseline.jsonl")
    ts = parse_run_timestamp(raw)
    # Latest timestamp in lab_baseline is 2026-09-19T10:15:40.000000Z
    assert ts == datetime(2026, 9, 19, 10, 15, 40, tzinfo=UTC)

    # Empty string falls back to current time
    now_before = datetime.now(UTC)
    fallback_ts = parse_run_timestamp("")
    now_after = datetime.now(UTC)
    assert now_before <= fallback_ts <= now_after


# --------------------------------------------------------------------------- #
# NucleiAdapter unit test with mocked execution
# --------------------------------------------------------------------------- #


def test_nuclei_adapter_scan_mocked_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_output = _load("lab_baseline.jsonl")

    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "_execute", lambda req: raw_output)

    now = datetime.now(UTC)
    auth = Authorization(
        engagement_id="eng-adapter-test",
        authorized_by="operator",
        allowlist=["172.20.0.0/16"],
        granted_at=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=24),
    )
    request = ScanRequest(target="172.20.1.10", authorization=auth)

    result = adapter.scan(request)
    assert isinstance(result, ScanResult)
    assert result.artifact.scanner == "nuclei"
    assert result.artifact.content_type == "application/x-ndjson"
    assert len(result.observations) == 3
    for obs in result.observations:
        assert obs.artifact_id == result.artifact.artifact_id
        assert obs.engagement_id == "eng-adapter-test"


# --------------------------------------------------------------------------- #
# Real nuclei v3 output shape
#
# The fixtures above were hand-authored. `real_capture_v3.11.1.jsonl` is a verbatim
# capture from nuclei v3.11.1, and it is what proves the parser reads the field set
# the tool actually emits rather than the one the fixtures assumed.
# --------------------------------------------------------------------------- #


def test_real_capture_uses_bare_host_with_separate_port_and_scheme() -> None:
    """nuclei v3 reports `host` bare, with port/scheme/url in their own fields.

    The older fixtures put a whole URL in `host`, which nuclei has not done since v3.0.
    A parser that only reads `host` silently loses the port.
    """
    raw = _load("real_capture_v3.11.1.jsonl")
    record = json.loads(raw.strip())

    assert record["host"] == "127.0.0.1"
    assert record["port"] == "8799"
    assert record["scheme"] == "http"
    assert record["url"] == "http://127.0.0.1:8799"
    assert record["matcher-status"] is True
    # -ot is passed on every run, so no base64 template copy rides along.
    assert "template-encoded" not in record

    observations = _parse("real_capture_v3.11.1.jsonl")
    assert len(observations) == 1
    attrs = observations[0].attributes
    assert attrs["host"] == "127.0.0.1"
    assert attrs["port"] == "8799"
    assert attrs["scheme"] == "http"
    assert attrs["url"] == "http://127.0.0.1:8799"
    assert attrs["endpoint"] == "127.0.0.1:8799/tcp"


def test_endpoint_is_spelled_like_an_nmap_port_subject() -> None:
    """The endpoint attribute is the join key back to nmap's port facts.

    nmap keys every port_open / service_version observation by `<host>:<port>/<proto>`
    (services/scanners/nmap_xml.py::_port_subject). A vuln_candidate that does not
    spell its listener identically cannot be attached to the service it was found on.
    """
    for obs in _parse("lab_extended.jsonl"):
        endpoint = obs.attributes["endpoint"]
        host, _, port_proto = endpoint.rpartition(":")
        port, _, proto = port_proto.partition("/")
        assert host
        assert port.isdigit()
        assert proto == "tcp"


def test_matcher_status_false_records_are_not_findings() -> None:
    """A record whose matcher did not fire is not a vulnerability candidate."""
    raw = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "did-not-match",
                    "info": {"name": "n", "severity": "high"},
                    "type": "http",
                    "host": "127.0.0.1",
                    "port": "80",
                    "matched-at": "http://127.0.0.1:80/",
                    "timestamp": "2026-09-19T10:15:30.123456Z",
                    "matcher-status": False,
                }
            ),
            json.dumps(
                {
                    "template-id": "did-match",
                    "info": {"name": "n", "severity": "high"},
                    "type": "http",
                    "host": "127.0.0.1",
                    "port": "80",
                    "matched-at": "http://127.0.0.1:80/",
                    "timestamp": "2026-09-19T10:15:30.123456Z",
                    "matcher-status": True,
                }
            ),
        ]
    )
    artifact = RawArtifact(
        artifact_id="sha256:matcher-status",
        scanner="nuclei",
        content=raw,
        content_type="application/x-ndjson",
        captured_at=datetime(2026, 9, 19, tzinfo=UTC),
    )
    observations = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)
    assert [o.attributes["template_id"] for o in observations] == ["did-match"]


def test_network_template_host_carries_host_and_port() -> None:
    """Network templates report `host` as "host:port" with no separate port field."""
    raw = json.dumps(
        {
            "template-id": "redis-detect",
            "info": {"name": "Redis Service - Detect", "severity": "info"},
            "type": "network",
            "host": "172.20.3.20:6379",
            "ip": "172.20.3.20",
            "matched-at": "172.20.3.20:6379",
            "timestamp": "2026-09-19T10:15:30.123456Z",
        }
    )
    artifact = RawArtifact(
        artifact_id="sha256:network",
        scanner="nuclei",
        content=raw,
        content_type="application/x-ndjson",
        captured_at=datetime(2026, 9, 19, tzinfo=UTC),
    )
    (obs,) = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)
    assert obs.attributes["endpoint"] == "172.20.3.20:6379/tcp"


def test_no_endpoint_emitted_when_the_port_is_unknown() -> None:
    """A port defaulted from the scheme would be an inference, not an observation."""
    raw = json.dumps(
        {
            "template-id": "no-port",
            "info": {"name": "n", "severity": "info"},
            "type": "http",
            "host": "example.test",
            "matched-at": "https://example.test/",
            "timestamp": "2026-09-19T10:15:30.123456Z",
        }
    )
    artifact = RawArtifact(
        artifact_id="sha256:no-port",
        scanner="nuclei",
        content=raw,
        content_type="application/x-ndjson",
        captured_at=datetime(2026, 9, 19, tzinfo=UTC),
    )
    (obs,) = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)
    assert "endpoint" not in obs.attributes


def test_template_tags_are_preserved() -> None:
    """Tags decide whether a finding was reachable under the adapter's -etags policy,
    so they have to survive into the fact store to be auditable."""
    by_template = {o.attributes["template_id"]: o for o in _parse("lab_extended.jsonl")}
    assert "dos" in by_template["cve-2021-23017"].attributes["tags"]
