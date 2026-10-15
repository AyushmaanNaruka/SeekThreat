"""Tests for services.scanners.nikto_json. Fixtures live in tests/fixtures/nikto/."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Source
from services.scanners.nikto_json import (
    NiktoParseError,
    parse_nikto_json,
    parse_run_timestamp,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "nikto"
ENGAGEMENT_ID = "eng-nikto-001"
CAPTURED_AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _artifact(content: str, captured_at: datetime = CAPTURED_AT) -> RawArtifact:
    return RawArtifact(
        artifact_id="sha256:test-nikto",
        scanner="nikto",
        content=content,
        content_type="application/json",
        captured_at=captured_at,
    )


def _parse_text(content: str) -> tuple[Observation, ...]:
    return parse_nikto_json(_artifact(content), ENGAGEMENT_ID)


def _parse(name: str) -> tuple[Observation, ...]:
    return _parse_text((FIXTURES / name).read_text(encoding="utf-8"))


def _host(vulns: list[dict[str, object]], **overrides: object) -> str:
    rec = {"host": "10.0.0.5", "ip": "10.0.0.5", "port": "80", "banner": "", **overrides}
    rec["vulnerabilities"] = vulns
    return json.dumps([rec])


# --------------------------------------------------------------------------- #
# Real capture (nikto 2.5.0 against httpd 2.4.49)
# --------------------------------------------------------------------------- #


def test_real_capture_emits_one_vuln_candidate_per_finding() -> None:
    obs = _parse("httpd_2449.json")
    assert len(obs) == 9
    assert {o.kind for o in obs} == {ObservationKind.VULN_CANDIDATE}
    assert {o.scanner for o in obs} == {"nikto"}
    for o in obs:
        assert o.engagement_id == ENGAGEMENT_ID
        assert o.artifact_id == "sha256:test-nikto"
        assert o.provenance.source is Source.SCANNER
        assert o.observed_at == CAPTURED_AT
        assert o.provenance.retrieved_at == CAPTURED_AT


def test_endpoint_is_spelled_like_nmap_port_subject() -> None:
    """nmap's port subject is `<ip>:<port>/<proto>`; the join to port_open depends on it."""
    for o in _parse("httpd_2449.json"):
        assert o.attributes["endpoint"] == "172.20.1.10:80/tcp"
        assert o.subject == "172.20.1.10:80/tcp"


def test_real_capture_attributes_and_no_severity() -> None:
    obs = _parse("httpd_2449.json")
    xst = next(o for o in obs if o.attributes["nikto_id"] == "000434")
    assert xst.attributes["method"] == "TRACE"
    assert xst.attributes["url"] == "/"
    assert xst.attributes["references"] == (
        "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
    )
    assert "XST" in xst.attributes["msg"]
    assert "cve_ids" not in xst.attributes
    for o in obs:
        assert not any("severity" in k or "cvss" in k for k in o.attributes)


def test_version_inferred_finding_is_low_response_based_is_medium() -> None:
    by_id = {o.attributes["nikto_id"]: o for o in _parse("httpd_2449.json")}
    assert by_id["600050"].provenance.confidence is Confidence.LOW  # "appears to be outdated"
    assert by_id["000434"].provenance.confidence is Confidence.MEDIUM  # TRACE answered
    assert by_id["013587"].provenance.confidence is Confidence.MEDIUM
    assert not any(o.provenance.confidence is Confidence.HIGH for o in _parse("httpd_2449.json"))


def test_empty_banner_emits_no_service_version() -> None:
    kinds = {o.kind for o in _parse("httpd_2449.json")}
    assert ObservationKind.SERVICE_VERSION not in kinds


# --------------------------------------------------------------------------- #
# Purity and determinism
# --------------------------------------------------------------------------- #


def test_parse_is_byte_identical_across_runs() -> None:
    first = _parse("httpd_2449.json")
    second = _parse("httpd_2449.json")
    assert [o.model_dump_json() for o in first] == [o.model_dump_json() for o in second]


def test_output_order_is_independent_of_input_order() -> None:
    data = json.loads((FIXTURES / "httpd_2449.json").read_text(encoding="utf-8"))
    forward = _parse_text(json.dumps(data))
    data[0]["vulnerabilities"].reverse()
    backward = _parse_text(json.dumps(data))
    assert [o.observation_id for o in forward] == [o.observation_id for o in backward]


def test_observation_ids_are_content_addressed_and_unique() -> None:
    obs = _parse("httpd_2449.json")
    ids = [o.observation_id for o in obs]
    assert len(set(ids)) == len(ids)
    assert all(i.startswith("obs:sha256:") and len(i) == len("obs:sha256:") + 64 for i in ids)


def test_ids_change_with_engagement_artifact_and_observed_at() -> None:
    content = (FIXTURES / "httpd_2449.json").read_text(encoding="utf-8")
    base = {o.observation_id for o in _parse_text(content)}
    other_eng = {o.observation_id for o in parse_nikto_json(_artifact(content), "eng-other")}
    later = {
        o.observation_id
        for o in parse_nikto_json(_artifact(content, datetime(2026, 11, 1, tzinfo=UTC)), "x")
    }
    assert base.isdisjoint(other_eng)
    assert base.isdisjoint(later)


def test_parse_does_not_read_the_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    import services.scanners.nikto_json as mod

    class Boom:
        @staticmethod
        def now(*_a: object, **_k: object) -> datetime:
            raise AssertionError("parse_nikto_json read the wall clock")

    monkeypatch.setattr(mod, "datetime", Boom)
    assert _parse("httpd_2449.json")


def test_exact_duplicate_findings_collapse_to_one_observation() -> None:
    vuln = {"id": "013587", "method": "GET", "url": "/", "msg": "dup"}
    assert len(_parse_text(_host([vuln, dict(vuln)]))) == 1


def test_parse_run_timestamp_is_aware_utc_and_validates() -> None:
    ts = parse_run_timestamp((FIXTURES / "httpd_2449.json").read_text(encoding="utf-8"))
    assert ts.tzinfo is not None and ts.utcoffset() is not None
    with pytest.raises(NiktoParseError):
        parse_run_timestamp((FIXTURES / "malformed.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Banner, CVE extraction, multiple hosts
# --------------------------------------------------------------------------- #


def test_banner_emits_service_version_joined_to_the_same_endpoint() -> None:
    obs = _parse("multi_host_cve.json")
    sv = [o for o in obs if o.kind is ObservationKind.SERVICE_VERSION]
    apache = next(o for o in sv if o.subject == "172.20.1.10:8080/tcp")
    assert apache.attributes["banner"] == "Apache/2.4.49 (Unix)"
    assert apache.attributes["product"] == "Apache"
    assert apache.attributes["version"] == "2.4.49"
    assert apache.attributes["endpoint"] == "172.20.1.10:8080/tcp"
    assert apache.provenance.confidence is Confidence.MEDIUM
    assert apache.provenance.source is Source.SCANNER

    nginx = next(o for o in sv if o.subject == "172.20.1.11:443/tcp")  # ip preferred over host
    assert nginx.attributes["product"] == "nginx"
    assert "version" not in nginx.attributes
    assert nginx.provenance.confidence is Confidence.LOW
    assert nginx.attributes["host"] == "web.lab.local"


def test_cve_ids_sorted_deduped_uppercased_and_comma_space_joined() -> None:
    obs = _parse("multi_host_cve.json")
    trav = next(o for o in obs if o.attributes.get("nikto_id") == "999001")
    # lower-case in the reference URL, repeated in msg: one upper-case entry each.
    assert trav.attributes["cve_ids"] == "CVE-2021-41773, CVE-2021-42013"


def test_cve_regex_is_strict() -> None:
    obs = _parse("multi_host_cve.json")
    near_miss = next(o for o in obs if o.attributes.get("nikto_id") == "999002")
    assert "cve_ids" not in near_miss.attributes
    assert near_miss.attributes["references"] == "CWE-552"


def test_multiple_hosts_are_all_parsed_and_sorted() -> None:
    obs = _parse("multi_host_cve.json")
    assert {o.subject for o in obs} == {"172.20.1.10:8080/tcp", "172.20.1.11:443/tcp"}
    subjects = [o.subject for o in obs]
    assert subjects == sorted(subjects)


def test_hostname_only_host_falls_back_to_hostname_endpoint() -> None:
    obs = _parse_text(
        _host([{"id": "1", "msg": "m"}], host="web.lab.local", ip="", port="8443"),
    )
    assert obs[0].attributes["endpoint"] == "web.lab.local:8443/tcp"


def test_ipv6_endpoint_is_bracketed_and_compressed() -> None:
    obs = _parse_text(
        _host([{"id": "1", "msg": "m"}], host="::1", ip="0:0:0:0:0:0:0:1", port="80"),
    )
    assert obs[0].attributes["endpoint"] == "[::1]:80/tcp"


@pytest.mark.parametrize("port", ["", "0", "65536", "http", "-1", "80; id"])
def test_invalid_port_yields_no_endpoint_and_nothing_is_defaulted(port: str) -> None:
    obs = _parse_text(_host([{"id": "1", "msg": "m"}], port=port))
    assert "endpoint" not in obs[0].attributes
    assert obs[0].subject == "10.0.0.5"


# --------------------------------------------------------------------------- #
# Real-world quirks
# --------------------------------------------------------------------------- #


def test_unreachable_target_pseudo_finding_is_not_a_candidate() -> None:
    """Nikto reports "Unable to connect" as finding id 0; it is a scan failure."""
    assert _parse("unreachable.json") == ()


def test_empty_vulnerabilities_and_empty_input_yield_nothing() -> None:
    assert _parse("empty_vulnerabilities.json") == ()
    assert _parse_text("") == ()
    assert _parse_text("  \n") == ()
    assert _parse_text("[]") == ()


def test_legacy_single_object_with_osvdb_and_trailing_commas() -> None:
    obs = _parse("legacy_trailing_commas.json")
    assert len(obs) == 3  # service_version + 2 findings
    iis = next(o for o in obs if o.attributes.get("nikto_id") == "999979")
    assert iis.attributes["osvdb"] == "877"
    # a ",]" inside a string survived the trailing-comma repair
    assert ",] inside a string" in iis.attributes["msg"]
    zero = next(o for o in obs if o.attributes.get("nikto_id") == "000001")
    assert "osvdb" not in zero.attributes  # OSVDB 0 means "none"
    sv = next(o for o in obs if o.kind is ObservationKind.SERVICE_VERSION)
    assert sv.attributes["product"] == "Microsoft-IIS"
    assert sv.attributes["version"] == "6.0"


def test_concatenated_documents_one_array_per_host() -> None:
    a = _host([{"id": "1", "msg": "a"}], ip="10.0.0.5", host="10.0.0.5")
    b = _host([{"id": "2", "msg": "b"}], ip="10.0.0.6", host="10.0.0.6")
    obs = _parse_text(a + "\n" + b)
    assert {o.subject for o in obs} == {"10.0.0.5:80/tcp", "10.0.0.6:80/tcp"}


def test_malformed_vulnerability_entries_are_skipped_not_fatal() -> None:
    content = json.dumps(
        [
            {
                "host": "10.0.0.5",
                "ip": "10.0.0.5",
                "port": "80",
                "vulnerabilities": ["junk", 7, None, {"id": "1", "msg": "ok"}, {}],
            },
            "not-a-host",
            {"host": "10.0.0.6", "ip": "10.0.0.6", "port": "80", "vulnerabilities": "nope"},
        ]
    )
    obs = _parse_text(content)
    assert [o.attributes["msg"] for o in obs] == ["ok"]


# --------------------------------------------------------------------------- #
# Errors and hardening
# --------------------------------------------------------------------------- #


def test_malformed_json_raises_nikto_parse_error() -> None:
    with pytest.raises(NiktoParseError):
        _parse("malformed.json")


@pytest.mark.parametrize("content", ["not json", "42", '"str"', "null", "[{", '{"a": }'])
def test_non_nikto_content_raises_nikto_parse_error(content: str) -> None:
    with pytest.raises(NiktoParseError):
        _parse_text(content)


def test_oversized_output_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import services.scanners.nikto_json as mod

    monkeypatch.setattr(mod, "_MAX_CONTENT_BYTES", 100)
    with pytest.raises(NiktoParseError, match="maximum allowed size"):
        _parse_text("[" + " " * 200 + "]")
    with pytest.raises(NiktoParseError, match="maximum allowed size"):
        parse_run_timestamp("[" + " " * 200 + "]")


def test_control_characters_stripped_and_long_values_truncated() -> None:
    long_msg = "A" * 5000
    obs = _parse_text(
        _host(
            [
                {
                    "id": "1\x00",
                    "method": "get\x1b",
                    "url": "/a\r\nb",
                    "msg": "bad\x07msg\x1b[31m" + long_msg,
                    "references": "http://x/\x00y",
                }
            ]
        )
    )
    attrs = obs[0].attributes
    for value in attrs.values():
        assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        assert len(value) <= 512
    assert attrs["msg"].endswith("…[truncated]")
    assert attrs["method"] == "GET"
    assert attrs["url"] == "/ab"


def test_non_string_values_are_coerced_without_crashing() -> None:
    obs = _parse_text(
        '[{"host":"10.0.0.5","ip":"10.0.0.5","port":80,"banner":null,'
        '"vulnerabilities":[{"id":13587,"msg":{"a":1},"url":["x"],"references":null}]}]'
    )
    assert obs[0].attributes["nikto_id"] == "13587"
    assert obs[0].attributes["endpoint"] == "10.0.0.5:80/tcp"
    assert "msg" not in obs[0].attributes


def test_hostile_message_cannot_inject_attributes_or_ids() -> None:
    obs = _parse_text(
        _host([{"id": "1", "msg": "x\x1f\x1e\x00attr\x1evalue", "url": "/", "method": "GET"}])
    )
    assert "\x1f" not in obs[0].attributes["msg"]
    assert "\x1e" not in obs[0].attributes["msg"]
