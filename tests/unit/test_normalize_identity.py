"""Track 1 identity resolution (services/normalize/identity.py, D-045 proposed)."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.normalize.identity import (
    AddressKind,
    IdentityResolver,
    canonical_host,
    is_valid_asset_id,
    parse_endpoint,
)
from services.scanners.nmap_xml import parse_nmap_xml

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
NMAP_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nmap"


def obs(
    obs_id: str,
    *,
    kind: ObservationKind = ObservationKind.VULN_CANDIDATE,
    scanner: str = "nuclei",
    subject: str = "172.20.1.10:80/tcp",
    attrs: dict[str, str] | None = None,
    engagement_id: str = "eng-1",
) -> Observation:
    return Observation(
        observation_id=obs_id,
        engagement_id=engagement_id,
        scanner=scanner,
        kind=kind,
        subject=subject,
        attributes=attrs or {},
        artifact_id="sha256:test",
        observed_at=NOW,
        provenance=Provenance(source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW),
    )


def host_up(obs_id: str, subject: str, **attrs: str) -> Observation:
    return obs(obs_id, kind=ObservationKind.HOST_UP, scanner="nmap", subject=subject, attrs=attrs)


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Identity resolution must never touch the network or the resolver."""

    def boom(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("identity resolution attempted a network/DNS call")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, boom)
    monkeypatch.setattr(socket, "socket", boom)
    yield


# --------------------------------------------------------------------------- #
# Canonicalisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "asset_id", "kind"),
    [
        ("172.20.1.10", "host:172.20.1.10", AddressKind.IPV4),
        (" 172.20.1.10 ", "host:172.20.1.10", AddressKind.IPV4),
        ("2001:0DB8:0000::0010", "host:2001:db8::10", AddressKind.IPV6),
        ("[2001:db8::10]", "host:2001:db8::10", AddressKind.IPV6),
        ("mac:AA:BB:CC:DD:EE:FF", "host:mac:aa:bb:cc:dd:ee:ff", AddressKind.MAC),
        ("mac:aa-bb-cc-dd-ee-ff", "host:mac:aa:bb:cc:dd:ee:ff", AddressKind.MAC),
        ("DVWA.Lab.Local.", "host:dvwa.lab.local", AddressKind.HOSTNAME),
        ("lab-dvwa-1.lab_dmz", "host:lab-dvwa-1.lab_dmz", AddressKind.HOSTNAME),
    ],
)
def test_canonical_host(raw: str, asset_id: str, kind: AddressKind) -> None:
    ref = canonical_host(raw)
    assert ref is not None
    assert ref.kind == kind
    assert ref.asset_id == asset_id
    assert is_valid_asset_id(ref.asset_id)


@pytest.mark.parametrize("raw", ["", "unknown", "mac:zz:bb:cc:dd:ee:ff", "has space", "a/b"])
def test_canonical_host_rejects_unusable(raw: str) -> None:
    assert canonical_host(raw) is None


@pytest.mark.parametrize(
    ("raw", "asset_id", "service"),
    [
        ("172.20.1.10:80/tcp", "host:172.20.1.10", "80/tcp"),
        ("[2001:db8::10]:443/tcp", "host:2001:db8::10", "443/tcp"),
        ("mac:aa:bb:cc:dd:ee:ff:22/tcp", "host:mac:aa:bb:cc:dd:ee:ff", "22/tcp"),
        ("http://DVWA.lab.local.:8080/login.php", "host:dvwa.lab.local", "8080/tcp"),
        ("http://[2001:db8::10]:80/", "host:2001:db8::10", "80/tcp"),
        # No explicit port: none is defaulted from the scheme.
        ("https://dvwa.lab.local/", "host:dvwa.lab.local", ""),
        ("dvwa.lab.local:80", "host:dvwa.lab.local", "80/tcp"),
        ("2001:db8::10", "host:2001:db8::10", ""),
    ],
)
def test_parse_endpoint(raw: str, asset_id: str, service: str) -> None:
    ep = parse_endpoint(raw)
    assert ep is not None
    assert ep.host.asset_id == asset_id
    assert ep.service_key == service


def test_is_valid_asset_id() -> None:
    for good in ("host:10.0.0.1", "host:2001:db8::1", "host:mac:aa:bb:cc:dd:ee:ff", "ast-1"):
        assert is_valid_asset_id(good)
    for bad in ("host:2001:0db8::1", "host:DVWA.local", "host:dvwa.local.", "host:[::1]", "a"):
        assert not is_valid_asset_id(bad)


# --------------------------------------------------------------------------- #
# Joins
# --------------------------------------------------------------------------- #


def test_spelling_variants_resolve_without_evidence() -> None:
    resolver = IdentityResolver([])
    a = resolver.resolve_observation(obs("a", subject="http://[2001:0db8::10]:80/"))
    b = resolver.resolve_observation(obs("b", attrs={"endpoint": "[2001:db8::10]:80/tcp"}))
    assert a is not None and b is not None
    assert a.asset_id == b.asset_id == "host:2001:db8::10"
    assert a.rule is None  # canonicalisation, not a join


def test_hostname_joins_ip_via_nmap_hostnames_attribute() -> None:
    nmap = host_up("h1", "172.20.1.10", ipv4="172.20.1.10", hostnames="dvwa.lab.local|user")
    nuclei = obs("v1", subject="http://DVWA.lab.local.:80/", attrs={"host": "DVWA.lab.local"})
    resolver = IdentityResolver([nmap, nuclei])
    res = resolver.resolve_observation(nuclei)
    assert res is not None
    assert res.asset_id == "host:172.20.1.10"
    assert res.alias == "host:dvwa.lab.local"
    assert res.rule == "nmap_hostname:user"
    assert res.observation_ids == ("h1",)
    assert [link.alias for link in resolver.links] == ["host:dvwa.lab.local"]


def test_hostname_joins_via_scanner_reported_ip() -> None:
    nuclei = obs(
        "v1",
        subject="http://app.lab.local:80/",
        attrs={"host": "app.lab.local", "ip": "172.20.1.11", "endpoint": "app.lab.local:80/tcp"},
    )
    resolver = IdentityResolver([nuclei])
    res = resolver.resolve_observation(nuclei)
    assert res is not None
    assert res.asset_id == "host:172.20.1.11"
    assert res.rule == "scanner_reported_ip"
    assert res.observation_ids == ("v1",)


def test_dual_stack_nmap_record_joins_ipv6_and_mac_to_ipv4() -> None:
    artifact = RawArtifact(
        artifact_id="sha256:dual",
        scanner="nmap",
        content=(NMAP_FIXTURES / "dual_stack.xml").read_text(encoding="utf-8"),
        content_type="application/xml",
        captured_at=NOW,
    )
    nmap = parse_nmap_xml(artifact, engagement_id="eng-1")
    ssh = obs("s1", scanner="ssh-audit", subject="[2001:db8::50]:22/tcp")
    mac = obs("m1", scanner="other", subject="mac:aa:bb:cc:dd:ee:ff:80/tcp")
    named = obs("n1", subject="http://dual.lab.local:80/")
    resolver = IdentityResolver([*nmap, ssh, mac, named])
    for o in (ssh, mac, named):
        res = resolver.resolve_observation(o)
        assert res is not None and res.asset_id == "host:172.20.1.50", o.observation_id
    assert resolver.ambiguities == []


def test_hostname_claimed_by_two_hosts_is_ambiguous_and_unjoined() -> None:
    a = host_up("h1", "172.20.1.10", ipv4="172.20.1.10", hostnames="shared.lab.local|PTR")
    b = host_up("h2", "172.20.1.11", ipv4="172.20.1.11", hostnames="shared.lab.local|PTR")
    nuclei = obs("v1", subject="http://shared.lab.local:80/")
    resolver = IdentityResolver([a, b, nuclei])
    res = resolver.resolve_observation(nuclei)
    assert res is not None
    assert res.asset_id == "host:shared.lab.local"
    assert res.ambiguous
    assert not res.joined
    [amb] = resolver.ambiguities
    assert amb.alias == "host:shared.lab.local"
    assert amb.candidates == ("host:172.20.1.10", "host:172.20.1.11")
    assert amb.observation_ids == ("h1", "h2")


def test_scanner_ip_contradicting_nmap_hostname_is_ambiguous() -> None:
    nmap = host_up("h1", "172.20.1.10", ipv4="172.20.1.10", hostnames="app.lab.local|user")
    nuclei = obs(
        "v1",
        subject="http://app.lab.local:80/",
        attrs={"host": "app.lab.local", "ip": "172.20.1.99"},
    )
    resolver = IdentityResolver([nmap, nuclei])
    res = resolver.resolve_observation(nuclei)
    assert res is not None and res.asset_id == "host:app.lab.local" and res.ambiguous


def test_mac_seen_with_two_ipv4s_is_ambiguous_but_ips_stay_themselves() -> None:
    a = host_up("h1", "10.0.0.1", ipv4="10.0.0.1", mac="aa:bb:cc:dd:ee:01")
    b = host_up("h2", "10.0.0.2", ipv4="10.0.0.2", mac="aa:bb:cc:dd:ee:01")
    resolver = IdentityResolver([a, b])
    mac_res = resolver.resolve_observation(obs("m", subject="mac:aa:bb:cc:dd:ee:01:80/tcp"))
    assert mac_res is not None
    assert mac_res.asset_id == "host:mac:aa:bb:cc:dd:ee:01" and mac_res.ambiguous
    ip_res = resolver.resolve_observation(obs("i", subject="10.0.0.2:80/tcp"))
    assert ip_res is not None and ip_res.asset_id == "host:10.0.0.2"
    [amb] = resolver.ambiguities
    assert amb.candidates == ("host:10.0.0.1", "host:10.0.0.2")


def test_hostname_does_not_glue_two_addresses_together() -> None:
    """Hostname links are one-way; they never merge address components."""
    a = host_up("h1", "10.0.0.1", ipv4="10.0.0.1", hostnames="x.lab|PTR")
    b = host_up("h2", "2001:db8::2", ipv6="2001:db8::2", hostnames="x.lab|PTR")
    resolver = IdentityResolver([a, b])
    v6 = resolver.resolve_observation(obs("v", subject="[2001:db8::2]:80/tcp"))
    assert v6 is not None and v6.asset_id == "host:2001:db8::2"


def test_unknown_host_resolves_to_none() -> None:
    resolver = IdentityResolver([])
    assert resolver.resolve_observation(obs("u", subject="unknown")) is None


def test_resolution_is_order_independent() -> None:
    items = [
        host_up("h1", "172.20.1.10", ipv4="172.20.1.10", hostnames="dvwa.lab|PTR"),
        host_up("h2", "2001:db8::10", ipv6="2001:db8::10", mac="aa:bb:cc:dd:ee:10"),
        host_up("h3", "172.20.1.10", ipv4="172.20.1.10", ipv6="2001:db8::10"),
    ]
    forward = IdentityResolver(items)
    backward = IdentityResolver(list(reversed(items)))
    assert forward.links == backward.links
    assert forward.ambiguities == backward.ambiguities
    mac = obs("m", subject="mac:aa:bb:cc:dd:ee:10:22/tcp")
    res = forward.resolve_observation(mac)
    assert res is not None and res.asset_id == "host:172.20.1.10"
