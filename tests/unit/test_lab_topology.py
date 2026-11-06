"""lab/topology.yaml must stay a faithful transcription of lab/docker-compose.yml.

The attack-graph engine reasons over the declared topology, not over compose, so a
drift between the two would silently change which lateral moves the engine allows.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest
import yaml

from packages.schema.models.topology import NetworkTopology

LAB_DIR = Path(__file__).resolve().parent.parent.parent / "lab"
COMPOSE_PATH = LAB_DIR / "docker-compose.yml"
TOPOLOGY_PATH = LAB_DIR / "topology.yaml"
SCANNER = "scanner"


def _load(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    data = _load(COMPOSE_PATH)
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def topology_raw() -> dict[str, Any]:
    data = _load(TOPOLOGY_PATH)
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def topology(topology_raw: dict[str, Any]) -> NetworkTopology:
    return NetworkTopology.model_validate(topology_raw)


def _network_subnets(compose: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, spec in compose["networks"].items():
        subnets = [c["subnet"] for c in spec["ipam"]["config"]]
        assert len(subnets) == 1, f"network {name} must declare exactly one subnet"
        out[name] = str(ip_network(subnets[0]))
    return out


def _container_addresses(compose: dict[str, Any]) -> dict[str, dict[str, str]]:
    """{container: {network: ipv4_address}}."""
    out: dict[str, dict[str, str]] = {}
    for name, spec in compose["services"].items():
        networks = spec.get("networks") or {}
        assert isinstance(networks, dict), f"{name}: networks must map name -> address"
        out[name] = {net: (cfg or {})["ipv4_address"] for net, cfg in networks.items()}
    return out


def _zone_for_cidr(topology: NetworkTopology, cidr: str) -> str:
    matches = [z.name for z in topology.zones if cidr in z.cidrs]
    assert len(matches) == 1, f"subnet {cidr} must be the CIDR of exactly one zone"
    return matches[0]


def test_topology_validates(topology: NetworkTopology) -> None:
    assert topology.topology_id.startswith("topology:sha256:")
    assert topology.engagement_id == "eng-lab-baseline"


def test_every_compose_subnet_is_a_zone_cidr(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    for network, cidr in _network_subnets(compose).items():
        zone = _zone_for_cidr(topology, cidr)
        assert zone == network, f"subnet {cidr} is network {network} but zone {zone}"


def test_every_zone_cidr_is_a_compose_subnet(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    subnets = set(_network_subnets(compose).values())
    for zone in topology.zones:
        for cidr in zone.cidrs:
            assert cidr in subnets, f"zone {zone.name} declares {cidr}, not a compose subnet"


def test_container_addresses_fall_in_matching_zone(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    subnets = _network_subnets(compose)
    for container, addresses in _container_addresses(compose).items():
        for network, address in addresses.items():
            zone = topology.zone(_zone_for_cidr(topology, subnets[network]))
            assert zone.contains(address), (
                f"{container} has {address} on {network}, outside zone {zone.name}"
            )
            assert topology.zones_of(address) == (zone.name,)


def test_multi_homed_hosts_match_compose_exactly(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    expected = {
        name: {ip_address(a).compressed for a in addresses.values()}
        for name, addresses in _container_addresses(compose).items()
        if len(addresses) >= 2
    }
    declared = {h.name: set(h.addresses) for h in topology.multi_homed_hosts}
    assert declared == expected


def test_scanner_sits_in_the_attacker_entry_zone(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    subnets = _network_subnets(compose)
    scanner_networks = _container_addresses(compose)[SCANNER]
    assert scanner_networks, "the scanner container must be attached to a network"
    entry = {z.name for z in topology.zones if z.attacker_entry}
    for network in scanner_networks:
        assert _zone_for_cidr(topology, subnets[network]) in entry
    assert entry == {_zone_for_cidr(topology, subnets[n]) for n in scanner_networks}


def test_no_cross_zone_flows_while_networks_are_isolated(
    compose: dict[str, Any], topology: NetworkTopology
) -> None:
    # Every compose network is `internal: true` and no container routes between them,
    # so the only path between zones is a multi-homed container. A declared flow would
    # grant reachability compose does not have.
    assert all(spec.get("internal") is True for spec in compose["networks"].values())
    assert topology.flows == ()
