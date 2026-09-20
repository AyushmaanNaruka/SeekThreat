"""Tests for lab/ground_truth.yaml and lab/docker-compose.yml.

Ensures that the lab environment topology and ground truth baseline:
1. Conform to the schema expected by evaluation metrics (Track A / Track B).
2. Adhere to the 8-12 hosts constraint across the 3 isolated subnets (dmz, internal, data).
3. Maintain exact cross-consistency between ground_truth.yaml and docker-compose.yml.
4. Contain realistic multi-hop attack paths and valid CVE specifications.
"""

import re
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest
import yaml

LAB_DIR = Path(__file__).resolve().parent.parent.parent / "lab"
GROUND_TRUTH_PATH = LAB_DIR / "ground_truth.yaml"
DOCKER_COMPOSE_PATH = LAB_DIR / "docker-compose.yml"


@pytest.fixture(scope="module")
def ground_truth() -> dict:
    assert GROUND_TRUTH_PATH.exists(), f"Missing ground truth file at {GROUND_TRUTH_PATH}"
    with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "ground_truth.yaml must parse into a dict"
    return data


@pytest.fixture(scope="module")
def docker_compose() -> dict:
    assert DOCKER_COMPOSE_PATH.exists(), f"Missing docker-compose file at {DOCKER_COMPOSE_PATH}"
    with open(DOCKER_COMPOSE_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict), "docker-compose.yml must parse into a dict"
    return data


class TestGroundTruthSchema:
    def test_top_level_metadata(self, ground_truth: dict) -> None:
        assert ground_truth.get("configuration") == "baseline"
        assert "description" in ground_truth and len(ground_truth["description"]) > 0
        assert "created" in ground_truth

    def test_network_subnets(self, ground_truth: dict) -> None:
        networks = ground_truth.get("network", {})
        assert set(networks.keys()) == {"dmz", "internal", "data"}
        for cidr in networks.values():
            net = ip_network(cidr)
            assert net.version == 4
            assert net.prefixlen == 24

    def test_host_count_within_specification(self, ground_truth: dict) -> None:
        hosts = ground_truth.get("hosts", [])
        assert 8 <= len(hosts) <= 12, f"Expected 8-12 hosts, found {len(hosts)}"
        # Unique host names and IPs
        names = [h["name"] for h in hosts]
        assert len(names) == len(set(names)), "Host names must be unique"
        ips = [h["ip"] for h in hosts]
        assert len(ips) == len(set(ips)), "Primary host IPs must be unique"

    def test_host_ip_matches_segment(self, ground_truth: dict) -> None:
        networks = {name: ip_network(cidr) for name, cidr in ground_truth["network"].items()}
        for host in ground_truth["hosts"]:
            segment = host["segment"]
            assert segment in networks, f"Unknown segment {segment} for host {host['name']}"
            host_ip = ip_address(host["ip"])
            assert host_ip in networks[segment], (
                f"Host {host['name']} IP {host_ip} does not belong to segment "
                f"{segment} ({networks[segment]})"
            )
            if "secondary_ip" in host:
                sec_ip = ip_address(host["secondary_ip"])
                # Secondary IP should be in internal or data
                assert any(sec_ip in net for net in networks.values())

    def test_services_definition(self, ground_truth: dict) -> None:
        for host in ground_truth["hosts"]:
            services = host.get("services", [])
            assert len(services) > 0, f"Host {host['name']} must declare at least one service"
            for svc in services:
                assert 1 <= svc["port"] <= 65535
                assert svc["service"] in {"http", "ssh", "postgresql", "redis"}
                assert "product" in svc and len(svc["product"]) > 0
                assert "version" in svc and len(svc["version"]) > 0

    def test_expected_cves_schema(self, ground_truth: dict) -> None:
        cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        valid_confidences = {"certain", "likely", "possible"}
        all_cve_ids = []

        for host in ground_truth["hosts"]:
            for cve in host.get("expected_cves", []):
                cve_id = cve["id"]
                assert cve_pattern.match(cve_id), f"Invalid CVE format: {cve_id}"
                assert cve["confidence"] in valid_confidences
                assert 0.0 <= float(cve["cvss"]) <= 10.0
                assert "note" in cve and len(cve["note"]) > 0
                all_cve_ids.append(cve_id)

        assert len(all_cve_ids) >= 8, "Expected at least 8 total CVEs across the lab baseline"

    def test_expected_attack_paths(self, ground_truth: dict) -> None:
        paths = ground_truth.get("expected_attack_paths", [])
        assert len(paths) >= 3, "Expected at least 3 distinct attack paths"
        valid_severities = {"critical", "high", "medium", "low"}

        for path in paths:
            assert "id" in path
            assert "description" in path and len(path["description"]) > 10
            assert path.get("severity") in valid_severities
            steps = path.get("steps", [])
            assert len(steps) >= 3, f"Attack path {path['id']} must have at least 3 steps"

    def test_known_false_positives(self, ground_truth: dict) -> None:
        fps = ground_truth.get("known_false_positives", [])
        assert len(fps) > 0, "Expected at least 1 known false positive for metric benchmark"
        for fp in fps:
            assert fp["id"].startswith("CVE-")
            assert fp["scanner"] in {"nmap", "nuclei"}
            assert "target" in fp
            assert "reason" in fp and len(fp["reason"]) > 0


class TestDockerComposeCrossConsistency:
    def test_docker_compose_networks_isolated(self, docker_compose: dict) -> None:
        networks = docker_compose.get("networks", {})
        assert set(networks.keys()) == {"dmz", "internal", "data"}
        for net_name, config in networks.items():
            assert config.get("internal") is True, f"Network {net_name} must have internal: true"
            ipam_configs = config.get("ipam", {}).get("config", [])
            assert len(ipam_configs) == 1
            subnet = ipam_configs[0].get("subnet")
            assert subnet in {"172.20.1.0/24", "172.20.2.0/24", "172.20.3.0/24"}

    def test_all_ground_truth_hosts_in_compose(
        self, ground_truth: dict, docker_compose: dict
    ) -> None:
        compose_services = docker_compose.get("services", {})
        for host in ground_truth["hosts"]:
            name = host["name"]
            assert name in compose_services, (
                f"Host {name} in ground_truth not found in docker-compose.yml"
            )
            service_def = compose_services[name]
            svc_networks = service_def.get("networks", {})
            primary_segment = host["segment"]
            assert primary_segment in svc_networks, (
                f"Host {name} missing network {primary_segment} in docker-compose"
            )
            assert svc_networks[primary_segment]["ipv4_address"] == host["ip"], (
                f"IP mismatch for host {name} in network {primary_segment}"
            )
            if "secondary_ip" in host:
                sec_ip = host["secondary_ip"]
                # Match secondary network
                matched_sec = any(
                    net_cfg.get("ipv4_address") == sec_ip
                    for net_name, net_cfg in svc_networks.items()
                    if net_name != primary_segment
                )
                assert matched_sec, f"Host {name} secondary IP {sec_ip} not configured in compose"

    def test_scanner_service_configured(self, docker_compose: dict) -> None:
        services = docker_compose.get("services", {})
        assert "scanner" in services, "scanner service must be defined in docker-compose.yml"
        scanner = services["scanner"]
        assert scanner.get("image") == "instrumentisto/nmap:latest"
        assert scanner["networks"]["dmz"]["ipv4_address"] == "172.20.1.250"
