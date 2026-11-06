"""Target parsing and expansion for multi-target scan launches (D-045)."""

from __future__ import annotations

import pytest

from apps.api.core.targets import (
    MAX_SCANS_PER_BATCH,
    TargetPlanError,
    plan_targets,
)


def _targets(plan) -> list[str]:
    return [p.target for p in plan.planned]


def test_splits_on_commas_whitespace_semicolons_and_newlines() -> None:
    plan = plan_targets("nmap", ["172.20.1.10, 172.20.1.11;172.20.1.12\n172.20.1.13  lab.local"])
    assert _targets(plan) == [
        "172.20.1.10",
        "172.20.1.11",
        "172.20.1.12",
        "172.20.1.13",
        "lab.local",
    ]
    assert plan.rejected == []


def test_duplicates_are_planned_once() -> None:
    plan = plan_targets("nmap", ["172.20.1.10", "172.20.1.10, 172.20.1.10"])
    assert _targets(plan) == ["172.20.1.10"]


def test_nmap_scans_a_cidr_as_one_network_job_with_discovery() -> None:
    plan = plan_targets("nmap", ["172.20.1.0/24"], {"no_ping": True})
    assert len(plan.planned) == 1
    item = plan.planned[0]
    assert (item.target, item.kind) == ("172.20.1.0/24", "network")
    assert "no_ping" not in item.options


def test_nmap_single_host_keeps_no_ping() -> None:
    plan = plan_targets("nmap", ["172.20.1.10"], {"no_ping": True})
    assert plan.planned[0].options == {"no_ping": True}


def test_cidr_with_host_bits_is_normalized_with_a_note() -> None:
    plan = plan_targets("nmap", ["172.20.1.5/24"])
    assert plan.planned[0].target == "172.20.1.0/24"
    assert "normalized" in (plan.planned[0].note or "")


def test_large_ipv4_block_is_split_for_nmap() -> None:
    plan = plan_targets("nmap", ["172.20.0.0/16"])
    assert len(plan.planned) == 64
    assert all(p.target.endswith("/22") for p in plan.planned)


def test_huge_block_is_refused_not_truncated() -> None:
    with pytest.raises(TargetPlanError):
        plan_targets("nmap", ["10.0.0.0/8"])
    with pytest.raises(TargetPlanError):
        plan_targets("nikto", ["172.20.0.0/16"])


def test_short_ipv4_range_expands_per_host_for_service_scanners() -> None:
    plan = plan_targets("ssh-audit", ["172.20.1.10-12"])
    assert _targets(plan) == ["172.20.1.10", "172.20.1.11", "172.20.1.12"]
    assert all(p.options == {"port": "22"} for p in plan.planned)


def test_full_ipv4_range_for_nmap_becomes_minimal_blocks() -> None:
    plan = plan_targets("nmap", ["172.20.1.0-172.20.1.7"])
    assert _targets(plan) == ["172.20.1.0/29"]


def test_url_becomes_bare_host_plus_scheme_and_port() -> None:
    plan = plan_targets("nikto", ["https://web.lab.local:8443/login?x=1"])
    item = plan.planned[0]
    assert item.target == "web.lab.local"
    assert item.options == {"scheme": "https", "port": "8443"}
    assert item.note and "path" in item.note


def test_nikto_default_port_follows_scheme() -> None:
    plan = plan_targets("nikto", ["https://172.20.1.10", "172.20.1.11"])
    assert [p.options for p in plan.planned] == [
        {"scheme": "https", "port": "443"},
        {"scheme": "http", "port": "80"},
    ]


def test_host_port_and_bracketed_ipv6() -> None:
    plan = plan_targets("nuclei", ["172.20.1.10:3000", "[fd00::1]:8080", "fd00::2"])
    assert [(p.target, p.options) for p in plan.planned] == [
        ("172.20.1.10", {"scheme": "http", "port": "3000"}),
        ("fd00::1", {"scheme": "http", "port": "8080"}),
        ("fd00::2", {"scheme": "http"}),
    ]


def test_nmap_port_from_entry_goes_to_ports_option() -> None:
    plan = plan_targets("nmap", ["172.20.1.10:5432"])
    assert plan.planned[0].options == {"ports": "5432"}


@pytest.mark.parametrize(
    "raw",
    [
        "*.lab.local",
        "http://attacker.com@172.20.1.10",
        "http://evil.example\\@172.20.1.10/",
        "ftp://172.20.1.10",
        "172.20.1.10:99999",
        "172.20.1.10:abc",
        "fe80::1%eth0",
        "172.20.1.0/255.255.255.0",
        "172.20.1.20-10",
        "-oX",
        "not_a_host!",
        "172.20.1.300",
    ],
)
def test_bad_entries_are_rejected_with_a_reason(raw: str) -> None:
    plan = plan_targets("nmap", [raw, "172.20.1.10"])
    assert _targets(plan) == ["172.20.1.10"]
    assert len(plan.rejected) == 1
    assert plan.rejected[0].input == raw and plan.rejected[0].reason


def test_empty_input_and_unknown_scanner() -> None:
    with pytest.raises(TargetPlanError):
        plan_targets("nmap", [" ,\n "])
    with pytest.raises(TargetPlanError):
        plan_targets("masscan", ["172.20.1.10"])


def test_cap_counts_planned_scans() -> None:
    hosts = [f"172.20.{i // 250}.{i % 250 + 1}" for i in range(MAX_SCANS_PER_BATCH)]
    assert len(plan_targets("nmap", hosts).planned) == MAX_SCANS_PER_BATCH
    with pytest.raises(TargetPlanError):
        plan_targets("nmap", [*hosts, "172.20.9.9"])
