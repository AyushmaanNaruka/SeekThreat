"""Cross-consistency tests for tests/fixtures/observations/.

Mirrors the spirit of tests/unit/test_ground_truth.py: this suite doesn't test parser
behavior (that's test_nmap_xml.py / test_nuclei_json.py) — it proves the fixture *set*,
taken together, actually delivers what docs/02-architecture.md promises: every host in
lab/ground_truth.yaml testable offline, with real vuln_candidate evidence present for at
least one of them. See tests/fixtures/observations/README.md for which files are real
captures and which are synthetic (hand-authored tool output run through the real
parsers via scripts/build_observation_fixtures.py).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from packages.schema.models.observation import Observation, ObservationKind, ScanResult

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "observations"
GROUND_TRUTH_PATH = Path(__file__).resolve().parent.parent.parent / "lab" / "ground_truth.yaml"


def _fixture_paths() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.json"))


def _load_ground_truth() -> dict[str, Any]:
    with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    return data


def _ground_truth_host_addresses() -> dict[str, set[str]]:
    """host name -> {ip, secondary_ip if present}, straight from ground_truth.yaml."""
    data = _load_ground_truth()
    hosts: dict[str, set[str]] = {}
    for host in data["hosts"]:
        addrs = {host["ip"]}
        if "secondary_ip" in host:
            addrs.add(host["secondary_ip"])
        hosts[host["name"]] = addrs
    return hosts


@pytest.fixture(scope="module")
def all_observations() -> list[Observation]:
    paths = _fixture_paths()
    assert paths, f"no observation fixtures found under {FIXTURES_DIR}"
    observations: list[Observation] = []
    for path in paths:
        scan_result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        observations.extend(scan_result.observations)
    return observations


def test_at_least_the_real_and_synthetic_fixtures_are_present() -> None:
    names = {p.name for p in _fixture_paths()}
    assert "lab_baseline.json" in names, "the real capture must never be removed"
    assert len(names) >= 2, "expected at least the real fixture plus synthetic coverage"


def test_every_ground_truth_host_is_covered_by_a_host_up_observation(
    all_observations: list[Observation],
) -> None:
    """The union of subjects across every fixture file must cover all 10 lab hosts.

    HOST_UP.subject is always the bare canonical host address (docs/02-architecture.md,
    "The nmap observation taxonomy"), so this is a direct membership check against each
    host's ip / secondary_ip in lab/ground_truth.yaml.
    """
    host_up_subjects = {o.subject for o in all_observations if o.kind is ObservationKind.HOST_UP}

    ground_truth_hosts = _ground_truth_host_addresses()
    assert len(ground_truth_hosts) == 10, "lab/ground_truth.yaml is expected to define 10 hosts"

    uncovered = {
        name: addrs
        for name, addrs in ground_truth_hosts.items()
        if host_up_subjects.isdisjoint(addrs)
    }
    assert not uncovered, (
        "hosts with no HOST_UP observation in any tests/fixtures/observations/ file: "
        f"{sorted(uncovered)}"
    )


def test_at_least_one_vuln_candidate_observation_exists(
    all_observations: list[Observation],
) -> None:
    vuln_candidates = [o for o in all_observations if o.kind is ObservationKind.VULN_CANDIDATE]
    assert vuln_candidates, (
        "expected at least one vuln_candidate observation somewhere in tests/fixtures/observations/"
    )


def test_vuln_candidate_cves_trace_back_to_ground_truth(
    all_observations: list[Observation],
) -> None:
    """CLAUDE.md: never invent a CVE. Every cve_ids attribute on a vuln_candidate
    observation in this fixture set must be one lab/ground_truth.yaml actually lists.
    """
    known_cve_ids = {
        cve["id"] for host in _load_ground_truth()["hosts"] for cve in host.get("expected_cves", [])
    }

    vuln_candidates = [o for o in all_observations if o.kind is ObservationKind.VULN_CANDIDATE]
    for obs in vuln_candidates:
        cve_ids = obs.attributes.get("cve_ids", "")
        for cve_id in (c.strip() for c in cve_ids.split(",") if c.strip()):
            assert cve_id in known_cve_ids, (
                f"observation {obs.observation_id} references {cve_id!r}, not present in "
                "lab/ground_truth.yaml's expected_cves"
            )
