"""Tests for evals/attack_paths.py and evals/golden/attack_paths_expected.yaml.

Results pinned here are harness outputs over the observation fixtures (8 of 10 lab
hosts synthetic). They check the harness, not the lab.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from evals.attack_paths import (
    FOUND,
    NOT_FOUND,
    ExpectedPath,
    HostIndex,
    entry_feasible,
    generate_markdown_report,
    ground_truth_contradictions,
    hop_feasible,
    lenient_match,
    load_expected,
    load_topology,
    main,
    path_feasibility,
    run_evaluation,
    strict_match,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GROUND_TRUTH = REPO_ROOT / "lab" / "ground_truth.yaml"
TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"
EXPECTED = REPO_ROOT / "evals" / "golden" / "attack_paths_expected.yaml"
RESULTS_JSON = REPO_ROOT / "evals" / "results" / "attack_paths_results.json"
RESULTS_MD = REPO_ROOT / "evals" / "results" / "attack_paths_results.md"


def _yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def ground_truth() -> dict[str, Any]:
    data = _yaml(GROUND_TRUTH)
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def index(ground_truth: dict[str, Any]) -> HostIndex:
    return HostIndex(ground_truth, load_topology(TOPOLOGY))


@pytest.fixture(scope="module")
def results() -> dict[str, Any]:
    return run_evaluation()


class TestExpectedFile:
    """The hop lists restate ground_truth.yaml; they must not add or drop anything."""

    def test_path_ids_match_ground_truth(self, ground_truth: dict[str, Any]) -> None:
        gt_ids = [p["id"] for p in ground_truth["expected_attack_paths"]]
        assert [e.path_id for e in load_expected(EXPECTED)] == gt_ids

    def test_hosts_exist_and_are_named_in_the_steps(self, ground_truth: dict[str, Any]) -> None:
        names = {h["name"] for h in ground_truth["hosts"]}
        steps = {
            p["id"]: " ".join(p["steps"]).lower() for p in ground_truth["expected_attack_paths"]
        }
        for expected in load_expected(EXPECTED):
            assert len(expected.hosts) >= 2, expected.path_id
            for host in expected.hosts:
                assert host in names, f"{expected.path_id}: unknown host {host}"
                assert host in steps[expected.path_id], f"{host} not in {expected.path_id} steps"

    def test_cves_are_named_in_the_steps_for_listed_hosts(
        self, ground_truth: dict[str, Any]
    ) -> None:
        steps = {p["id"]: " ".join(p["steps"]) for p in ground_truth["expected_attack_paths"]}
        for expected in load_expected(EXPECTED):
            assert set(expected.cves) <= set(expected.hosts), expected.path_id
            for cves in expected.cves.values():
                for cve in cves:
                    assert cve in steps[expected.path_id], f"{cve} not in {expected.path_id}"


class TestMatching:
    def test_strict_requires_exact_sequence(self) -> None:
        assert strict_match(("a", "b"), ("a", "b"))
        assert not strict_match(("a", "b"), ("a", "x", "b"))
        assert not strict_match(("a", "b"), ("a",))
        assert not strict_match(("a", "b"), ("b", "a"))

    def test_lenient_allows_extra_hosts_but_keeps_order(self) -> None:
        assert lenient_match(("a", "b"), ("a", "b"))
        assert lenient_match(("a", "b"), ("x", "a", "y", "b", "z"))
        assert not lenient_match(("a", "b"), ("b", "a"))
        assert not lenient_match(("a", "b", "c"), ("a", "c"))
        # A host consumed by an earlier match cannot satisfy a later one.
        assert not lenient_match(("a", "a"), ("a",))


class TestHostIndex:
    def test_machine_ids_map_back_to_hosts(self, index: HostIndex) -> None:
        assert index.host_of_machine("host:172.20.2.25") == "jenkins-ci"
        assert index.host_of_machine("host:172.20.3.50") == "bastion-ssh"  # secondary_ip
        assert index.host_of_machine("dmz-proxy") == "dmz-proxy"  # multi-homed name
        assert index.host_of_machine("host:10.0.0.1") == "unmapped:host:10.0.0.1"
        assert index.host_of_machine(None) is None

    def test_multi_homed_host_has_both_zones(self, index: HostIndex) -> None:
        assert index.zones("bastion-ssh") == ("internal", "data")
        assert index.zones("dvwa") == ("dmz",)


class TestFeasibility:
    def test_hops(self, index: HostIndex) -> None:
        assert hop_feasible(index, "spring-gateway", "jenkins-ci")[0]
        assert hop_feasible(index, "bastion-ssh", "cache-redis")[0]
        ok, why = hop_feasible(index, "dvwa", "internal-api")
        assert not ok
        assert "share no zone" in why

    def test_entry(self, index: HostIndex) -> None:
        assert entry_feasible(index, "dvwa")[0]
        assert not entry_feasible(index, "jenkins-ci")[0]

    def test_path_feasibility_flags_each_bad_hop(self, index: HostIndex) -> None:
        report = path_feasibility(index, ExpectedPath("t", ("jenkins-ci", "dvwa", "juiceshop"), {}))
        assert not report["feasible"]
        assert [h["feasible"] for h in report["hops"]] == [False, False, True]

    def test_contradictions_only_list_unsupported_claims(self, index: HostIndex) -> None:
        gt = {
            "hosts": [
                {"name": "dvwa", "reachable_from_outside": True},
                {"name": "jenkins-ci", "reachable_from": ["spring-gateway", "dvwa"]},
                {"name": "db-primary", "reachable_from_outside": True},
            ]
        }
        claims = [(c["host"], c["claim"]) for c in ground_truth_contradictions(gt, index)]
        assert claims == [
            ("jenkins-ci", "reachable_from dvwa"),
            ("db-primary", "reachable_from_outside: true"),
        ]


class TestEvaluation:
    def test_output_shape(self, results: dict[str, Any]) -> None:
        assert set(results) == {
            "metadata",
            "engine",
            "expected_paths",
            "summary",
            "ground_truth_contradictions",
            "spurious",
        }
        assert "NOT A LAB RUN" in results["metadata"]["banner"]
        engine = results["engine"]
        assert sum(engine["paths_by_confidence"].values()) == engine["total_paths"]
        assert sum(engine["paths_by_goal_kind"].values()) == engine["total_paths"]
        sp = results["spurious"]
        assert sp["on_route_paths"] + sp["off_route_paths"] == engine["total_paths"]
        for path in results["expected_paths"]:
            for mode in ("strict", "lenient"):
                assert path[mode]["verdict"] in (FOUND, NOT_FOUND)
                assert (path[mode]["verdict"] == FOUND) == (path[mode]["matching_paths"] > 0)
            # Strict matches are a subset of lenient ones.
            assert path["strict"]["matching_paths"] <= path["lenient"]["matching_paths"]
            # A miss is always explained; a hit always has an example path.
            if path["lenient"]["verdict"] == NOT_FOUND:
                assert path["diagnosis"]
                assert path["example_path"] is None
            else:
                assert path["example_path"] is not None

    def test_infeasible_ground_truth_is_diagnosed_as_such(self, results: dict[str, Any]) -> None:
        for path in results["expected_paths"]:
            bad = [h for h in path["feasibility"]["hops"] if not h["feasible"]]
            for hop in bad:
                assert any(
                    f"hop {hop['from']} -> {hop['to']} unreachable" in d for d in path["diagnosis"]
                )
            assert (path["id"] in results["summary"]["ground_truth_infeasible"]) == bool(bad)

    def test_deterministic(self, results: dict[str, Any]) -> None:
        assert json.dumps(run_evaluation(), sort_keys=True) == json.dumps(results, sort_keys=True)

    def test_committed_results_are_current(self, results: dict[str, Any]) -> None:
        committed = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        assert committed == json.loads(json.dumps(results)), (
            "evals/results/attack_paths_results.json is stale; rerun python evals/attack_paths.py"
        )
        assert RESULTS_MD.read_text(encoding="utf-8") == generate_markdown_report(results)


class TestCli:
    def test_writes_outputs(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
        assert main(["--output-json", str(out_json), "--output-md", str(out_md)]) == 0
        data = json.loads(out_json.read_text(encoding="utf-8"))
        assert [p["id"] for p in data["expected_paths"]] == ["path-1", "path-2", "path-3"]
        assert out_md.read_text(encoding="utf-8").startswith("# Attack Path Validity")
        printed = capsys.readouterr().out
        for path in data["expected_paths"]:
            assert path["summary"] in printed

    def test_missing_input_fails(self, tmp_path: Path) -> None:
        code = main(
            [
                "--expected",
                str(tmp_path / "nope.yaml"),
                "--output-json",
                str(tmp_path / "r.json"),
                "--output-md",
                str(tmp_path / "r.md"),
                "--quiet",
            ]
        )
        assert code == 1
        assert not (tmp_path / "r.json").exists()
