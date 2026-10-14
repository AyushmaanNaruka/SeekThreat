"""Unit tests for the ERS ranking corroboration harness (evals/ers_validation.py)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from evals.ers_validation import (
    _REAL_RESULTS_JSON,
    _REAL_RESULTS_MD,
    _SYNTHETIC_OUTPUT_JSON,
    _SYNTHETIC_OUTPUT_MD,
    PROFILES,
    SYNTHETIC_BANNER,
    TIE_RULE,
    _has_exploit,
    _has_exploitdb,
    _has_metasploit,
    evaluate_ranking,
    generate_markdown_report,
    main,
    rank_items,
    resolve_output_paths,
    run_ers_validation,
)
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "enrichment"
DATASET_PATH = REPO_ROOT / "evals" / "golden" / "enrichment_baseline.json"
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _attr(val: Any, src: Source) -> Attributed[Any]:
    return Attributed(
        value=val,
        provenance=Provenance(source=src, confidence=Confidence.HIGH, retrieved_at=NOW),
    )


class TestExploitDetectionHelpers:
    def test_exploitdb_detection(self) -> None:
        fields = {"has_public_exploit": _attr(True, Source.EXPLOITDB)}
        assert _has_exploitdb(fields) is True
        assert _has_metasploit(fields) is False
        assert _has_exploit(fields) is True

    def test_metasploit_detection(self) -> None:
        fields = {"has_metasploit_module": _attr(True, Source.METASPLOIT)}
        assert _has_exploitdb(fields) is False
        assert _has_metasploit(fields) is True
        assert _has_exploit(fields) is True

    def test_neither_exploit_detected(self) -> None:
        fields = {
            "has_public_exploit": _attr(False, Source.EXPLOITDB),
            "has_metasploit_module": _attr(False, Source.METASPLOIT),
        }
        assert _has_exploitdb(fields) is False
        assert _has_metasploit(fields) is False
        assert _has_exploit(fields) is False

    def test_derived_placeholder_ignored(self) -> None:
        fields = {"has_public_exploit": _attr(True, Source.DERIVED)}
        assert _has_exploitdb(fields) is False
        assert _has_exploit(fields) is False


class TestEvaluateRanking:
    def test_ranking_precision_and_recall(self) -> None:
        sample_items = [
            {"cve_id": "CVE-1", "score": 9.5, "has_exploit": True},
            {"cve_id": "CVE-2", "score": 9.0, "has_exploit": True},
            {"cve_id": "CVE-3", "score": 8.0, "has_exploit": False},
            {"cve_id": "CVE-4", "score": 7.0, "has_exploit": True},
        ]
        # Total exploited in dataset = 3
        # Top 2 items: CVE-1 (exp) and CVE-2 (exp) -> precision = 100%, recall = 2/3 = 66.7%
        res = evaluate_ranking(sample_items, "score", top_k=2)
        assert res["top_k"] == 2
        assert res["top_k_exploited_count"] == 2
        assert res["precision_pct"] == 100.0
        assert res["recall_pct"] == 66.7
        assert res["top_cves"] == ["CVE-1", "CVE-2"]

    def test_metasploit_precision(self) -> None:
        items = [
            {"cve_id": "CVE-1", "score": 9.0, "has_exploit": True, "has_metasploit": True},
            {"cve_id": "CVE-2", "score": 8.0, "has_exploit": True, "has_metasploit": False},
            {"cve_id": "CVE-3", "score": 7.0, "has_exploit": False, "has_metasploit": False},
        ]
        res = evaluate_ranking(items, "score", top_k=2)
        assert res["precision_pct"] == 100.0
        assert res["metasploit_precision_pct"] == 50.0

    def test_empty_slice_handled(self) -> None:
        res = evaluate_ranking([], "score", top_k=0)
        assert res["precision_pct"] == 0.0
        assert res["recall_pct"] == 0.0


class TestTieDeterminism:
    ITEMS = [
        {"cve_id": "CVE-2024-0003", "score": 9.0, "has_exploit": False},
        {"cve_id": "CVE-2024-0001", "score": 9.0, "has_exploit": True},
        {"cve_id": "CVE-2024-0004", "score": 9.5, "has_exploit": True},
        {"cve_id": "CVE-2024-0002", "score": 9.0, "has_exploit": True},
        {"cve_id": "CVE-2024-0005", "score": 1.0, "has_exploit": False},
    ]

    def test_ties_broken_by_cve_id_regardless_of_input_order(self) -> None:
        expected = ["CVE-2024-0004", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        for items in (self.ITEMS, list(reversed(self.ITEMS)), sorted(self.ITEMS, key=str)):
            ranked = [x["cve_id"] for x in rank_items(items, "score")]
            assert ranked[:4] == expected
            res = evaluate_ranking(items, "score", top_k=2)
            assert res["top_cves"] == expected[:2]
        assert TIE_RULE == "score descending, then cve_id ascending"

    def test_boundary_ties_and_precision_range_reported(self) -> None:
        # Top 2: 0004 (9.5) is fixed; one slot is left for three CVEs tied at 9.0,
        # two of which have a catalogue entry.
        res = evaluate_ranking(self.ITEMS, "score", top_k=2)
        assert res["ties_at_boundary"] == 3
        assert res["tied_outside_top_k"] == 2
        assert res["precision_pct"] == 100.0
        assert res["precision_range_over_tie_orders_pct"] == [50.0, 100.0]

    def test_no_ties_gives_point_range(self) -> None:
        res = evaluate_ranking(self.ITEMS, "score", top_k=1)
        assert res["ties_at_boundary"] == 1
        assert res["tied_outside_top_k"] == 0
        assert res["precision_range_over_tie_orders_pct"] == [100.0, 100.0]


class TestOutputSafety:
    def test_synthetic_defaults_to_synthetic_paths(self) -> None:
        out_json, out_md = resolve_output_paths(True, None, None)
        assert out_json == REPO_ROOT / _SYNTHETIC_OUTPUT_JSON
        assert out_md == REPO_ROOT / _SYNTHETIC_OUTPUT_MD

    def test_synthetic_never_writes_real_results_path(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            resolve_output_paths(True, _REAL_RESULTS_JSON, tmp_path / "x.md")
        with pytest.raises(ValueError):
            resolve_output_paths(True, tmp_path / "x.json", REPO_ROOT / _REAL_RESULTS_MD)

    def test_real_mirrors_require_explicit_outputs(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            resolve_output_paths(False, None, None)
        with pytest.raises(ValueError):
            resolve_output_paths(False, tmp_path / "x.json", None)
        assert resolve_output_paths(False, tmp_path / "x.json", tmp_path / "x.md") == (
            tmp_path / "x.json",
            tmp_path / "x.md",
        )

    def test_missing_cache_dir_is_an_error_not_a_fallback(self, tmp_path: Path) -> None:
        missing = tmp_path / "no_such_cache"
        with pytest.raises(FileNotFoundError):
            run_ers_validation(DATASET_PATH, missing)
        assert main(["--cache-dir", str(missing), "--quiet"]) == 1

    def test_real_mode_without_outputs_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Copy the fixtures with the _synthetic flag stripped so the run counts as real.
        real_dir = tmp_path / "mirrors"
        real_dir.mkdir()
        for src in FIXTURES_DIR.glob("*.json"):
            data = json.loads(src.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.pop("_synthetic", None)
            (real_dir / src.name).write_text(json.dumps(data), encoding="utf-8")
        before_json = (REPO_ROOT / _REAL_RESULTS_JSON).read_bytes()
        monkeypatch.chdir(tmp_path)
        args = ["--dataset", str(DATASET_PATH), "--cache-dir", str(real_dir), "--quiet"]
        assert main(args) == 2
        assert list(tmp_path.rglob("ers_validation*")) == []
        assert (REPO_ROOT / _REAL_RESULTS_JSON).read_bytes() == before_json


class TestProfilesConfiguration:
    def test_profile_weights_sum_to_one(self) -> None:
        for pname, w in PROFILES.items():
            total = w.weight_cvss + w.weight_epss + w.weight_kev
            assert pytest.approx(total, abs=1e-5) == 1.0, f"Profile {pname} does not sum to 1.0"


class TestRunErsValidation:
    def test_run_ers_validation_on_fixtures(self) -> None:
        results = run_ers_validation(DATASET_PATH, FIXTURES_DIR)
        assert "metadata" in results
        assert "profiles" in results
        assert "comparison" in results
        assert results["metadata"]["total_cves"] == 50
        assert "balanced" in results["profiles"]
        assert "no_epss_control" in results["profiles"]
        assert "cvss_only" in results["profiles"]

    def test_markdown_report_generation(self) -> None:
        results = run_ers_validation(DATASET_PATH, FIXTURES_DIR)
        report = generate_markdown_report(results)
        assert "# ERS Ranking Corroboration Report (smoke-level)" in report
        assert SYNTHETIC_BANNER in report
        assert "D-038" in report
        assert "Limitations & circularity disclosure" in report
        assert "Top-ranked CVEs (balanced ERS)" in report
        assert "Independent Metasploit" not in report
        assert "Hard Rule 1" not in report
        assert "weaponized" not in report.lower().replace("cohort_e_weaponized_exploit", "")

    def test_synthetic_run_reports_baselines(self) -> None:
        results = run_ers_validation(DATASET_PATH, FIXTURES_DIR)
        meta, comp = results["metadata"], results["comparison"]
        assert meta["synthetic_mode"] is True
        assert meta["banner"] == SYNTHETIC_BANNER
        assert "generated_at" not in meta
        assert comp["random_baseline_precision_pct"] == meta["overall_exploit_rate_pct"]
        assert comp["random_baseline_metasploit_precision_pct"] == meta["metasploit_rate_pct"]
        assert [x["cve_id"] for x in results["items"]] == [
            x["cve_id"] for x in rank_items(results["items"], "score_balanced")
        ]


class TestCommittedSyntheticResults:
    def test_committed_synthetic_results_match_fresh_run(self) -> None:
        results = run_ers_validation(DATASET_PATH, FIXTURES_DIR)
        committed = json.loads((REPO_ROOT / _SYNTHETIC_OUTPUT_JSON).read_text(encoding="utf-8"))
        assert committed == json.loads(json.dumps(results)), (
            "Re-run `python evals/ers_validation.py`"
        )
        committed_md = (REPO_ROOT / _SYNTHETIC_OUTPUT_MD).read_text(encoding="utf-8")
        assert committed_md.replace("\r\n", "\n") == generate_markdown_report(results)
