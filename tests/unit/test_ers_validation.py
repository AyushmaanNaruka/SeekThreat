"""Unit tests for ERS empirical validation harness (evals/ers_validation.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from evals.ers_validation import (
    PROFILES,
    _has_exploit,
    _has_exploitdb,
    _has_metasploit,
    evaluate_ranking,
    generate_markdown_report,
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

    def test_empty_slice_handled(self) -> None:
        res = evaluate_ranking([], "score", top_k=0)
        assert res["precision_pct"] == 0.0
        assert res["recall_pct"] == 0.0


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
        assert "# ERS Empirical Validation & Exploit Corroboration Report" in report
        assert "D-038" in report
        assert "Methodological Defense & Circularity Disclosure" in report
        assert "Top-Ranked Vulnerabilities Corroboration Table" in report
