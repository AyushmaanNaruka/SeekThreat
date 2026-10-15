"""Unit tests for the evals/enrichment_coverage.py harness.

Counts pinned here are harness outputs on the synthetic fixtures in
tests/fixtures/enrichment/. They check the harness, not the platform.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from evals.enrichment_coverage import (
    HEADLINE_FIELDS,
    LIKE_FOR_LIKE_FIELDS,
    SIGNAL_FIELDS,
    SYNTHETIC_BANNER,
    _find_fixture_or_mirror,
    _is_filled,
    _signal_state,
    build_engines,
    cohort_labels_verified,
    describe_mirrors,
    generate_markdown_report,
    run_evaluation,
)
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "enrichment"
DATASET_PATH = REPO_ROOT / "evals" / "golden" / "enrichment_baseline.json"
RESULTS_JSON = REPO_ROOT / "evals" / "results" / "enrichment_coverage_results.json"
RESULTS_MD = REPO_ROOT / "evals" / "results" / "enrichment_coverage_results.md"

# Fields excluded when comparing a fresh run to the committed results (wall clock).
_VOLATILE_METADATA = ("generated_at",)

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _attr(value: Any, source: Source, confidence: Confidence = Confidence.HIGH) -> Attributed[Any]:
    return Attributed(
        value=value,
        provenance=Provenance(source=source, confidence=confidence, retrieved_at=_NOW),
    )


@pytest.fixture(scope="module")
def results() -> dict[str, Any]:
    return run_evaluation(DATASET_PATH, FIXTURES_DIR)


class TestIsFilled:
    def test_derived_and_low_confidence_placeholders_excluded(self) -> None:
        assert _is_filled("cvss_score", {"cvss_score": _attr(5.0, Source.DERIVED)}) is False
        assert (
            _is_filled("cvss_score", {"cvss_score": _attr(9.8, Source.CVE_ORG, Confidence.LOW)})
            is False
        )
        assert _is_filled("cwe_ids", {"cwe_ids": _attr(["CWE-Other"], Source.DERIVED)}) is False
        assert _is_filled("epss_score", {"epss_score": _attr(0.001, Source.DERIVED)}) is False

    def test_real_values_equal_to_placeholder_values_count(self) -> None:
        # A real CVSS 5.0 or EPSS 0.001 is data, not a placeholder.
        assert _is_filled("cvss_score", {"cvss_score": _attr(5.0, Source.NVD)}) is True
        assert _is_filled("epss_score", {"epss_score": _attr(0.001, Source.EPSS)}) is True

    def test_missing_and_empty_values_excluded(self) -> None:
        assert _is_filled("summary", {}) is False
        assert _is_filled("summary", {"summary": _attr("   ", Source.CVE_ORG)}) is False
        assert _is_filled("cwe_ids", {"cwe_ids": _attr([], Source.CVE_ORG)}) is False

    def test_signal_fields_rejected_by_headline_check(self) -> None:
        for field in SIGNAL_FIELDS:
            with pytest.raises(ValueError):
                _is_filled(field, {})


class TestSignalState:
    def test_kev_states(self) -> None:
        assert _signal_state("in_kev", {"in_kev": _attr(True, Source.KEV)}) == "positive"
        assert _signal_state("in_kev", {"in_kev": _attr(False, Source.KEV)}) == "negative"
        unknown = {"in_kev": _attr(None, Source.DERIVED, Confidence.LOW)}
        assert _signal_state("in_kev", unknown) == "unknown"
        assert _signal_state("in_kev", {}) == "unknown"

    def test_exploit_states(self) -> None:
        pos = {
            "has_public_exploit": _attr(False, Source.EXPLOITDB),
            "has_metasploit_module": _attr(True, Source.METASPLOIT),
        }
        assert _signal_state("exploit_availability", pos) == "positive"
        neg = {"has_public_exploit": _attr(False, Source.EXPLOITDB)}
        assert _signal_state("exploit_availability", neg) == "negative"
        unk = {"has_public_exploit": _attr(None, Source.DERIVED, Confidence.LOW)}
        assert _signal_state("exploit_availability", unk) == "unknown"


class TestEngines:
    def test_find_fixture_or_mirror(self) -> None:
        path = _find_fixture_or_mirror(FIXTURES_DIR, "cve_org")
        assert path is not None and path.name == "cve_org_sample.json"

    def test_baseline_engine_loads_only_nvd(self) -> None:
        baseline, multi = build_engines(FIXTURES_DIR)
        assert baseline.nvd is not None and baseline.nvd.is_loaded
        assert baseline.cve_org.is_loaded is False
        assert baseline.cisa_kev.is_loaded is False
        assert baseline.first_epss.is_loaded is False
        assert baseline.vulnrichment is None
        assert baseline.euvd is None
        assert baseline.exploitdb is None
        assert baseline.metasploit is None
        assert multi.cve_org.is_loaded and multi.cisa_kev.is_loaded and multi.first_epss.is_loaded

    def test_fixture_mirrors_detected_synthetic_by_content(self, tmp_path: Path) -> None:
        synthetic, mirrors = describe_mirrors(
            {"cve_org": FIXTURES_DIR / "cve_org_sample.json", "nvd": None}
        )
        assert synthetic is True
        assert all("sha256" not in m for m in mirrors)

        # Directory name says "fixture"; content has no _synthetic key -> real mode.
        real_dir = tmp_path / "fixture_sample_dir"
        real_dir.mkdir()
        mirror = real_dir / "cve_org.json"
        mirror.write_text(json.dumps({"CVE-2000-0001": {}}), encoding="utf-8")
        (real_dir / "cve_org.meta.json").write_text(
            json.dumps({"synced_at": "2026-10-01T00:00:00+00:00"}), encoding="utf-8"
        )
        synthetic, mirrors = describe_mirrors({"cve_org": mirror})
        assert synthetic is False
        entry = next(m for m in mirrors if m["name"] == "cve_org")
        assert len(entry["sha256"]) == 64
        assert entry["mtime"]
        assert entry["synced_at"] == "2026-10-01T00:00:00+00:00"


class TestRunEvaluation:
    def test_metadata(self, results: dict[str, Any]) -> None:
        meta = results["metadata"]
        assert meta["sample_mode"] == "synthetic_fixtures"
        assert meta["banner"] == SYNTHETIC_BANNER
        assert meta["total_cves"] == 50
        assert meta["total_headline_instances"] == 50 * len(HEADLINE_FIELDS)
        assert "generated_at" not in meta
        assert "\\" not in meta["dataset_path"] and "\\" not in meta["cache_dir"]

    def test_signals_not_in_headline(self, results: dict[str, Any]) -> None:
        assert tuple(results["per_field"]) == HEADLINE_FIELDS
        for field in SIGNAL_FIELDS:
            assert field not in results["per_field"]
            assert field not in results["metadata"]["headline_fields"]
        headline_total = sum(f["multi_count"] for f in results["per_field"].values())
        assert results["summary"]["multi_filled"] == headline_total

    def test_pinned_per_field_counts(self, results: dict[str, Any]) -> None:
        counts = {
            f: (d["baseline_count"], d["multi_count"]) for f, d in results["per_field"].items()
        }
        assert counts == {
            "cvss_score": (0, 0),
            "cwe_ids": (0, 0),
            "summary": (0, 0),
            "epss_score": (0, 0),
        }
        assert results["summary"]["baseline_filled"] == 0
        assert results["summary"]["multi_filled"] == 0

    def test_headline_excluding_epss(self, results: dict[str, Any]) -> None:
        excl = results["summary_excluding_epss"]
        assert tuple(excl["fields"]) == LIKE_FOR_LIKE_FIELDS
        assert "epss_score" not in excl["fields"]
        assert excl["total_instances"] == 50 * len(LIKE_FOR_LIKE_FIELDS)
        per_field = results["per_field"]
        assert excl["baseline_filled"] == sum(
            per_field[f]["baseline_count"] for f in LIKE_FOR_LIKE_FIELDS
        )
        assert excl["multi_filled"] == sum(
            per_field[f]["multi_count"] for f in LIKE_FOR_LIKE_FIELDS
        )
        # Pinned on the synthetic fixtures (harness check, not a platform measurement).
        assert (excl["baseline_filled"], excl["multi_filled"]) == (0, 0)
        assert excl["baseline_coverage_pct"] == 0.0
        assert excl["multi_coverage_pct"] == 0.0
        assert excl["coverage_improvement_pp"] == 0.0
        assert "| Excluding `epss_score` | 0.0% (0/150) | 0.0% (0/150) | +0.0 pp |" in (
            generate_markdown_report(results)
        )

    def test_cohort_label_limitation_follows_dataset_flag(self, results: dict[str, Any]) -> None:
        assert cohort_labels_verified({"cohort_labels_verified": True}) is True
        assert cohort_labels_verified({"cohort_labels_verified": "yes"}) is False
        assert cohort_labels_verified({}) is False
        assert results["metadata"]["cohort_labels_verified"] is True
        assert "Cohort labels are recorded as verified" in (
            generate_markdown_report(results)
        )
        tampered = json.loads(json.dumps(results))
        tampered["metadata"]["cohort_labels_verified"] = False
        report = generate_markdown_report(tampered)
        assert "Cohort labels come from the dataset and are not verified" in report
        assert "recorded as verified" not in report

    def test_pinned_signal_counts(self, results: dict[str, Any]) -> None:
        sig = results["signals"]
        # in_kev baseline is loaded because NVD is loaded in baseline (Task A-3)
        assert sig["in_kev"]["baseline"]["mirror_loaded"] is True
        assert sig["in_kev"]["multi_source"]["mirror_loaded"] is True
        # exploit_availability baseline is not loaded
        assert sig["exploit_availability"]["baseline"]["mirror_loaded"] is False
        assert sig["exploit_availability"]["baseline"]["positive_rate_pct"] is None
        assert sig["exploit_availability"]["baseline"]["unknown_count"] == 50
        assert sig["exploit_availability"]["multi_source"]["mirror_loaded"] is True
        assert sig["in_kev"]["multi_source"]["positive_count"] == 0
        assert sig["exploit_availability"]["multi_source"]["positive_count"] == 0

    def test_markdown_report(self, results: dict[str, Any]) -> None:
        report = generate_markdown_report(results)
        assert SYNTHETIC_BANNER in report
        assert "Key Findings" not in report
        assert "+-" not in report

    def test_negative_gain_formatting(self, results: dict[str, Any]) -> None:
        tampered = json.loads(json.dumps(results))
        tampered["summary"]["coverage_improvement_pp"] = -2.5
        report = generate_markdown_report(tampered)
        assert "-2.5 pp" in report
        assert "+-2.5" not in report


class TestCommittedResults:
    def test_committed_json_matches_fresh_run(self, results: dict[str, Any]) -> None:
        committed = json.loads(RESULTS_JSON.read_text(encoding="utf-8"))
        fresh = json.loads(json.dumps(results))
        for data in (committed, fresh):
            for key in _VOLATILE_METADATA:
                data["metadata"].pop(key, None)
        assert committed == fresh, "Re-run `python evals/enrichment_coverage.py`"

    def test_committed_markdown_matches_fresh_run(self, results: dict[str, Any]) -> None:
        committed = RESULTS_MD.read_text(encoding="utf-8").replace("\r\n", "\n")
        assert committed == generate_markdown_report(results)
