"""Unit tests for evals/enrichment_coverage.py harness."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from evals.enrichment_coverage import (
    _find_fixture_or_mirror,
    _is_filled,
    build_engines,
    generate_markdown_report,
    run_evaluation,
)
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"
DATASET_PATH = Path(__file__).parent.parent.parent / "evals" / "golden" / "enrichment_baseline.json"


class TestEnrichmentCoverageHarness:
    """Tests for enrichment coverage evaluation logic and harness functions."""

    def test_find_fixture_or_mirror(self) -> None:
        cve_path = _find_fixture_or_mirror(FIXTURES_DIR, "cve_org")
        assert cve_path is not None
        assert cve_path.exists()
        assert "cve_org" in cve_path.name

    def test_is_filled_detects_placeholders(self) -> None:
        now = datetime.now(UTC)
        # Placeholder CVSS
        p_cvss = {
            "cvss_score": Attributed(
                value=5.0,
                provenance=Provenance(
                    source=Source.DERIVED, confidence=Confidence.LOW, retrieved_at=now
                ),
            )
        }
        assert _is_filled("cvss_score", p_cvss) is False

        # Real CVSS
        r_cvss = {
            "cvss_score": Attributed(
                value=9.8,
                provenance=Provenance(
                    source=Source.CVE_ORG, confidence=Confidence.HIGH, retrieved_at=now
                ),
            )
        }
        assert _is_filled("cvss_score", r_cvss) is True

        # Placeholder CWE
        p_cwe = {
            "cwe_ids": Attributed(
                value=["CWE-Other"],
                provenance=Provenance(
                    source=Source.DERIVED, confidence=Confidence.LOW, retrieved_at=now
                ),
            )
        }
        assert _is_filled("cwe_ids", p_cwe) is False

        # Placeholder KEV (unknown / None)
        p_kev = {
            "in_kev": Attributed(
                value=None,
                provenance=Provenance(
                    source=Source.DERIVED, confidence=Confidence.LOW, retrieved_at=now
                ),
            )
        }
        assert _is_filled("in_kev", p_kev) is False

        # Authoritative KEV negative
        r_kev_neg = {
            "in_kev": Attributed(
                value=False,
                provenance=Provenance(
                    source=Source.KEV, confidence=Confidence.HIGH, retrieved_at=now
                ),
            )
        }
        assert _is_filled("in_kev", r_kev_neg) is True

    def test_is_filled_exploit_availability(self) -> None:
        now = datetime.now(UTC)
        # None / Derived
        p_edb = {
            "has_public_exploit": Attributed(
                value=None,
                provenance=Provenance(
                    source=Source.DERIVED, confidence=Confidence.LOW, retrieved_at=now
                ),
            )
        }
        assert _is_filled("exploit_availability", p_edb) is False

        # Definite ExploitDB signal
        r_edb = {
            "has_public_exploit": Attributed(
                value=True,
                provenance=Provenance(
                    source=Source.EXPLOITDB, confidence=Confidence.HIGH, retrieved_at=now
                ),
            )
        }
        assert _is_filled("exploit_availability", r_edb) is True

    def test_build_engines(self) -> None:
        baseline, multi = build_engines(FIXTURES_DIR)
        assert baseline.nvd is not None
        assert baseline.nvd.is_loaded is True
        assert baseline.cve_org.is_loaded is False
        assert multi.cve_org.is_loaded is True
        assert multi.cisa_kev.is_loaded is True
        assert multi.first_epss.is_loaded is True

    def test_run_evaluation_offline(self) -> None:
        results = run_evaluation(DATASET_PATH, FIXTURES_DIR)
        assert results["metadata"]["total_cves"] == 50
        summary = results["summary"]
        assert summary["multi_overall_coverage_pct"] > summary["baseline_overall_coverage_pct"]
        assert summary["coverage_improvement_pp"] > 0
        assert "cohort_a_nvd_control" in results["cohorts"]

    def test_generate_markdown_report(self) -> None:
        results = run_evaluation(DATASET_PATH, FIXTURES_DIR)
        report = generate_markdown_report(results)
        assert "# Enrichment Coverage Evaluation Results" in report
        assert "Synthetic fixture files" in report or "synthetic fixture files" in report.lower()
        assert "Overall Coverage" in report
        assert "Cohort Analysis" in report
