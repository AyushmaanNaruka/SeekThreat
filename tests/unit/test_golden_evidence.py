"""Unit tests for Task A-2: Per-CVE evidence records in enrichment_baseline.json.

Verifies:
1. Dataset version >= 3.0.0 and cohort_labels_verified is True.
2. No legacy cohort names ('nvd_gap', 'high_epss_no_nvd') remain.
3. Every entry has a complete, structured evidence block:
   - retrieved_at ISO timestamp
   - nvd: checked, cvss_present, source_url
   - cisa_kev: in_catalog, source_url
   - epss: score, source_url
   - euvd: present, source_url
4. KEV strata consistency:
   - Items in kev_* strata have evidence.cisa_kev.in_catalog == True and non-empty date_added.
   - Items in non_kev_* strata have evidence.cisa_kev.in_catalog == False.
5. CISA KEV catalog mirror directly confirms CVE-2022-22965 is in KEV (resolving D-038 discrepancy).
6. Evidence builder produces in_catalog == True for CVE-2022-22965.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE_PATH = REPO_ROOT / "evals" / "golden" / "enrichment_baseline.json"
LIST_PATH = REPO_ROOT / "evals" / "golden" / "eval_cve_list.txt"
KEV_MIRROR_PATH = REPO_ROOT / "data" / "enrichment_cache" / "cisa_kev.json"


@pytest.fixture(scope="module")
def baseline_data() -> dict:
    assert BASELINE_PATH.exists(), f"Missing {BASELINE_PATH}"
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


class TestBaselineMetadata:
    """Test top-level dataset metadata in enrichment_baseline.json."""

    def test_dataset_version_is_v3_or_higher(self, baseline_data: dict) -> None:
        version = baseline_data.get("dataset_version", "0.0.0")
        major = int(version.split(".")[0])
        assert major >= 3, f"Expected dataset_version >= 3.0.0, got {version}"

    def test_cohort_labels_verified_is_true(self, baseline_data: dict) -> None:
        assert baseline_data.get("cohort_labels_verified") is True

    def test_legacy_cohorts_removed(self, baseline_data: dict) -> None:
        cohorts = baseline_data.get("cohorts", [])
        legacy = {"cohort_b_nvd_gap", "nvd_gap", "cohort_d_high_epss_no_nvd", "high_epss_no_nvd"}
        for c in cohorts:
            assert c not in legacy, f"Legacy cohort {c} should not be present in cohorts list"

    def test_mirrors_used_metadata(self, baseline_data: dict) -> None:
        mirrors = baseline_data.get("mirrors_used", {})
        assert "cisa_kev" in mirrors
        assert "epss_v4" in mirrors
        for name, info in mirrors.items():
            if info.get("present"):
                assert "sha256" in info, f"Mirror {name} missing sha256"
                assert len(info["sha256"]) == 64


class TestPerCveEvidenceRecords:
    """Test evidence blocks for each item in enrichment_baseline.json."""

    def test_item_count_matches_eval_cve_list(self, baseline_data: dict) -> None:
        assert LIST_PATH.exists()
        expected_cves = [l.strip() for l in LIST_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
        items = baseline_data.get("items", [])
        actual_cves = [item["cve_id"] for item in items]
        assert actual_cves == expected_cves

    def test_every_item_has_complete_evidence(self, baseline_data: dict) -> None:
        items = baseline_data.get("items", [])
        assert len(items) >= 50

        for item in items:
            cve_id = item.get("cve_id")
            assert cve_id, "Item missing cve_id"
            evidence = item.get("evidence")
            assert isinstance(evidence, dict), f"{cve_id} missing evidence dict"

            # Check retrieved_at
            assert "retrieved_at" in evidence, f"{cve_id} missing retrieved_at"
            assert "T" in evidence["retrieved_at"], f"{cve_id} malformed retrieved_at timestamp"

            # Check NVD evidence
            nvd = evidence.get("nvd")
            assert isinstance(nvd, dict), f"{cve_id} missing nvd evidence"
            assert isinstance(nvd.get("checked"), bool)
            assert isinstance(nvd.get("cvss_present"), bool)
            assert nvd.get("source_url", "").startswith("https://nvd.nist.gov/vuln/detail/")

            # Check CISA KEV evidence
            kev = evidence.get("cisa_kev")
            assert isinstance(kev, dict), f"{cve_id} missing cisa_kev evidence"
            assert isinstance(kev.get("in_catalog"), bool)
            assert kev.get("source_url") == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

            # Check EPSS evidence
            epss = evidence.get("epss")
            assert isinstance(epss, dict), f"{cve_id} missing epss evidence"
            score = epss.get("score")
            assert score is None or (isinstance(score, (int, float)) and 0.0 <= score <= 1.0)
            assert f"cve={cve_id}" in epss.get("source_url", "")

            # Check EUVD evidence
            euvd = evidence.get("euvd")
            assert isinstance(euvd, dict), f"{cve_id} missing euvd evidence"
            assert isinstance(euvd.get("present"), bool)
            assert cve_id in euvd.get("source_url", "")

    def test_kev_strata_evidence_consistency(self, baseline_data: dict) -> None:
        items = baseline_data.get("items", [])
        for item in items:
            cohort = item.get("cohort", "")
            kev_evidence = item["evidence"]["cisa_kev"]
            if cohort.startswith("kev_"):
                assert kev_evidence["in_catalog"] is True, (
                    f"{item['cve_id']} in stratum {cohort} but in_catalog is not True"
                )
                assert kev_evidence.get("date_added") is not None, (
                    f"{item['cve_id']} in KEV stratum but date_added is missing"
                )
            elif cohort.startswith("non_kev_"):
                assert kev_evidence["in_catalog"] is False, (
                    f"{item['cve_id']} in stratum {cohort} but in_catalog is True"
                )


class TestCve202222965DiscrepancyResolution:
    """Verifies CVE-2022-22965 (Spring4Shell) is recognized in CISA KEV (Task A-2 / Review Fix)."""

    def test_kev_mirror_contains_cve_2022_22965(self) -> None:
        if not KEV_MIRROR_PATH.exists():
            pytest.skip("Local CISA KEV mirror not found")
        data = json.loads(KEV_MIRROR_PATH.read_text(encoding="utf-8"))
        vulnerabilities = data.get("vulnerabilities", [])
        match = next((v for v in vulnerabilities if v.get("cveID") == "CVE-2022-22965"), None)
        assert match is not None, "CVE-2022-22965 must be present in cisa_kev.json mirror"
        assert match.get("dateAdded") == "2022-04-04"

    def test_evidence_builder_identifies_cve_2022_22965_in_kev(self) -> None:
        from evals.scripts.build_enrichment_baseline import _evidence_for

        mirrors_dir = REPO_ROOT / "data" / "enrichment_cache"
        if not (mirrors_dir / "cisa_kev.json").exists():
            pytest.skip("Local CISA KEV mirror not found")

        kev_idx = {
            "CVE-2022-22965": {
                "cveID": "CVE-2022-22965",
                "dateAdded": "2022-04-04",
                "dueDate": "2022-04-25",
            }
        }
        evidence = _evidence_for(
            cve_id="CVE-2022-22965",
            mirrors_dir=mirrors_dir,
            kev_idx=kev_idx,
            epss_idx={"CVE-2022-22965": 0.97},
            nvd_idx={},
            euvd_idx={},
            retrieved_at="2026-10-15T22:00:00Z",
        )
        assert evidence["cisa_kev"]["in_catalog"] is True
        assert evidence["cisa_kev"]["date_added"] == "2022-04-04"
        assert evidence["epss"]["score"] == 0.97
