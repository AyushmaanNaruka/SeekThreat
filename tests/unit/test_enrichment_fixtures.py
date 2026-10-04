"""Tests for Track 2 (Enrichment) test fixtures and offline sample feeds."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.schema.models.finding import Finding
from tests.fixtures.findings.baseline_findings import (
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_HEURISTIC_NO_CVE,
    FINDING_LOG4SHELL,
    FINDING_SPRING_GATEWAY_RCE,
    get_baseline_findings,
    get_baseline_findings_by_id,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestBaselineFindingFixtures:
    """Validate hand-built Finding fixtures against schema invariants."""

    def test_all_baseline_findings_are_valid_findings(self) -> None:
        findings = get_baseline_findings()
        assert len(findings) == 6
        for f in findings:
            assert isinstance(f, Finding)
            assert f.finding_id.startswith("find-")
            assert f.engagement_id == "eng-lab-baseline-001"
            assert len(f.observation_ids) > 0
            assert f.detected_at.tzinfo is not None

    def test_finding_map_keys_match_ids(self) -> None:
        findings_map = get_baseline_findings_by_id()
        assert len(findings_map) == 6
        for fid, finding in findings_map.items():
            assert fid == finding.finding_id

    def test_single_cve_finding(self) -> None:
        assert FINDING_LOG4SHELL.cve_ids == ["CVE-2021-44228"]
        assert "Log4Shell" in FINDING_LOG4SHELL.title
        assert len(FINDING_LOG4SHELL.observation_ids) == 2

        assert FINDING_APACHE_PATH_TRAVERSAL.cve_ids == ["CVE-2021-41773"]
        assert "2.4.49" in FINDING_APACHE_PATH_TRAVERSAL.title

    def test_multi_cve_finding(self) -> None:
        assert len(FINDING_SPRING_GATEWAY_RCE.cve_ids) == 2
        assert "CVE-2022-22947" in FINDING_SPRING_GATEWAY_RCE.cve_ids
        assert "CVE-2022-22965" in FINDING_SPRING_GATEWAY_RCE.cve_ids

    def test_heuristic_non_cve_finding(self) -> None:
        assert FINDING_HEURISTIC_NO_CVE.cve_ids == []
        assert FINDING_HEURISTIC_NO_CVE.scanner == "nmap"
        assert len(FINDING_HEURISTIC_NO_CVE.observation_ids) == 1

    def test_finding_raises_on_empty_observations(self) -> None:
        with pytest.raises(ValueError, match="at least one observation"):
            Finding(
                finding_id="find-invalid-001",
                engagement_id="eng-001",
                asset_id="asset-001",
                scanner="nuclei",
                observation_ids=[],
                detected_at=FINDING_LOG4SHELL.detected_at,
            )


class TestEnrichmentSampleFeeds:
    """Validate sample offline intelligence feeds."""

    def test_cve_org_sample_feed_validity(self) -> None:
        path = FIXTURES_DIR / "cve_org_sample.json"
        assert path.exists(), f"Missing fixture file: {path}"

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, dict)
        assert "CVE-2021-44228" in data
        assert "CVE-2024-23897" in data

        # Check CVE record structure
        log4j = data["CVE-2021-44228"]
        assert log4j["dataType"] == "CVE_RECORD"
        assert log4j["dataVersion"] == "5.1"
        assert log4j["cveMetadata"]["cveId"] == "CVE-2021-44228"

        cna = log4j["containers"]["cna"]
        assert "title" in cna
        metrics = cna["metrics"][0]
        cvss = metrics.get("cvssV3_1")
        assert cvss is not None
        assert cvss["baseScore"] == 10.0
        assert cvss["baseSeverity"] == "CRITICAL"

        # Check CWE problem types
        cwes = [
            desc["cweId"]
            for pt in cna.get("problemTypes", [])
            for desc in pt.get("descriptions", [])
            if "cweId" in desc
        ]
        assert "CWE-502" in cwes

    def test_cisa_kev_sample_feed_validity(self) -> None:
        path = FIXTURES_DIR / "cisa_kev_sample.json"
        assert path.exists(), f"Missing fixture file: {path}"

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["catalogVersion"] == "2024.09.20"
        vulns = data.get("vulnerabilities", [])
        assert len(vulns) >= 4

        cve_ids = {v["cveID"] for v in vulns}
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2021-41773" in cve_ids
        assert "CVE-2022-22947" in cve_ids
        assert "CVE-2024-23897" in cve_ids
        # Express-fileupload prototype pollution must not be in KEV
        assert "CVE-2020-7699" not in cve_ids

        # Validate mandatory KEV fields
        for v in vulns:
            assert "cveID" in v
            assert "dateAdded" in v
            assert "requiredAction" in v
            assert "knownRansomwareCampaignUse" in v

    def test_epss_v4_sample_feed_validity(self) -> None:
        path = FIXTURES_DIR / "epss_v4_sample.json"
        assert path.exists(), f"Missing fixture file: {path}"

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "OK"
        assert data["version"] == "v4"
        items = data.get("data", [])
        assert len(items) >= 6

        epss_by_cve = {item["cve"]: float(item["epss"]) for item in items}
        percentile_by_cve = {item["cve"]: float(item["percentile"]) for item in items}

        # Check probability tiers
        assert epss_by_cve["CVE-2021-44228"] > 0.9  # High probability
        assert epss_by_cve["CVE-2021-41773"] > 0.9  # High probability
        assert 0.1 <= epss_by_cve["CVE-2020-7699"] <= 0.5  # Moderate probability
        assert epss_by_cve["CVE-2020-15778"] < 0.01  # Low probability

        # Check percentile consistency
        assert percentile_by_cve["CVE-2021-44228"] > 0.99
        assert percentile_by_cve["CVE-2020-15778"] < 0.50

    def test_fixture_cross_referencing(self) -> None:
        """Every CVE in baseline findings must be covered in intelligence sample feeds."""
        with open(FIXTURES_DIR / "cve_org_sample.json", encoding="utf-8") as f:
            cve_org = json.load(f)

        with open(FIXTURES_DIR / "epss_v4_sample.json", encoding="utf-8") as f:
            epss_data = json.load(f)
        epss_cves = {item["cve"] for item in epss_data["data"]}

        for finding in get_baseline_findings():
            for cve in finding.cve_ids:
                assert cve in cve_org, f"Missing CVE.org fixture for {cve}"
                assert cve in epss_cves, f"Missing EPSS fixture for {cve}"


@pytest.mark.parametrize(
    "filename", ["cve_org_sample.json", "cisa_kev_sample.json", "epss_v4_sample.json"]
)
def test_sample_feeds_are_marked_synthetic(filename: str) -> None:
    """Fixtures must declare themselves synthetic; values are not real measurements."""
    with open(FIXTURES_DIR / filename, encoding="utf-8") as f:
        data = json.load(f)
    assert data["_synthetic"] is True
    assert "not real measurements" in data["_comment"]
    assert (FIXTURES_DIR / "README.md").exists()
