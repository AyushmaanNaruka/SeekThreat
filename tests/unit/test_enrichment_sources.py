"""Unit tests for Track 2 intelligence source clients."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources import (
    CISAKevSource,
    CVEOrgSource,
    EUVDSource,
    FirstEPSSSource,
    NVDSource,
    SourceSynchronizer,
    VulnrichmentSource,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestCVEOrgSource:
    """Test CVE.org local-mirror client (Priority 1)."""

    def test_cve_org_source_loading_and_lookup(self) -> None:
        source = CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json")
        assert source.priority == 1
        assert source.source == Source.CVE_ORG
        assert source.count() >= 6

        # Lookup Log4Shell
        record = source.lookup("CVE-2021-44228")
        assert record is not None
        assert record.cve_id == "CVE-2021-44228"
        assert record.cvss_score == 10.0
        assert record.base_severity == "CRITICAL"
        assert "CVSS:3.1" in (record.cvss_vector or "")
        assert "CWE-502" in record.cwe_ids
        assert "Log4j2" in record.description

    def test_cve_org_case_insensitivity(self) -> None:
        source = CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json")
        rec_lower = source.lookup("cve-2021-44228")
        rec_upper = source.lookup("CVE-2021-44228")
        assert rec_lower is not None and rec_upper is not None
        assert rec_lower.cve_id == rec_upper.cve_id

    def test_cve_org_missing_cve_returns_none(self) -> None:
        source = CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json")
        assert source.lookup("CVE-1999-99999") is None

    def test_cve_org_attributed_conversion(self) -> None:
        source = CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json")
        record = source.lookup("CVE-2021-41773")
        assert record is not None

        attr_cvss = record.get_attributed_cvss()
        assert attr_cvss is not None
        assert attr_cvss.value == 7.5
        assert attr_cvss.provenance.source == Source.CVE_ORG
        assert attr_cvss.provenance.confidence == Confidence.HIGH

        attr_cwe = record.get_attributed_cwe()
        assert attr_cwe is not None
        assert attr_cwe.value == ["CWE-22"]
        assert attr_cwe.provenance.source == Source.CVE_ORG


class TestCISAKevSource:
    """Test CISA KEV local-mirror client (Priority 3)."""

    def test_cisa_kev_source_loading_and_lookup(self) -> None:
        source = CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json")
        assert source.priority == 3
        assert source.source == Source.KEV
        assert source.count() >= 4

        # Positive lookup
        rec_log4j = source.lookup("CVE-2021-44228")
        assert rec_log4j.is_in_kev is True
        assert rec_log4j.vendor_project == "Apache"
        assert rec_log4j.date_added == "2021-12-10"
        assert rec_log4j.known_ransomware_campaign_use == "Known"

        attr_kev = rec_log4j.get_attributed_is_in_kev()
        assert attr_kev.value is True
        assert attr_kev.provenance.source == Source.KEV
        assert attr_kev.provenance.confidence == Confidence.HIGH

    def test_cisa_kev_negative_affirmative_record(self) -> None:
        source = CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json")
        # CVE-2020-7699 is not in KEV
        rec_negative = source.lookup("CVE-2020-7699")
        assert rec_negative.is_in_kev is False
        assert rec_negative.source == Source.KEV
        assert rec_negative.confidence == Confidence.HIGH

        attr_negative = rec_negative.get_attributed_is_in_kev()
        assert attr_negative.value is False
        assert "Not listed" in (attr_negative.provenance.note or "")


class TestFirstEPSSSource:
    """Test FIRST EPSS v4 local-mirror client (Priority 4)."""

    def test_epss_source_loading_and_lookup(self) -> None:
        source = FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json")
        assert source.priority == 4
        assert source.source == Source.EPSS
        assert source.count() >= 6

        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert abs(rec.epss - 0.97543) < 1e-6
        assert abs(rec.percentile - 0.99980) < 1e-6

        attr_epss = rec.get_attributed_epss()
        assert attr_epss.value == rec.epss
        assert attr_epss.provenance.source == Source.EPSS
        assert attr_epss.provenance.confidence == Confidence.HIGH

    def test_epss_missing_cve_returns_none(self) -> None:
        source = FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json")
        assert source.lookup("CVE-1999-0000") is None


class TestSourcePrioritiesAndIsolation:
    """Verify source hierarchy and offline isolation invariants."""

    def test_source_priorities_match_readme(self) -> None:
        assert CVEOrgSource.priority == 1
        assert VulnrichmentSource.priority == 2
        assert CISAKevSource.priority == 3
        assert FirstEPSSSource.priority == 4
        assert NVDSource.priority == 5
        assert EUVDSource.priority == 6

    def test_lookup_performs_zero_network_calls(self) -> None:
        source = CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json")
        with patch("socket.socket") as mock_sock:
            record = source.lookup("CVE-2021-44228")
            assert record is not None
            mock_sock.assert_not_called()


class TestSourceSynchronizer:
    """Test source synchronizer coordinator and atomic file persistence."""

    def test_synchronizer_atomic_sync(self, tmp_path: Path) -> None:
        syncer = SourceSynchronizer(cache_dir=tmp_path)
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.95", "percentile": "0.99"}]}
        result = syncer.sync_from_data(Source.EPSS, payload, count=1)

        assert result.success is True
        assert result.records_synced == 1
        assert result.target_path.exists()
        assert syncer.get_source_path(Source.EPSS) == result.target_path
