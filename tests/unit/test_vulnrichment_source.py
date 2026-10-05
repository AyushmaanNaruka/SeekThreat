"""Unit tests for CISA Vulnrichment secondary intelligence source."""

from __future__ import annotations

import json
from pathlib import Path

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.secondary import VulnrichmentRecord, VulnrichmentSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestVulnrichmentSource:
    """Tests loading, parsing, and lookups for CISA Vulnrichment source."""

    def test_load_from_mirror_file(self) -> None:
        source = VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json")
        assert source.is_loaded is True
        assert source.count() >= 3

    def test_lookup_record_fields(self) -> None:
        source = VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json")
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert isinstance(rec, VulnrichmentRecord)
        assert rec.cve_id == "CVE-2021-44228"
        assert rec.source == Source.VULNRICHMENT
        assert rec.confidence == Confidence.MEDIUM
        assert rec.ssvc_decision == "Act"
        assert rec.cvss_score == 10.0
        assert rec.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert rec.cwe_ids == ["CWE-502"]

    def test_lookup_attend_record(self) -> None:
        source = VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json")
        rec = source.lookup("cve-2025-0001")  # Case insensitive
        assert rec is not None
        assert rec.cve_id == "CVE-2025-0001"
        assert rec.ssvc_decision == "Attend"
        assert rec.cvss_score == 8.1
        assert rec.cwe_ids == ["CWE-79"]

    def test_lookup_missing_cve_returns_none(self) -> None:
        source = VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json")
        assert source.lookup("CVE-9999-9999") is None

    def test_missing_cache_file_graceful(self, tmp_path: Path) -> None:
        missing_path = tmp_path / "nonexistent.json"
        source = VulnrichmentSource(cache_file=missing_path)
        assert source.is_loaded is False
        assert source.count() == 0
        assert source.lookup("CVE-2021-44228") is None

    def test_malformed_records_handled_gracefully(self, tmp_path: Path) -> None:
        corrupt_data = {
            "_synthetic": True,
            "CVE-VALID": {
                "cveId": "CVE-VALID",
                "cvss_score": 7.5,
                "ssvc_decision": "Track",
            },
            "CVE-CORRUPT": "not a dictionary",
            "CVE-INVALID-CVSS": {
                "cveId": "CVE-INVALID-CVSS",
                "cvss_score": "not_a_number",
            },
        }
        test_file = tmp_path / "corrupt_vulnrichment.json"
        test_file.write_text(json.dumps(corrupt_data), encoding="utf-8")

        source = VulnrichmentSource(cache_file=test_file)
        assert source.is_loaded is True
        assert source.lookup("CVE-VALID") is not None
        assert source.lookup("CVE-CORRUPT") is None
        # Invalid cvss record should still parse or degrade safely
        assert source.lookup("NON_EXISTENT") is None

    def test_parse_cve_v5_adp_format(self, tmp_path: Path) -> None:
        adp_data = {
            "CVE-2024-1234": {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {"cveId": "CVE-2024-1234", "dateUpdated": "2024-06-01T10:00:00Z"},
                "containers": {
                    "adp": [
                        {
                            "title": "CISA ADP Vulnrichment",
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 9.1,
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                                        ),
                                    }
                                },
                                {
                                    "other": {
                                        "type": "ssvc",
                                        "content": {"decision": "Act"},
                                    }
                                },
                            ],
                            "problemTypes": [
                                {
                                    "descriptions": [
                                        {"cweId": "CWE-89"},
                                    ]
                                }
                            ],
                        }
                    ]
                },
            }
        }
        test_file = tmp_path / "adp_vulnrichment.json"
        test_file.write_text(json.dumps(adp_data), encoding="utf-8")

        source = VulnrichmentSource(cache_file=test_file)
        assert source.is_loaded is True
        rec = source.lookup("CVE-2024-1234")
        assert rec is not None
        assert rec.cvss_score == 9.1
        assert rec.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        assert rec.ssvc_decision == "Act"
        assert rec.cwe_ids == ["CWE-89"]
