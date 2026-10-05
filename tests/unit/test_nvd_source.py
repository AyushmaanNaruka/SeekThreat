"""Unit tests for NVD 2.0 secondary intelligence source."""

from __future__ import annotations

import json
from pathlib import Path

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.secondary import NVDRecord, NVDSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestNVDSource:
    """Tests loading, parsing, and lookups for NVD 2.0 metadata."""

    def test_load_from_mirror_file(self) -> None:
        source = NVDSource(cache_file=FIXTURES_DIR / "nvd_sample.json")
        assert source.is_loaded is True
        assert source.count() >= 4

    def test_lookup_record_fields(self) -> None:
        source = NVDSource(cache_file=FIXTURES_DIR / "nvd_sample.json")
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert isinstance(rec, NVDRecord)
        assert rec.cve_id == "CVE-2021-44228"
        assert rec.source == Source.NVD
        assert rec.confidence == Confidence.HIGH
        assert rec.cvss_score == 10.0
        assert rec.cwe_ids == ["CWE-502"]
        assert "Log4j2" in rec.description

    def test_lookup_case_insensitive(self) -> None:
        source = NVDSource(cache_file=FIXTURES_DIR / "nvd_sample.json")
        rec = source.lookup("cve-2021-41773")
        assert rec is not None
        assert rec.cvss_score == 7.5
        assert rec.cwe_ids == ["CWE-22"]

    def test_lookup_missing_returns_none(self) -> None:
        source = NVDSource(cache_file=FIXTURES_DIR / "nvd_sample.json")
        assert source.lookup("CVE-2024-23897") is None

    def test_missing_cache_file_graceful(self, tmp_path: Path) -> None:
        missing_path = tmp_path / "nonexistent_nvd.json"
        source = NVDSource(cache_file=missing_path)
        assert source.is_loaded is False
        assert source.count() == 0
        assert source.lookup("CVE-2021-44228") is None

    def test_parse_nvd_api_format(self, tmp_path: Path) -> None:
        """Verify parsing official NVD 2.0 API response structure."""
        api_data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [{"lang": "en", "value": "Sample NVD description"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "vectorString": (
                                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                                        ),
                                        "baseScore": 9.8,
                                        "baseSeverity": "CRITICAL",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {
                                "description": [{"lang": "en", "value": "CWE-79"}]
                            }
                        ],
                    }
                }
            ]
        }
        test_file = tmp_path / "nvd_api.json"
        test_file.write_text(json.dumps(api_data), encoding="utf-8")

        source = NVDSource(cache_file=test_file)
        rec = source.lookup("CVE-2023-12345")
        assert rec is not None
        assert rec.cvss_score == 9.8
        assert rec.cwe_ids == ["CWE-79"]
        assert rec.description == "Sample NVD description"
