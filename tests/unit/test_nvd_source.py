"""Unit tests for NVD 2.0 secondary intelligence source."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

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
                        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
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


UPSTREAM = FIXTURES_DIR / "upstream"


def _write(tmp_path: Path, cve: dict[str, object]) -> Path:
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps({"vulnerabilities": [{"cve": cve}]}), encoding="utf-8")
    return path


def _metric(score: float, source: str, kind: str, version: str = "3.1") -> dict[str, object]:
    return {
        "source": source,
        "type": kind,
        "cvssData": {
            "version": version,
            "vectorString": f"CVSS:{version}/AV:N",
            "baseScore": score,
            "baseSeverity": "HIGH",
        },
    }


class TestNVDRealShape:
    """Parser behaviour against the captured NVD API 2.0 response and its edge cases."""

    def test_captured_response_uses_nvd_primary_metric(self) -> None:
        source = NVDSource(cache_file=UPSTREAM / "nvd_response_CVE-2021-44228.json")
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.cvss_score == 10.0
        assert rec.cvss_version == "3.1"
        assert rec.cvss_source == "nvd@nist.gov"
        assert rec.confidence == Confidence.HIGH
        assert "CWE-502" in rec.cwe_ids

    def test_primary_preferred_over_listed_first_secondary(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2024-0001",
            "metrics": {
                "cvssMetricV31": [
                    _metric(5.0, "cna@example.test", "Secondary"),
                    _metric(9.1, "nvd@nist.gov", "Primary"),
                ]
            },
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2024-0001")
        assert rec is not None
        assert rec.cvss_score == 9.1
        assert rec.confidence == Confidence.HIGH

    def test_secondary_only_is_lower_confidence(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2024-0002",
            "metrics": {"cvssMetricV31": [_metric(6.1, "cna@example.test", "Secondary")]},
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2024-0002")
        assert rec is not None
        assert rec.cvss_score == 6.1
        assert rec.cvss_source == "cna@example.test"
        assert rec.confidence == Confidence.MEDIUM

    def test_v30_used_when_no_v31(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2018-0001",
            "metrics": {"cvssMetricV30": [_metric(7.2, "nvd@nist.gov", "Primary", "3.0")]},
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2018-0001")
        assert rec is not None
        assert rec.cvss_score == 7.2
        assert rec.cvss_version == "3.0"

    def test_v40_used_when_no_v3(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2025-0001",
            "metrics": {"cvssMetricV40": [_metric(8.7, "nvd@nist.gov", "Primary", "4.0")]},
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2025-0001")
        assert rec is not None
        assert rec.cvss_score == 8.7
        assert rec.cvss_version == "4.0"

    def test_v31_preferred_over_v40(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2025-0002",
            "metrics": {
                "cvssMetricV40": [_metric(8.7, "nvd@nist.gov", "Primary", "4.0")],
                "cvssMetricV31": [_metric(7.5, "nvd@nist.gov", "Primary", "3.1")],
            },
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2025-0002")
        assert rec is not None
        assert rec.cvss_version == "3.1"

    def test_nvd_cwe_placeholders_filtered(self, tmp_path: Path) -> None:
        cve = {
            "id": "CVE-2024-0003",
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "NVD-CWE-noinfo"},
                        {"lang": "en", "value": "NVD-CWE-Other"},
                        {"lang": "en", "value": "CWE-787"},
                    ]
                }
            ],
        }
        rec = NVDSource(cache_file=_write(tmp_path, cve)).lookup("CVE-2024-0003")
        assert rec is not None
        assert rec.cwe_ids == ["CWE-787"]

    def test_flat_cwe_placeholders_filtered(self, tmp_path: Path) -> None:
        path = tmp_path / "nvd.json"
        flat = {"CVE-2024-0004": {"cwe_ids": ["nvd-cwe-noinfo", "NVD-CWE-OTHER", "CWE-79"]}}
        path.write_text(json.dumps(flat), encoding="utf-8")
        rec = NVDSource(cache_file=path).lookup("CVE-2024-0004")
        assert rec is not None
        assert rec.cwe_ids == ["CWE-79"]

    def test_corrupt_mirror_is_logged_not_silent(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # alembic's fileConfig (exercised by test_alembic) disables existing loggers.
        monkeypatch.setattr(
            logging.getLogger("services.enrichment.sources.secondary"), "disabled", False
        )
        path = tmp_path / "nvd.json"
        path.write_text("{not json", encoding="utf-8")
        with caplog.at_level(logging.WARNING):
            source = NVDSource(cache_file=path)
        assert source.is_loaded is False
        assert any("nvd.json" in r.getMessage() for r in caplog.records)
