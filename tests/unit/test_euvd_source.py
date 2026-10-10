"""Unit tests for ENISA EUVD secondary intelligence source."""

from __future__ import annotations

import json
from pathlib import Path

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.secondary import EUVDRecord, EUVDSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestEUVDSource:
    """Tests loading, parsing, and lookups for ENISA EUVD source."""

    def test_load_from_mirror_file(self) -> None:
        source = EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json")
        assert source.is_loaded is True
        assert source.count() >= 2

    def test_lookup_record_fields(self) -> None:
        source = EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json")
        rec = source.lookup("CVE-2025-0002")
        assert rec is not None
        assert isinstance(rec, EUVDRecord)
        assert rec.cve_id == "CVE-2025-0002"
        assert rec.source == Source.EUVD
        assert rec.confidence == Confidence.MEDIUM
        assert rec.cvss_score == 6.5
        assert rec.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"
        assert rec.cwe_ids == ["CWE-20"]
        assert "EUVD fallback record" in rec.description

    def test_lookup_case_insensitive(self) -> None:
        source = EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json")
        rec = source.lookup("cve-2025-0002")
        assert rec is not None
        assert rec.cve_id == "CVE-2025-0002"

    def test_lookup_missing_cve_returns_none(self) -> None:
        source = EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json")
        assert source.lookup("CVE-9999-9999") is None

    def test_missing_cache_file_graceful(self, tmp_path: Path) -> None:
        missing_path = tmp_path / "nonexistent_euvd.json"
        source = EUVDSource(cache_file=missing_path)
        assert source.is_loaded is False
        assert source.count() == 0
        assert source.lookup("CVE-2025-0002") is None

    def test_graceful_degradation_for_incomplete_data(self, tmp_path: Path) -> None:
        incomplete_data = {
            "_synthetic": True,
            "CVE-INCOMPLETE-1": {
                "cve_id": "CVE-INCOMPLETE-1",
                # No CVSS, no CWE, only title
                "description": "Beta advisory without CVSS metrics",
            },
            "CVE-INCOMPLETE-2": {
                "cve_id": "CVE-INCOMPLETE-2",
                "cvss_score": "invalid_score",
                "cwe_ids": ["CWE-79"],
            },
            "CVE-BAD-TYPE": None,
        }
        test_file = tmp_path / "incomplete_euvd.json"
        test_file.write_text(json.dumps(incomplete_data), encoding="utf-8")

        source = EUVDSource(cache_file=test_file)
        assert source.is_loaded is True
        rec1 = source.lookup("CVE-INCOMPLETE-1")
        assert rec1 is not None
        assert rec1.cvss_score is None
        assert rec1.cwe_ids == []
        assert "Beta advisory" in rec1.description

        rec2 = source.lookup("CVE-INCOMPLETE-2")
        assert rec2 is not None
        assert rec2.cvss_score is None  # invalid_score safely coerced to None
        assert rec2.cwe_ids == ["CWE-79"]


UPSTREAM = FIXTURES_DIR / "upstream"


def _captured_items() -> list[dict[str, object]]:
    search = json.loads((UPSTREAM / "euvd_search_CVE-2024-3400.json").read_text("utf-8"))
    items: list[dict[str, object]] = search["items"]
    return items


class TestEUVDRealShape:
    """Parser against the captured euvdservices.enisa.europa.eu /api/search item."""

    def test_real_record_fields(self, tmp_path: Path) -> None:
        path = tmp_path / "euvd.json"
        path.write_text(json.dumps({"CVE-2024-3400": _captured_items()[0]}), encoding="utf-8")
        rec = EUVDSource(cache_file=path).lookup("CVE-2024-3400")
        assert rec is not None
        assert rec.euvd_id == "EUVD-2024-31989"
        assert rec.cvss_score == 10.0
        assert rec.cvss_version == "3.1"
        assert rec.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert rec.aliases == ["CVE-2024-3400", "GHSA-v475-xhc9-wfxg"]
        assert "GlobalProtect" in rec.description
        assert rec.cwe_ids == []  # EUVD records carry no CWE field

    def test_cve_resolved_from_aliases_without_key(self, tmp_path: Path) -> None:
        path = tmp_path / "euvd.json"
        path.write_text(json.dumps(_captured_items()), encoding="utf-8")
        assert EUVDSource(cache_file=path).lookup("CVE-2024-3400") is not None

    def test_invented_camelcase_keys_are_not_read(self, tmp_path: Path) -> None:
        path = tmp_path / "euvd.json"
        invented = {"CVE-2024-0001": {"cvssBaseScore": 9.9, "cvssVector": "CVSS:3.1/X"}}
        path.write_text(json.dumps(invented), encoding="utf-8")
        rec = EUVDSource(cache_file=path).lookup("CVE-2024-0001")
        assert rec is not None
        assert rec.cvss_score is None
        assert rec.cvss_vector is None
