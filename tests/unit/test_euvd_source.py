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
