"""Unit tests for Metasploit secondary intelligence source (Hard Rule 4: Module names only)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.secondary import MetasploitRecord, MetasploitSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class TestMetasploitSource:
    """Tests loading, parsing, and lookups for Metasploit module metadata."""

    def test_load_from_mirror_file(self) -> None:
        source = MetasploitSource(cache_file=FIXTURES_DIR / "metasploit_sample.json")
        assert source.is_loaded is True
        assert source.count() >= 3

    def test_lookup_module_names_only(self) -> None:
        """Verify output contains ONLY module names (Hard Rule 4)."""
        source = MetasploitSource(cache_file=FIXTURES_DIR / "metasploit_sample.json")
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert isinstance(rec, MetasploitRecord)
        assert rec.cve_id == "CVE-2021-44228"
        assert rec.source == Source.METASPLOIT
        assert rec.confidence == Confidence.HIGH
        assert rec.module_names == ["exploit/multi/http/log4shell_header_injection"]
        assert rec.has_metasploit_module is True

        # Assert no executable code attributes exist
        assert not hasattr(rec, "code")
        assert not hasattr(rec, "ruby")
        assert not hasattr(rec, "exploit_body")

    def test_lookup_case_insensitive(self) -> None:
        source = MetasploitSource(cache_file=FIXTURES_DIR / "metasploit_sample.json")
        rec = source.lookup("cve-2021-41773")
        assert rec is not None
        assert rec.module_names == ["exploit/multi/http/apache_normalize_path_rce"]
        assert rec.has_metasploit_module is True

    def test_lookup_missing_returns_none(self) -> None:
        source = MetasploitSource(cache_file=FIXTURES_DIR / "metasploit_sample.json")
        assert source.lookup("CVE-2099-0001") is None

    def test_missing_cache_file_graceful(self, tmp_path: Path) -> None:
        missing_path = tmp_path / "nonexistent_msf.json"
        source = MetasploitSource(cache_file=missing_path)
        assert source.is_loaded is False
        assert source.count() == 0
        assert source.lookup("CVE-2021-44228") is None

    def test_load_rapid7_modules_metadata_format(self, tmp_path: Path) -> None:
        """Test parsing Rapid7 modules_metadata_base.json format."""
        rapid7_data = {
            "exploit/multi/http/log4shell_header_injection": {
                "name": "Log4Shell HTTP Header Injection",
                "references": [
                    "CVE-2021-44228",
                    "URL-https://logging.apache.org/log4j/2.x/security.html",
                ],
            },
            "auxiliary/scanner/http/apache_options": {
                "name": "Apache Options Scanner",
                "references": [],
            },
        }
        test_file = tmp_path / "modules_metadata_base.json"
        test_file.write_text(json.dumps(rapid7_data), encoding="utf-8")

        source = MetasploitSource(cache_file=test_file)
        assert source.is_loaded is True
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.module_names == ["exploit/multi/http/log4shell_header_injection"]
        assert rec.has_metasploit_module is True
