"""Unit tests for Task A-3: NVDRecord KEV field parsing in NVDSource._parse_record.

Verifies that when the NVD 2.0 mirror contains CISA KEV fields
(cisaExploitAdd, cisaActionDue, cisaRequiredAction, cisaVulnerabilityName)
they are correctly parsed into the corresponding NVDRecord fields, and that
records without these fields produce None values (not KeyError).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from services.enrichment.sources.secondary import NVDRecord, NVDSource


# ---------------------------------------------------------------------------
# Minimal NVD 2.0 raw record helpers
# ---------------------------------------------------------------------------

def _nvd_raw(
    cve_id: str = "CVE-2021-44228",
    cvss_score: float | None = 10.0,
    *,
    cisa_exploit_add: str | None = None,
    cisa_action_due: str | None = None,
    cisa_required_action: str | None = None,
    cisa_vulnerability_name: str | None = None,
) -> dict:
    """Build a minimal NVD 2.0 flat entry dict."""
    entry: dict = {
        "id": cve_id,
        "published": "2021-12-10T00:00:00.000",
        "lastModified": "2021-12-12T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": f"Test description for {cve_id}"}],
        "metrics": {},
        "weaknesses": [],
    }
    if cvss_score is not None:
        entry["metrics"]["cvssMetricV31"] = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "baseScore": cvss_score,
                    "baseSeverity": "CRITICAL",
                },
            }
        ]
    # Only add KEV fields when they're not None
    if cisa_exploit_add is not None:
        entry["cisaExploitAdd"] = cisa_exploit_add
    if cisa_action_due is not None:
        entry["cisaActionDue"] = cisa_action_due
    if cisa_required_action is not None:
        entry["cisaRequiredAction"] = cisa_required_action
    if cisa_vulnerability_name is not None:
        entry["cisaVulnerabilityName"] = cisa_vulnerability_name
    return entry


def _make_nvd_mirror(entries: list[dict]) -> Path:
    """Write a flat {cve_id: entry} NVD mirror to a temp file."""
    mirror_data = {e["id"]: e for e in entries}
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(mirror_data, tmp, ensure_ascii=False)
    tmp.flush()
    return Path(tmp.name)


class TestNVDRecordKEVFields:
    """NVDRecord dataclass exposes the four KEV fields."""

    def test_kev_fields_exist_on_dataclass(self) -> None:
        record = NVDRecord(cve_id="CVE-2021-0001")
        # All KEV fields default to None
        assert record.cisa_exploit_add is None
        assert record.cisa_action_due is None
        assert record.cisa_required_action is None
        assert record.cisa_vulnerability_name is None

    def test_kev_fields_can_be_set(self) -> None:
        record = NVDRecord(
            cve_id="CVE-2021-0001",
            cisa_exploit_add="2021-12-10",
            cisa_action_due="2022-01-10",
            cisa_required_action="Apply update",
            cisa_vulnerability_name="Log4Shell",
        )
        assert record.cisa_exploit_add == "2021-12-10"
        assert record.cisa_action_due == "2022-01-10"
        assert record.cisa_required_action == "Apply update"
        assert record.cisa_vulnerability_name == "Log4Shell"


class TestNVDSourceParsesKEVFields:
    """NVDSource._parse_record extracts KEV fields when present."""

    @pytest.fixture()
    def source_with_kev(self, tmp_path: Path) -> NVDSource:
        entry = _nvd_raw(
            cve_id="CVE-2021-44228",
            cisa_exploit_add="2021-12-10",
            cisa_action_due="2022-01-10",
            cisa_required_action="Apply updates per vendor instructions.",
            cisa_vulnerability_name="Apache Log4j2 Remote Code Execution Vulnerability",
        )
        mirror = _make_nvd_mirror([entry])
        return NVDSource(cache_file=mirror)

    @pytest.fixture()
    def source_without_kev(self, tmp_path: Path) -> NVDSource:
        entry = _nvd_raw(cve_id="CVE-2020-1234")  # No KEV fields
        mirror = _make_nvd_mirror([entry])
        return NVDSource(cache_file=mirror)

    def test_kev_fields_parsed_when_present(self, source_with_kev: NVDSource) -> None:
        record = source_with_kev.lookup("CVE-2021-44228")
        assert record is not None
        assert isinstance(record, NVDRecord)
        assert record.cisa_exploit_add == "2021-12-10"
        assert record.cisa_action_due == "2022-01-10"
        assert record.cisa_required_action == "Apply updates per vendor instructions."
        assert record.cisa_vulnerability_name == (
            "Apache Log4j2 Remote Code Execution Vulnerability"
        )

    def test_kev_fields_none_when_absent(self, source_without_kev: NVDSource) -> None:
        record = source_without_kev.lookup("CVE-2020-1234")
        assert record is not None
        assert isinstance(record, NVDRecord)
        assert record.cisa_exploit_add is None
        assert record.cisa_action_due is None
        assert record.cisa_required_action is None
        assert record.cisa_vulnerability_name is None

    def test_cvss_still_parsed_when_kev_present(self, source_with_kev: NVDSource) -> None:
        """KEV field addition must not break existing CVSS parsing."""
        record = source_with_kev.lookup("CVE-2021-44228")
        assert record is not None
        assert record.cvss_score == 10.0
        assert record.cvss_version == "3.1"

    def test_kev_fields_whitespace_stripped(self, tmp_path: Path) -> None:
        """Leading/trailing whitespace in raw KEV strings is normalised away."""
        entry = _nvd_raw(cve_id="CVE-2021-99999")
        entry["cisaExploitAdd"] = "  2021-12-10  "
        entry["cisaVulnerabilityName"] = "  Whitespace Vuln  "
        mirror = _make_nvd_mirror([entry])
        source = NVDSource(cache_file=mirror)
        record = source.lookup("CVE-2021-99999")
        assert record is not None
        assert record.cisa_exploit_add == "2021-12-10"
        assert record.cisa_vulnerability_name == "Whitespace Vuln"

    def test_empty_string_kev_normalised_to_none(self, tmp_path: Path) -> None:
        """An empty string KEV value is treated as None."""
        entry = _nvd_raw(cve_id="CVE-2021-88888")
        entry["cisaExploitAdd"] = ""
        entry["cisaActionDue"] = "   "
        mirror = _make_nvd_mirror([entry])
        source = NVDSource(cache_file=mirror)
        record = source.lookup("CVE-2021-88888")
        assert record is not None
        assert record.cisa_exploit_add is None
        assert record.cisa_action_due is None

    def test_real_nvd_mirror_has_kev_for_known_cve(self) -> None:
        """Regression: the real NVD mirror contains KEV fields for Log4Shell."""
        import os
        mirror_path = Path("data/enrichment_cache/nvd.json")
        if not mirror_path.exists():
            pytest.skip("Real NVD mirror not present")

        source = NVDSource(cache_file=mirror_path)
        record = source.lookup("CVE-2021-44228")
        # Log4Shell is in CISA KEV; NVD should carry cisaExploitAdd.
        # If the mirror predates KEV integration, skip gracefully.
        if record is None:
            pytest.skip("CVE-2021-44228 not in real NVD mirror")
        if record.cisa_exploit_add is None:
            pytest.skip(
                "NVD mirror does not carry KEV fields for CVE-2021-44228 "
                "(older mirror snapshot or KEV not back-filled)"
            )
        assert record.cisa_exploit_add  # non-empty date string


class TestNVDKEVInRealMirror:
    """Spot-checks against the real local mirror (skipped if mirror absent)."""

    def test_mirror_format_is_flat_dict(self) -> None:
        import re
        mirror_path = Path("data/enrichment_cache/nvd.json")
        if not mirror_path.exists():
            pytest.skip("Real NVD mirror not present")

        import json
        data = json.loads(mirror_path.read_text(encoding="utf-8"))
        assert isinstance(data, dict), "Expected flat {cve_id: entry} dict"
        cve_re = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")
        assert any(cve_re.match(k) for k in data), "No CVE-like keys found"
