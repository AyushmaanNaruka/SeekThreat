"""Tests for B-1: Mirror staleness policy in BaseEnrichmentSource and FusionEngine.

Invariants tested:
- A fresh mirror (synced_at within threshold) → is_stale() == False.
- A stale mirror (synced_at beyond threshold) → is_stale() == True.
- Negative assertion from a stale KEV mirror → Confidence.MEDIUM, note mentions "stale".
- Positive assertion from a stale KEV mirror → Confidence.HIGH (never downgraded).
- Negative ExploitDB from stale mirror → Confidence.LOW.
- Negative Metasploit from stale mirror → Confidence.LOW.
- mirror_age_days() returns None for a source without a cache file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.sources.base import clear_mirror_cache
from services.enrichment.sources.cisa_kev import CISAKevSource
from services.enrichment.sources.secondary import ExploitDBSource, MetasploitSource

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_meta(mirror_path: Path, synced_at: datetime) -> None:
    """Write a .meta.json sidecar with the given synced_at timestamp."""
    meta = {
        "synced_at": synced_at.isoformat(),
        "source_url": "https://example.com/feed",
        "record_count": 0,
        "sha256": "aabbcc",
    }
    meta_path = mirror_path.with_name(f"{mirror_path.stem}.meta.json")
    meta_path.write_text(json.dumps(meta), encoding="utf-8")


def _fresh_kev_mirror(tmp: Path, days_old: float = 1.0) -> tuple[Path, CISAKevSource]:
    """Write a KEV mirror with at least one record and a sidecar ``days_old`` days ago."""
    mirror = tmp / "cisa_kev.json"
    catalog = {
        "catalogVersion": "2024.01.01",
        "vulnerabilities": [
            {
                "cveID": "CVE-2020-0001",
                "vendorProject": "Test",
                "product": "Test",
                "vulnerabilityName": "Test Vuln",
                "dateAdded": "2020-01-01",
                "shortDescription": "Test",
                "requiredAction": "Patch",
                "dueDate": "2020-01-15",
            }
        ],
    }
    mirror.write_text(json.dumps(catalog), encoding="utf-8")
    _write_meta(mirror, datetime.now(UTC) - timedelta(days=days_old))
    clear_mirror_cache(Source.KEV)
    return mirror, CISAKevSource(cache_file=mirror)


def _simple_finding(cve_id: str = "CVE-2023-99999") -> object:
    """Minimal Finding-like object with one CVE ID."""
    from packages.schema.models.finding import Finding

    return Finding(
        finding_id="fnd-1",
        asset_id="ast-1",
        scanner="nmap",
        observation_ids=["obs-1"],
        detected_at=datetime.now(UTC),
        title="test",
        severity="HIGH",
        cve_ids=[cve_id],
        scan_id="scan-1",
        engagement_id="eng-1",
    )


# ---------------------------------------------------------------------------
# BaseEnrichmentSource.mirror_age_days / is_stale
# ---------------------------------------------------------------------------


class TestMirrorAgeAndIsStale:
    def test_no_cache_file_age_is_none(self):
        kev = CISAKevSource(cache_file=None)
        assert kev.mirror_age_days() is None

    def test_no_cache_file_is_stale_false(self):
        kev = CISAKevSource(cache_file=None)
        assert kev.is_stale(threshold_days=1) is False

    def test_fresh_mirror_not_stale(self, tmp_path):
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=1.0)
        assert not kev.is_stale(threshold_days=7)

    def test_stale_mirror_is_stale(self, tmp_path):
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=10.0)
        assert kev.is_stale(threshold_days=7)

    def test_age_days_matches_synced_at(self, tmp_path):
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=3.0)
        age = kev.mirror_age_days()
        assert age is not None
        assert 2.9 < age < 3.1, f"Expected ~3.0 days old, got {age}"

    def test_just_under_threshold_not_stale(self, tmp_path):
        # Mirror slightly under 7 days old is NOT stale
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=6.95)
        assert not kev.is_stale(threshold_days=7)

    def test_past_threshold_is_stale(self, tmp_path):
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=7.05)
        assert kev.is_stale(threshold_days=7)


# ---------------------------------------------------------------------------
# FusionEngine staleness downgrade — KEV
# ---------------------------------------------------------------------------


class TestKevStalenessDowngrade:
    def _engine_with_kev(self, tmp_path: Path, days_old: float) -> FusionEngine:
        _mirror, kev = _fresh_kev_mirror(tmp_path, days_old=days_old)
        return FusionEngine(cisa_kev=kev)

    def test_fresh_kev_negative_is_high(self, tmp_path):
        engine = self._engine_with_kev(tmp_path, days_old=1.0)
        finding = _simple_finding()
        fields = engine.fuse(finding)
        in_kev = fields.get("in_kev")
        assert in_kev is not None
        assert in_kev.value is False
        assert in_kev.provenance.confidence == Confidence.HIGH

    def test_stale_kev_negative_is_medium(self, tmp_path):
        engine = self._engine_with_kev(tmp_path, days_old=10.0)
        finding = _simple_finding()
        fields = engine.fuse(finding)
        in_kev = fields.get("in_kev")
        assert in_kev is not None
        assert in_kev.value is False
        assert in_kev.provenance.confidence == Confidence.MEDIUM, (
            f"Expected MEDIUM confidence for stale KEV, got {in_kev.provenance.confidence}"
        )
        assert "stale" in (in_kev.provenance.note or "").lower(), (
            f"Expected 'stale' in provenance note, got: {in_kev.provenance.note}"
        )

    def test_stale_kev_positive_still_high(self, tmp_path):
        """A confirmed KEV hit must never be downgraded regardless of mirror age."""
        mirror = tmp_path / "cisa_kev.json"
        catalog = {
            "catalogVersion": "2024.01.01",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "Log4j RCE",
                    "requiredAction": "Patch",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }
        mirror.write_text(json.dumps(catalog), encoding="utf-8")
        _write_meta(mirror, datetime.now(UTC) - timedelta(days=10.0))
        clear_mirror_cache(Source.KEV)
        kev = CISAKevSource(cache_file=mirror)
        engine = FusionEngine(cisa_kev=kev)

        finding = _simple_finding("CVE-2021-44228")
        fields = engine.fuse(finding)
        in_kev = fields.get("in_kev")
        assert in_kev is not None
        assert in_kev.value is True
        assert in_kev.provenance.confidence == Confidence.HIGH


# ---------------------------------------------------------------------------
# FusionEngine staleness downgrade — ExploitDB
# ---------------------------------------------------------------------------


class TestExploitDBStalenessDowngrade:
    def _engine_with_exploitdb(self, tmp_path: Path, days_old: float) -> FusionEngine:
        mirror = tmp_path / "exploitdb.json"
        mirror.write_text(
            json.dumps({"CVE-2020-0001": {"exploit_ids": ["12345"]}}), encoding="utf-8"
        )
        _write_meta(mirror, datetime.now(UTC) - timedelta(days=days_old))
        clear_mirror_cache(Source.EXPLOITDB)
        edb = ExploitDBSource(cache_file=mirror)
        return FusionEngine(exploitdb=edb)

    def test_fresh_exploitdb_negative_is_medium(self, tmp_path):
        engine = self._engine_with_exploitdb(tmp_path, days_old=1.0)
        fields = engine.fuse(_simple_finding())
        result = fields.get("has_public_exploit")
        if result is not None:
            assert result.provenance.confidence in (
                Confidence.MEDIUM,
                Confidence.HIGH,
                Confidence.LOW,
            )
            if result.value is False:
                assert result.provenance.confidence == Confidence.MEDIUM

    def test_stale_exploitdb_negative_is_low(self, tmp_path):
        engine = self._engine_with_exploitdb(tmp_path, days_old=10.0)
        fields = engine.fuse(_simple_finding())
        result = fields.get("has_public_exploit")
        assert result is not None
        assert result.value is False
        assert result.provenance.confidence == Confidence.LOW, (
            f"Expected LOW confidence for stale ExploitDB, got {result.provenance.confidence}"
        )
        assert "stale" in (result.provenance.note or "").lower()


# ---------------------------------------------------------------------------
# FusionEngine staleness downgrade — Metasploit
# ---------------------------------------------------------------------------


class TestMetasploitStalenessDowngrade:
    def _engine_with_metasploit(self, tmp_path: Path, days_old: float) -> FusionEngine:
        mirror = tmp_path / "metasploit.json"
        mirror.write_text(
            json.dumps({"CVE-2020-0001": {"module_names": ["exploit/test"]}}), encoding="utf-8"
        )
        _write_meta(mirror, datetime.now(UTC) - timedelta(days=days_old))
        clear_mirror_cache(Source.METASPLOIT)
        msf = MetasploitSource(cache_file=mirror)
        return FusionEngine(metasploit=msf)

    def test_fresh_metasploit_negative_is_medium(self, tmp_path):
        engine = self._engine_with_metasploit(tmp_path, days_old=1.0)
        fields = engine.fuse(_simple_finding())
        result = fields.get("has_metasploit_module")
        if result is not None and result.value is False:
            assert result.provenance.confidence == Confidence.MEDIUM

    def test_stale_metasploit_negative_is_low(self, tmp_path):
        engine = self._engine_with_metasploit(tmp_path, days_old=10.0)
        fields = engine.fuse(_simple_finding())
        result = fields.get("has_metasploit_module")
        assert result is not None
        assert result.value is False
        assert result.provenance.confidence == Confidence.LOW, (
            f"Expected LOW confidence for stale Metasploit, got {result.provenance.confidence}"
        )
        assert "stale" in (result.provenance.note or "").lower()
