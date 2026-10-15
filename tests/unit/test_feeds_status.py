"""Tests for B-2: GET /feeds/status endpoint.

Invariants tested:
- Returns 200 with a list of FeedStatus objects for all 8 feeds.
- When a .meta.json sidecar exists, synced_at / record_count / sha256 are populated.
- When no sidecar exists, synced_at is null and last_sync_result is "never".
- is_stale is True when synced_at is older than the configured threshold.
- is_stale is False for a fresh mirror.
- not_found_cache_size reflects the actual .notfound.json entry count.
- Access is audit-logged as feeds_status_read.
- Sorting: response is sorted by name alphabetically.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.main import app

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_meta(path: Path, synced_at: datetime, record_count: int = 42, sha256: str = "aabbcc") -> None:
    meta = {
        "synced_at": synced_at.isoformat(),
        "record_count": record_count,
        "sha256": sha256,
        "source_url": "https://example.com/feed",
        "last_sync_result": "ok",
    }
    meta_path = path.with_name(f"{path.stem}.meta.json")
    meta_path.write_text(json.dumps(meta), encoding="utf-8")


def _write_not_found(path: Path, cves: list[str]) -> None:
    nf_path = path.with_name(f"{path.stem}.notfound.json")
    entries = {cve: {"checked_at": datetime.now(UTC).isoformat()} for cve in cves}
    nf_path.write_text(json.dumps(entries), encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFeedsStatusEndpoint:
    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch, tmp_path):
        """Point enrichment_cache_dir to tmp_path for every test."""
        from apps.api.core import config as cfg

        monkeypatch.setattr(cfg.settings, "enrichment_cache_dir", tmp_path)
        clear_audit_log()
        self.tmp = tmp_path
        self.client = TestClient(app)

    def test_returns_200_and_list(self):
        resp = self.client.get("/feeds/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 8  # one entry per feed

    def test_no_sidecar_produces_never(self):
        resp = self.client.get("/feeds/status")
        data = resp.json()
        for entry in data:
            assert entry["synced_at"] is None
            assert entry["last_sync_result"] == "never"
            assert entry["record_count"] is None
            assert entry["sha256"] is None
            assert not entry["is_stale"]
            assert entry["not_found_cache_size"] == 0

    def test_with_sidecar_populates_fields(self):
        # Write a sidecar for cisa_kev.json (fresh, 1 day old)
        mirror = self.tmp / "cisa_kev.json"
        mirror.write_text("{}", encoding="utf-8")
        synced = datetime.now(UTC) - timedelta(days=1)
        _write_meta(mirror, synced, record_count=100, sha256="deadbeef")

        resp = self.client.get("/feeds/status")
        data = resp.json()
        kev_entry = next((e for e in data if e["name"] == "kev"), None)
        assert kev_entry is not None
        assert kev_entry["synced_at"] is not None
        assert kev_entry["record_count"] == 100
        assert kev_entry["sha256"] == "deadbeef"
        assert kev_entry["last_sync_result"] == "ok"
        assert not kev_entry["is_stale"]

    def test_stale_mirror_flagged(self):
        mirror = self.tmp / "cisa_kev.json"
        mirror.write_text("{}", encoding="utf-8")
        old_synced = datetime.now(UTC) - timedelta(days=10)
        _write_meta(mirror, old_synced)

        resp = self.client.get("/feeds/status")
        data = resp.json()
        kev_entry = next((e for e in data if e["name"] == "kev"), None)
        assert kev_entry is not None
        assert kev_entry["is_stale"] is True

    def test_not_found_cache_size_counted(self):
        mirror = self.tmp / "nvd.json"
        mirror.write_text("{}", encoding="utf-8")
        _write_meta(mirror, datetime.now(UTC) - timedelta(days=1))
        _write_not_found(mirror, ["CVE-2023-1111", "CVE-2023-2222", "CVE-2023-3333"])

        resp = self.client.get("/feeds/status")
        data = resp.json()
        nvd_entry = next((e for e in data if e["name"] == "nvd"), None)
        assert nvd_entry is not None
        assert nvd_entry["not_found_cache_size"] == 3

    def test_response_sorted_by_name(self):
        resp = self.client.get("/feeds/status")
        names = [e["name"] for e in resp.json()]
        assert names == sorted(names), f"Expected sorted names, got: {names}"

    def test_audit_event_logged(self):
        self.client.get("/feeds/status")
        events = get_audit_log()
        assert any(e["event"] == "feeds_status_read" for e in events), (
            f"Expected feeds_status_read audit event, got: {[e['event'] for e in events]}"
        )
        audit = next(e for e in events if e["event"] == "feeds_status_read")
        assert audit["target"] == "feeds"
        assert audit["status"] == "success"

    def test_all_8_feeds_present(self):
        resp = self.client.get("/feeds/status")
        names = {e["name"] for e in resp.json()}
        expected = {"kev", "epss", "exploitdb", "metasploit", "cve_org", "vulnrichment", "euvd", "nvd"}
        assert names == expected, f"Missing or extra feeds: {names ^ expected}"
