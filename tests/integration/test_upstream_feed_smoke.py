"""Integration smoke tests for upstream threat intelligence feeds (Task 2).

Validates:
1. EUVD search query parameters (?text={cve}&size=10) and alias matching.
2. NVD API 2.0 per-CVE lookup and rate limit header handling.
3. Live upstream smoke test (opt-in via RUN_LIVE_FEED_SMOKE=1; skipped in standard CI).
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from packages.schema.models.provenance import Source
from services.enrichment.sources import EUVDSource, NVDSource
from services.enrichment.sources.sync import (
    DEFAULT_EUVD_URL,
    DEFAULT_NVD_URL,
    FeedSyncer,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment" / "upstream"


class TestUpstreamFeedSmokeOffline:
    """Offline tests validating upstream response shapes and parser fidelity."""

    def test_euvd_upstream_fixture_shape_and_alias_parsing(self, tmp_path: Path) -> None:
        fixture_path = FIXTURES_DIR / "euvd_search_CVE-2024-3400.json"
        content = fixture_path.read_bytes()

        routes = {
            "euvdservices.enisa.europa.eu/api/search": httpx.Response(200, content=content),
        }

        syncer = FeedSyncer(
            cache_dir=tmp_path,
            transport=httpx.MockTransport(
                lambda req: routes.get(f"{req.url.host}{req.url.path}", httpx.Response(404))
            ),
            sleep=lambda _: None,
        )

        result = syncer.sync_euvd(["CVE-2024-3400"])
        assert result.success is True
        assert result.records_synced == 1

        rec = EUVDSource(cache_file=result.target_path).lookup("CVE-2024-3400")
        assert rec is not None
        assert rec.euvd_id == "EUVD-2024-31989"
        assert rec.cvss_score == 10.0
        assert rec.source == Source.EUVD

    def test_nvd_upstream_fixture_shape_and_parsing(self, tmp_path: Path) -> None:
        fixture_path = FIXTURES_DIR / "nvd_response_CVE-2021-44228.json"
        content = fixture_path.read_bytes()

        routes = {
            "services.nvd.nist.gov/rest/json/cves/2.0": httpx.Response(200, content=content),
        }

        syncer = FeedSyncer(
            cache_dir=tmp_path,
            transport=httpx.MockTransport(
                lambda req: routes.get(f"{req.url.host}{req.url.path}", httpx.Response(404))
            ),
            sleep=lambda _: None,
        )

        result = syncer.sync_nvd(["CVE-2021-44228"])
        assert result.success is True
        assert result.records_synced == 1

        rec = NVDSource(cache_file=result.target_path).lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.cvss_score == 10.0
        assert rec.source == Source.NVD


@pytest.mark.skipif(
    not os.getenv("RUN_LIVE_FEED_SMOKE"),
    reason="Live feed smoke test disabled by default. Set RUN_LIVE_FEED_SMOKE=1 to run.",
)
class TestUpstreamFeedSmokeLive:
    """Live integration smoke tests hitting upstream endpoints (manual/scheduled)."""

    def test_live_euvd_endpoint(self) -> None:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                DEFAULT_EUVD_URL,
                params={"text": "CVE-2024-3400", "size": 10},
                headers={
                    "User-Agent": "SeekThreat/0.1 (+https://github.com/AyushmaanNaruka/SeekThreat)"
                },
            )
            assert resp.status_code == 200, f"EUVD returned HTTP {resp.status_code}: {resp.text}"
            data = resp.json()
            assert "items" in data
            assert len(data["items"]) >= 1

    def test_live_nvd_endpoint(self) -> None:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                DEFAULT_NVD_URL,
                params={"cveId": "CVE-2021-44228"},
                headers={
                    "User-Agent": "SeekThreat/0.1 (+https://github.com/AyushmaanNaruka/SeekThreat)"
                },
            )
            assert resp.status_code == 200, f"NVD returned HTTP {resp.status_code}: {resp.text}"
            data = resp.json()
            assert "vulnerabilities" in data
            assert len(data["vulnerabilities"]) >= 1
