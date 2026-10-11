"""Tests for FeedSyncer — the off-request-path feed download job.

Guards:
- Network is ONLY allowed inside the sync job itself (not on the request path).
- All HTTP goes through an injected ``httpx.MockTransport`` — no real network in CI.
- Upstream shapes come from the labelled real captures in
  ``tests/fixtures/enrichment/upstream/`` (see the README there for URLs and dates).
- Writes are atomic, never shrink a mirror silently, and carry a ``.meta.json`` sidecar.
- Downloads are bounded: User-Agent, size cap, https-only redirects.
- Every sync reports success/failure per source truthfully.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources import (
    CISAKevSource,
    CVEOrgSource,
    EUVDSource,
    ExploitDBSource,
    FirstEPSSSource,
    MetasploitSource,
    NVDSource,
    VulnrichmentSource,
)
from services.enrichment.sources.sync import (
    DEFAULT_CISA_KEV_URL,
    DEFAULT_FIRST_EPSS_URL,
    MIRROR_FILENAMES,
    USER_AGENT,
    FeedSyncer,
    SourceSynchronizer,
    SyncReport,
    SyncResult,
    get_default_cache_dir,
    meta_path,
    mirror_path,
    read_mirror_meta,
    vulnrichment_path,
)

UPSTREAM = Path(__file__).parent.parent / "fixtures" / "enrichment" / "upstream"

Handler = Callable[[httpx.Request], httpx.Response]


def _upstream_bytes(name: str) -> bytes:
    return (UPSTREAM / name).read_bytes()


def _upstream_json(name: str) -> Any:
    return json.loads(_upstream_bytes(name).decode("utf-8"))


def _router(routes: dict[str, Handler | httpx.Response]) -> httpx.MockTransport:
    """Mock transport dispatching on ``host + path``; unknown URLs return 404."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.url.host}{request.url.path}"
        target = routes.get(key)
        if target is None:
            return httpx.Response(404, text="not found")
        if isinstance(target, httpx.Response):
            return target
        return target(request)

    return httpx.MockTransport(handler)


def _syncer(tmp_path: Path, routes: dict[str, Handler | httpx.Response], **kw: Any) -> FeedSyncer:
    kw.setdefault("sleep", lambda _seconds: None)
    return FeedSyncer(cache_dir=tmp_path, transport=_router(routes), **kw)


def _host_path(url: str) -> str:
    parsed = httpx.URL(url)
    return f"{parsed.host}{parsed.path}"


KEV_KEY = _host_path(DEFAULT_CISA_KEV_URL)
EPSS_KEY = _host_path(DEFAULT_FIRST_EPSS_URL)
EXPLOITDB_KEY = "gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
METASPLOIT_KEY = (
    "raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)


def _kev_response() -> httpx.Response:
    return httpx.Response(200, content=_upstream_bytes("cisa_kev_catalog_sample.json"))


def _epss_response() -> httpx.Response:
    return httpx.Response(200, content=gzip.compress(_upstream_bytes("epss_scores_sample.csv")))


# ---------------------------------------------------------------------------
# Shared paths and defaults
# ---------------------------------------------------------------------------


class TestMirrorLayout:
    def test_filenames_are_the_reader_contract(self) -> None:
        assert MIRROR_FILENAMES[Source.KEV] == "cisa_kev.json"
        assert MIRROR_FILENAMES[Source.EPSS] == "epss_v4.json"
        assert MIRROR_FILENAMES[Source.CVE_ORG] == "cve_org.json"
        assert MIRROR_FILENAMES[Source.NVD] == "nvd.json"

    def test_mirror_and_meta_paths(self, tmp_path: Path) -> None:
        assert mirror_path(tmp_path, Source.KEV) == tmp_path / "cisa_kev.json"
        assert meta_path(tmp_path / "cisa_kev.json") == tmp_path / "cisa_kev.meta.json"

    def test_syncer_and_settings_share_one_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from apps.api.core.config import Settings

        monkeypatch.delenv("ENRICHMENT_CACHE_DIR", raising=False)
        settings_default = Settings(_env_file=None).enrichment_cache_dir  # type: ignore[call-arg]
        assert settings_default == get_default_cache_dir()
        assert FeedSyncer().cache_dir == get_default_cache_dir()

    def test_creates_cache_dir(self, tmp_path: Path) -> None:
        cache = tmp_path / "enrichment_cache"
        FeedSyncer(cache_dir=cache)
        assert cache.is_dir()

    def test_vulnrichment_bucket_path(self) -> None:
        assert vulnrichment_path("CVE-2024-3400") == "2024/3xxx/CVE-2024-3400.json"
        assert vulnrichment_path("CVE-2021-44228") == "2021/44xxx/CVE-2021-44228.json"
        assert vulnrichment_path("CVE-2024-0001") == "2024/0xxx/CVE-2024-0001.json"
        assert vulnrichment_path("cve-2023-1234567") == "2023/1234xxx/CVE-2023-1234567.json"


# ---------------------------------------------------------------------------
# Atomic writes, shrink guard, sidecar metadata
# ---------------------------------------------------------------------------


class TestSourceSynchronizerWrites:
    def test_writes_compact_json_and_meta_sidecar(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        data = {"CVE-2021-44228": {"a": 1}, "CVE-2014-0160": {"b": 2}}
        result = sync.sync_from_data(Source.CVE_ORG, data, 2, source_url="https://x.test/a")

        assert result.success is True
        raw = result.target_path.read_bytes()
        assert b"\n" not in raw  # compact, not indented
        meta = read_mirror_meta(result.target_path)
        assert meta is not None
        assert meta["record_count"] == 2
        assert meta["source_url"] == "https://x.test/a"
        assert meta["sha256"] == hashlib.sha256(raw).hexdigest()
        assert datetime.fromisoformat(meta["synced_at"]).tzinfo is not None
        assert result.sha256 == meta["sha256"]

    def test_no_temp_files_left_behind(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        sync.sync_from_data(Source.KEV, {"vulnerabilities": [{}]}, 1)
        names = sorted(p.name for p in tmp_path.iterdir())
        assert names == ["cisa_kev.json", "cisa_kev.meta.json"]

    def test_failed_write_keeps_existing_mirror(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        existing = mirror_path(tmp_path, Source.KEV)
        existing.write_text('{"existing": true}', encoding="utf-8")

        with patch("services.enrichment.sources.sync.json.dump", side_effect=OSError("disk full")):
            result = sync.sync_from_data(Source.KEV, {"vulnerabilities": [{}]}, 1)

        assert result.success is False
        assert "disk full" in (result.error or "")
        assert json.loads(existing.read_text())["existing"] is True
        assert sorted(p.name for p in tmp_path.iterdir()) == ["cisa_kev.json"]

    def test_refuses_empty_overwrite(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        sync.sync_from_data(Source.CVE_ORG, {"CVE-1": {}, "CVE-2": {}}, 2)
        result = sync.sync_from_data(Source.CVE_ORG, {}, 0)

        assert result.success is False
        assert "refusing" in (result.error or "").lower()
        assert len(json.loads(mirror_path(tmp_path, Source.CVE_ORG).read_text())) == 2

    def test_refuses_shrink_below_half(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        big = {f"CVE-2020-{i:04d}": {} for i in range(10)}
        sync.sync_from_data(Source.CVE_ORG, big, 10)
        result = sync.sync_from_data(Source.CVE_ORG, {"CVE-2020-0001": {}}, 4)

        assert result.success is False
        assert "10" in (result.error or "") and "4" in (result.error or "")
        assert read_mirror_meta(mirror_path(tmp_path, Source.CVE_ORG))["record_count"] == 10  # type: ignore[index]

    def test_allows_half_or_more(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        sync.sync_from_data(Source.CVE_ORG, {f"CVE-{i}": {} for i in range(10)}, 10)
        assert sync.sync_from_data(Source.CVE_ORG, {f"CVE-{i}": {} for i in range(5)}, 5).success

    def test_shrink_guard_counts_legacy_mirror_without_meta(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path)
        legacy = {"vulnerabilities": [{"cveID": f"CVE-2020-{i:04d}"} for i in range(10)]}
        mirror_path(tmp_path, Source.KEV).write_text(json.dumps(legacy), encoding="utf-8")
        result = sync.sync_from_data(Source.KEV, {"vulnerabilities": [{}]}, 1)
        assert result.success is False

    def test_allow_shrink_override(self, tmp_path: Path) -> None:
        sync = SourceSynchronizer(cache_dir=tmp_path, allow_shrink=True)
        sync.sync_from_data(Source.CVE_ORG, {f"CVE-{i}": {} for i in range(10)}, 10)
        assert sync.sync_from_data(Source.CVE_ORG, {"CVE-1": {}}, 1).success


# ---------------------------------------------------------------------------
# Download bounds
# ---------------------------------------------------------------------------


class TestDownloadBounds:
    def test_sends_seekthreat_user_agent(self, tmp_path: Path) -> None:
        seen: list[str] = []

        def kev(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers["user-agent"])
            return _kev_response()

        _syncer(tmp_path, {KEV_KEY: kev}).sync_kev()
        assert seen == [USER_AGENT]
        assert USER_AGENT.startswith("SeekThreat-feed-sync/")
        assert "github.com" in USER_AGENT

    def test_aborts_past_size_cap(self, tmp_path: Path) -> None:
        syncer = _syncer(
            tmp_path,
            {KEV_KEY: httpx.Response(200, content=b"x" * 2048)},
            max_bytes={Source.KEV: 1024},
        )
        result = syncer.sync_kev()
        assert result.success is False
        assert "exceeds" in (result.error or "")
        assert not mirror_path(tmp_path, Source.KEV).exists()

    def test_refuses_redirect_to_plain_http(self, tmp_path: Path) -> None:
        redirect = httpx.Response(302, headers={"location": "http://evil.test/kev.json"})
        result = _syncer(tmp_path, {KEV_KEY: redirect}).sync_kev()
        assert result.success is False
        assert "https" in (result.error or "")

    def test_follows_https_redirect(self, tmp_path: Path) -> None:
        redirect = httpx.Response(302, headers={"location": "https://mirror.test/kev.json"})
        routes = {KEV_KEY: redirect, "mirror.test/kev.json": _kev_response()}
        result = _syncer(tmp_path, routes).sync_kev()
        assert result.success is True

    def test_refuses_non_https_feed_url(self, tmp_path: Path) -> None:
        syncer = _syncer(tmp_path, {}, kev_url="http://www.cisa.gov/kev.json")
        result = syncer.sync_kev()
        assert result.success is False
        assert "https" in (result.error or "")

    def test_gzip_decompression_is_bounded(self, tmp_path: Path) -> None:
        bomb = gzip.compress(b"#model_version:v1,score_date:2026-01-01\n" + b"0" * 4096)
        syncer = _syncer(
            tmp_path,
            {EPSS_KEY: httpx.Response(200, content=bomb)},
            max_bytes={Source.EPSS: 1024},
        )
        result = syncer.sync_epss()
        assert result.success is False
        assert "exceeds" in (result.error or "")


# ---------------------------------------------------------------------------
# Full mirrors: KEV, EPSS bulk CSV, ExploitDB, Metasploit
# ---------------------------------------------------------------------------


class TestFullMirrors:
    def test_kev_catalog(self, tmp_path: Path) -> None:
        result = _syncer(tmp_path, {KEV_KEY: _kev_response()}).sync_kev()
        assert result.success is True
        assert result.records_synced == 2
        assert result.source_url == DEFAULT_CISA_KEV_URL
        source = CISAKevSource(cache_file=result.target_path)
        assert source.count() == 2
        assert source.catalog_date is not None

    def test_kev_http_error_is_reported(self, tmp_path: Path) -> None:
        result = _syncer(tmp_path, {KEV_KEY: httpx.Response(503)}).sync_kev()
        assert result.success is False
        assert "503" in (result.error or "")

    def test_epss_bulk_csv(self, tmp_path: Path) -> None:
        result = _syncer(tmp_path, {EPSS_KEY: _epss_response()}).sync_epss()
        assert result.success is True
        assert result.records_synced == 3

        saved = json.loads(result.target_path.read_text())
        assert saved["model_version"] == "v2026.06.15"
        assert saved["score_date"] == "2026-10-10T12:00:23Z"

        source = FirstEPSSSource(cache_file=result.target_path)
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.epss == pytest.approx(0.99999)
        assert rec.percentile == pytest.approx(1.0)
        # Record date is FIRST's score_date, not the sync time.
        assert rec.retrieved_at == datetime(2026, 10, 10, 12, 0, 23, tzinfo=UTC)
        assert rec.date == "2026-10-10T12:00:23Z"

    def test_epss_rejects_csv_without_header(self, tmp_path: Path) -> None:
        bad = gzip.compress(b"cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n")
        result = _syncer(tmp_path, {EPSS_KEY: httpx.Response(200, content=bad)}).sync_epss()
        assert result.success is False
        assert "score_date" in (result.error or "")

    def test_exploitdb_csv(self, tmp_path: Path) -> None:
        content = _upstream_bytes("exploitdb_files_exploits_sample.csv")
        result = _syncer(
            tmp_path, {EXPLOITDB_KEY: httpx.Response(200, content=content)}
        ).sync_exploitdb()
        assert result.success is True
        source = ExploitDBSource(cache_file=result.target_path)
        rec = source.lookup("CVE-2009-3699")
        assert rec is not None
        assert rec.exploit_ids == ["EDB-16929"]

    def test_metasploit_keeps_only_exploit_modules_by_fullname(self, tmp_path: Path) -> None:
        content = _upstream_bytes("metasploit_modules_metadata_sample.json")
        result = _syncer(
            tmp_path, {METASPLOIT_KEY: httpx.Response(200, content=content)}
        ).sync_metasploit()
        assert result.success is True

        saved = json.loads(result.target_path.read_text())
        log4j = saved["CVE-2021-44228"]["module_names"]
        assert log4j == ["exploit/multi/http/log4shell_header_injection"]  # no auxiliary scanner
        for record in saved.values():
            for name in record["module_names"]:
                assert name.startswith("exploit/")
                assert set(record) <= {"cve_id", "module_names", "has_metasploit_module"}

    def test_metasploit_ignores_cve_text_inside_url_references(self, tmp_path: Path) -> None:
        payload = {
            "exploit_x/y": {
                "fullname": "exploit/x/y",
                "type": "exploit",
                "references": ["URL-https://example.test/CVE-2020-1472/poc", "CVE-2019-0708"],
            }
        }
        result = _syncer(
            tmp_path, {METASPLOIT_KEY: httpx.Response(200, json=payload)}
        ).sync_metasploit()
        saved = json.loads(result.target_path.read_text())
        assert set(saved) == {"CVE-2019-0708"}

    def test_metasploit_reader_loads_synced_mirror(self, tmp_path: Path) -> None:
        content = _upstream_bytes("metasploit_modules_metadata_sample.json")
        result = _syncer(
            tmp_path, {METASPLOIT_KEY: httpx.Response(200, content=content)}
        ).sync_metasploit()
        source = MetasploitSource(cache_file=result.target_path)
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        meta = read_mirror_meta(result.target_path)
        assert meta is not None
        # No per-record date upstream: provenance uses the mirror's synced_at.
        assert rec.retrieved_at == datetime.fromisoformat(meta["synced_at"])


# ---------------------------------------------------------------------------
# Targeted per-CVE sync: CVE.org, Vulnrichment, EUVD, NVD
# ---------------------------------------------------------------------------


def _cve_org_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=_upstream_bytes("cve_org_record_CVE-2021-44228.json"))


class TestTargetedSync:
    def test_cve_org_per_id_endpoint_and_merge(self, tmp_path: Path) -> None:
        existing = {"CVE-2014-0160": {"cveMetadata": {"cveId": "CVE-2014-0160"}}}
        mirror_path(tmp_path, Source.CVE_ORG).write_text(json.dumps(existing), encoding="utf-8")

        routes = {"cveawg.mitre.org/api/cve/CVE-2021-44228": _cve_org_handler}
        result = _syncer(tmp_path, routes).sync_cve_org(["cve-2021-44228"])

        assert result.success is True
        saved = json.loads(result.target_path.read_text())
        assert set(saved) == {"CVE-2014-0160", "CVE-2021-44228"}
        rec = CVEOrgSource(cache_file=result.target_path).lookup("CVE-2021-44228")
        assert rec is not None
        # Apache's CNA container carries no CVSS for Log4Shell (only an "other"
        # metric), which is exactly why the fallback chain exists.
        assert rec.cvss_score is None
        assert set(rec.cwe_ids) == {"CWE-502", "CWE-400", "CWE-20"}
        assert rec.retrieved_at == datetime(2025, 10, 21, 23, 25, 23, 121000, tzinfo=UTC)

    def test_invalid_cve_ids_are_never_requested(self, tmp_path: Path) -> None:
        requested: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(str(request.url))
            return httpx.Response(404)

        syncer = FeedSyncer(
            cache_dir=tmp_path, transport=httpx.MockTransport(handler), sleep=lambda _s: None
        )
        result = syncer.sync_cve_org(["../../etc/passwd", "CVE-2021-44228/../x", "not-a-cve"])
        assert requested == []
        assert result.records_synced == 0

    def test_per_cve_error_is_reported_but_successes_are_kept(self, tmp_path: Path) -> None:
        routes: dict[str, Handler | httpx.Response] = {
            "cveawg.mitre.org/api/cve/CVE-2021-44228": _cve_org_handler,
            "cveawg.mitre.org/api/cve/CVE-2014-0160": httpx.Response(500),
        }
        result = _syncer(tmp_path, routes).sync_cve_org(["CVE-2021-44228", "CVE-2014-0160"])
        assert result.success is False
        assert "1 of 2" in (result.error or "")
        assert "CVE-2021-44228" in json.loads(result.target_path.read_text())

    def test_no_cve_ids_is_a_truthful_noop(self, tmp_path: Path) -> None:
        result = _syncer(tmp_path, {}).sync_cve_org([])
        assert result.success is True
        assert result.records_synced == 0
        assert result.note is not None
        assert not result.target_path.exists()

    def test_vulnrichment_per_cve_file(self, tmp_path: Path) -> None:
        content = _upstream_bytes("vulnrichment_record_CVE-2024-3400.json")
        routes: dict[str, Handler | httpx.Response] = {
            "raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/3xxx/CVE-2024-3400.json": (
                httpx.Response(200, content=content)
            ),
        }
        # CVE-1999-0001 has no Vulnrichment file: 404 is "not enriched", not an error.
        result = _syncer(tmp_path, routes).sync_vulnrichment(["CVE-2024-3400", "CVE-1999-0001"])
        assert result.success is True
        assert result.records_synced == 1

        rec = VulnrichmentSource(cache_file=result.target_path).lookup("CVE-2024-3400")
        assert rec is not None
        assert rec.ssvc_options == {
            "Exploitation": "active",
            "Automatable": "yes",
            "Technical Impact": "total",
        }
        assert rec.ssvc_decision is None  # CISA publishes decision points, not a decision
        assert rec.cvss_score is None  # CISA-ADP added no CVSS; the CNA's lives in CVE.org

    def test_euvd_search_filtered_by_alias(self, tmp_path: Path) -> None:
        captured: list[httpx.Request] = []
        content = _upstream_bytes("euvd_search_CVE-2024-3400.json")

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, content=content)

        routes = {"euvdservices.enisa.europa.eu/api/search": handler}
        result = _syncer(tmp_path, routes).sync_euvd(["CVE-2024-3400", "CVE-2021-44228"])

        assert sorted(r.url.params["text"] for r in captured) == ["CVE-2021-44228", "CVE-2024-3400"]
        # The canned response only aliases CVE-2024-3400, so the other CVE is not stored.
        assert result.records_synced == 1
        rec = EUVDSource(cache_file=result.target_path).lookup("CVE-2024-3400")
        assert rec is not None
        assert rec.euvd_id == "EUVD-2024-31989"
        assert rec.cvss_score == 10.0
        assert rec.cvss_version == "3.1"
        assert rec.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert rec.retrieved_at == datetime(2025, 10, 21, 23, 5, 21, tzinfo=UTC)

    def test_nvd_rate_limited_without_key(self, tmp_path: Path) -> None:
        content = _upstream_bytes("nvd_response_CVE-2021-44228.json")
        sleeps: list[float] = []
        seen_keys: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_keys.append(request.headers.get("apikey"))
            return httpx.Response(200, content=content)

        routes = {"services.nvd.nist.gov/rest/json/cves/2.0": handler}
        syncer = _syncer(tmp_path, routes, sleep=sleeps.append)
        result = syncer.sync_nvd(["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"])

        assert result.success is True
        assert seen_keys == [None, None, None]
        assert sleeps == [6.0, 6.0]  # 5 requests / 30 s without an API key
        rec = NVDSource(cache_file=result.target_path).lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.cvss_score == 10.0
        assert rec.confidence == Confidence.HIGH  # NVD-authored Primary metric

    def test_nvd_api_key_header_and_faster_rate(self, tmp_path: Path) -> None:
        content = _upstream_bytes("nvd_response_CVE-2021-44228.json")
        sleeps: list[float] = []
        seen_keys: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_keys.append(request.headers.get("apikey"))
            return httpx.Response(200, content=content)

        routes = {"services.nvd.nist.gov/rest/json/cves/2.0": handler}
        syncer = _syncer(tmp_path, routes, sleep=sleeps.append, nvd_api_key="k")
        syncer.sync_nvd(["CVE-2021-44228", "CVE-2021-45046"])
        assert seen_keys == ["k", "k"]
        assert sleeps == [0.6]

    def test_nvd_rate_limit_403_backoff_and_retry(self, tmp_path: Path) -> None:
        content = _upstream_bytes("nvd_response_CVE-2021-44228.json")
        sleeps: list[float] = []
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(
                    403, text="Request forbidden by administrative rules (rate limit)"
                )
            return httpx.Response(200, content=content)

        routes = {"services.nvd.nist.gov/rest/json/cves/2.0": handler}
        syncer = _syncer(tmp_path, routes, sleep=sleeps.append)
        result = syncer.sync_nvd(["CVE-2021-44228"])

        assert result.success is True
        assert result.records_synced == 1
        assert calls == 2
        assert 6.0 in sleeps
        rec = NVDSource(cache_file=result.target_path).lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.cvss_score == 10.0

    def test_rate_limit_429_with_retry_after_header(self, tmp_path: Path) -> None:
        content = _upstream_bytes("euvd_search_CVE-2024-3400.json")
        sleeps: list[float] = []
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(429, headers={"Retry-After": "15"}, text="Too Many Requests")
            return httpx.Response(200, content=content)

        routes = {"euvdservices.enisa.europa.eu/api/search": handler}
        syncer = _syncer(tmp_path, routes, sleep=sleeps.append)
        result = syncer.sync_euvd(["CVE-2024-3400"])

        assert result.success is True
        assert result.records_synced == 1
        assert calls == 2
        assert 15.0 in sleeps

    def test_rate_limit_retries_exhausted_fails_cleanly(self, tmp_path: Path) -> None:
        sleeps: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="Too Many Requests")

        routes = {"services.nvd.nist.gov/rest/json/cves/2.0": handler}
        syncer = _syncer(tmp_path, routes, sleep=sleeps.append)
        result = syncer.sync_nvd(["CVE-2021-44228"])

        assert result.success is False
        assert result.records_synced == 0
        assert "HTTP 429" in (result.error or "")
        assert len(sleeps) == 3

    def test_sync_cve_records_covers_four_sources(self, tmp_path: Path) -> None:
        results = _syncer(tmp_path, {}).sync_cve_records(["CVE-2021-44228"])
        assert [r.source for r in results] == [
            Source.CVE_ORG,
            Source.VULNRICHMENT,
            Source.EUVD,
            Source.NVD,
        ]


# ---------------------------------------------------------------------------
# sync_all + SyncReport
# ---------------------------------------------------------------------------


class TestSyncAll:
    def _all_routes(self) -> dict[str, Handler | httpx.Response]:
        return {
            KEV_KEY: _kev_response(),
            EPSS_KEY: _epss_response(),
            EXPLOITDB_KEY: httpx.Response(
                200, content=_upstream_bytes("exploitdb_files_exploits_sample.csv")
            ),
            METASPLOIT_KEY: httpx.Response(
                200, content=_upstream_bytes("metasploit_modules_metadata_sample.json")
            ),
            "cveawg.mitre.org/api/cve/CVE-2021-44228": _cve_org_handler,
        }

    def test_syncs_every_source(self, tmp_path: Path) -> None:
        report = _syncer(tmp_path, self._all_routes()).sync_all(cve_ids=["CVE-2021-44228"])
        assert isinstance(report, SyncReport)
        assert {r.source for r in report.results} == {
            Source.KEV,
            Source.EPSS,
            Source.EXPLOITDB,
            Source.METASPLOIT,
            Source.CVE_ORG,
            Source.VULNRICHMENT,
            Source.EUVD,
            Source.NVD,
        }
        assert report.ok is True
        assert report.failed == []

    def test_partial_failure_is_reported_and_others_continue(self, tmp_path: Path) -> None:
        routes = self._all_routes()
        routes[KEV_KEY] = httpx.Response(500)
        report = _syncer(tmp_path, routes).sync_all(cve_ids=[])
        assert report.ok is False
        assert [r.source for r in report.failed] == [Source.KEV]
        assert mirror_path(tmp_path, Source.EPSS).exists()

    def test_sources_filter(self, tmp_path: Path) -> None:
        report = _syncer(tmp_path, self._all_routes()).sync_all(sources=["kev", "epss"])
        assert [r.source for r in report.results] == [Source.KEV, Source.EPSS]

    def test_summary_shape(self, tmp_path: Path) -> None:
        report = SyncReport(
            results=[
                SyncResult(Source.KEV, True, 3, tmp_path / "k.json"),
                SyncResult(Source.EPSS, False, 0, tmp_path / "e.json", error="boom"),
            ]
        )
        summary = report.to_summary()
        assert summary["ok"] is False
        assert summary["succeeded"] == ["kev"]
        assert summary["failed"] == ["epss"]
        assert summary["sources"]["epss"]["error"] == "boom"


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------


def _report(ok: bool, tmp_path: Path) -> SyncReport:
    return SyncReport(
        results=[
            SyncResult(Source.KEV, True, 10, tmp_path / "cisa_kev.json"),
            SyncResult(
                Source.EPSS,
                ok,
                20 if ok else 0,
                tmp_path / "epss_v4.json",
                error=None if ok else "connection timeout",
            ),
        ]
    )


class TestSyncFeedsCeleryTask:
    def setup_method(self) -> None:
        from apps.api.core.audit import clear_audit_log

        clear_audit_log()

    def test_scheduled_task_syncs_everything_with_known_cves(self, tmp_path: Path) -> None:
        task_module = importlib.import_module("apps.api.tasks.sync_feeds")

        with (
            patch.object(task_module, "_known_cve_ids", return_value=["CVE-2021-44228"]),
            patch.object(FeedSyncer, "sync_all", return_value=_report(True, tmp_path)) as m_all,
        ):
            summary = task_module.sync_feeds()

        assert m_all.call_args.kwargs["cve_ids"] == ["CVE-2021-44228"]
        assert m_all.call_args.kwargs.get("sources") is None
        assert summary["ok"] is True
        assert summary["sources"]["kev"]["records"] == 10

    def test_success_writes_system_audit_event(self, tmp_path: Path) -> None:
        from apps.api.core.audit import get_audit_log

        task_module = importlib.import_module("apps.api.tasks.sync_feeds")

        with (
            patch.object(task_module, "_known_cve_ids", return_value=[]),
            patch.object(FeedSyncer, "sync_all", return_value=_report(True, tmp_path)),
        ):
            task_module.sync_feeds()

        events = [e for e in get_audit_log() if e["event"].startswith("feed_sync.")]
        assert len(events) == 1
        assert events[0]["event"] == "feed_sync.completed"
        assert events[0]["actor"] == "system:celery_beat"
        assert events[0]["status"] == "success"

    def test_failure_is_audited_and_raised(self, tmp_path: Path) -> None:
        from celery.exceptions import MaxRetriesExceededError

        from apps.api.core.audit import get_audit_log

        task_module = importlib.import_module("apps.api.tasks.sync_feeds")

        with (
            patch.object(task_module, "_known_cve_ids", return_value=[]),
            patch.object(FeedSyncer, "sync_all", return_value=_report(False, tmp_path)),
            patch.object(
                task_module.sync_feeds, "retry", side_effect=MaxRetriesExceededError("exhausted")
            ),
            pytest.raises(task_module.FeedSyncError, match="epss"),
        ):
            task_module.sync_feeds()

        events = [e for e in get_audit_log() if e["event"] == "feed_sync.failed"]
        assert len(events) == 1
        assert events[0]["actor"] == "system:celery_beat"
        assert events[0]["details"]["failed"] == ["epss"]

    def test_failure_retries_only_failed_sources(self, tmp_path: Path) -> None:
        from celery.exceptions import Retry

        task_module = importlib.import_module("apps.api.tasks.sync_feeds")

        retry = MagicMock(side_effect=Retry("retrying"))
        with (
            patch.object(task_module, "_known_cve_ids", return_value=[]),
            patch.object(FeedSyncer, "sync_all", return_value=_report(False, tmp_path)),
            patch.object(task_module.sync_feeds, "retry", retry),
            pytest.raises(Retry),
        ):
            task_module.sync_feeds()

        assert retry.call_args.kwargs["kwargs"]["sources"] == ["epss"]

    def test_known_cve_ids_reads_enriched_findings(self) -> None:
        from datetime import timedelta

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        from apps.api.db.base import Base
        from apps.api.db.models import EnrichedFindingModel
        from apps.api.db.repositories import EngagementRepository
        from apps.api.tasks.sync_feeds import _known_cve_ids
        from packages.schema.models.engagement import Authorization, Engagement
        from packages.schema.models.finding import EnrichedFinding, Finding

        now = datetime(2026, 10, 1, tzinfo=UTC)
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        session = sessionmaker(bind=engine)()
        EngagementRepository(session).save(
            Engagement(
                engagement_id="eng-1",
                name="lab",
                authorization=Authorization(
                    engagement_id="eng-1",
                    authorized_by="tester",
                    allowlist=("172.20.0.0/16",),
                    granted_at=now - timedelta(hours=1),
                    expires_at=now + timedelta(days=1),
                ),
                created_at=now,
            )
        )
        for fid, cves in (
            ("f1", ["CVE-2021-44228", "cve-2014-0160"]),
            ("f2", []),
            ("f3", ["CVE-2021-44228"]),
        ):
            finding = Finding(
                finding_id=fid,
                engagement_id="eng-1",
                asset_id="a",
                scanner="nmap",
                cve_ids=cves,
                title="t",
                observation_ids=["o"],
                detected_at=now,
            )
            session.add(
                EnrichedFindingModel.from_schema(EnrichedFinding(finding=finding, fields={}))
            )
        session.commit()

        assert _known_cve_ids(session) == ["CVE-2014-0160", "CVE-2021-44228"]
        session.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestSyncFeedsCLI:
    def setup_method(self) -> None:
        from apps.api.core.audit import clear_audit_log

        clear_audit_log()

    def test_cli_all_success_audits_as_system_cli(self, tmp_path: Path) -> None:
        from apps.api.core.audit import get_audit_log
        from services.enrichment.sync_feeds import main

        with patch.object(FeedSyncer, "sync_all", return_value=_report(True, tmp_path)) as m_all:
            exit_code = main(["--cache-dir", str(tmp_path), "--cve", "CVE-2021-44228"])

        assert exit_code == 0
        assert m_all.call_args.kwargs["cve_ids"] == ["CVE-2021-44228"]
        events = [e for e in get_audit_log() if e["event"].startswith("feed_sync.")]
        assert events[-1]["actor"] == "system:cli"

    def test_cli_failure_exit_code(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        with patch.object(FeedSyncer, "sync_all", return_value=_report(False, tmp_path)):
            assert main(["--cache-dir", str(tmp_path)]) == 1

    def test_cli_single_source(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        with patch.object(FeedSyncer, "sync_all", return_value=_report(True, tmp_path)) as m_all:
            main(["--source", "epss", "--cache-dir", str(tmp_path)])
        assert m_all.call_args.kwargs["sources"] == ["epss"]
