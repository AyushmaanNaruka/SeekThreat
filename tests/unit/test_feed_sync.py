"""Tests for FeedSyncer — off-request-path feed download job.

Guards:
- Network is ONLY allowed inside the sync job itself (not on the request path).
- test_offline_mirror.py must keep passing; these tests do not touch EnrichmentService.
- All HTTP calls are mocked — no real network in CI.
- Atomic write: a failed download must not corrupt an existing mirror.
- Each sync returns a SyncResult with correct metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from packages.schema.models.provenance import Source
from services.enrichment.sources.sync import (
    MIRROR_FILENAMES,
    FeedSyncer,
    SyncResult,
    mirror_path,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MINIMAL_KEV_PAYLOAD: dict[str, Any] = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.09.20",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 JNDI RCE.",
            "requiredAction": "Apply updates.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        }
    ],
}

_MINIMAL_EPSS_PAYLOAD: dict[str, Any] = {
    "status": "OK",
    "status-code": 200,
    "version": "v4",
    "total": 1,
    "data": [{"cve": "CVE-2021-44228", "epss": "0.97543", "percentile": "0.99980"}],
}

_MINIMAL_CVE_ORG_PAYLOAD: dict[str, Any] = {
    "CVE-2021-44228": {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Log4Shell RCE."}],
                "metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}],
            }
        },
    }
}


def _make_mock_response(payload: dict[str, Any], status_code: int = 200) -> MagicMock:
    """Build a mock httpx.Response that behaves like a successful JSON response."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = payload
    mock_resp.content = json.dumps(payload).encode()
    return mock_resp


# ---------------------------------------------------------------------------
# MIRROR_FILENAMES sanity checks
# ---------------------------------------------------------------------------


class TestMirrorFilenames:
    """MIRROR_FILENAMES is the shared contract: FeedSyncer writes, FusionEngine reads."""

    def test_kev_filename(self) -> None:
        assert MIRROR_FILENAMES[Source.KEV] == "cisa_kev.json"

    def test_epss_filename(self) -> None:
        assert MIRROR_FILENAMES[Source.EPSS] == "epss_v4.json"

    def test_cve_org_filename(self) -> None:
        assert MIRROR_FILENAMES[Source.CVE_ORG] == "cve_org.json"

    def test_mirror_path_helper(self, tmp_path: Path) -> None:
        p = mirror_path(tmp_path, Source.KEV)
        assert p == tmp_path / "cisa_kev.json"


# ---------------------------------------------------------------------------
# FeedSyncer initialisation
# ---------------------------------------------------------------------------


class TestFeedSyncerInit:
    def test_creates_cache_dir(self, tmp_path: Path) -> None:
        cache = tmp_path / "enrichment_cache"
        assert not cache.exists()
        FeedSyncer(cache_dir=cache)
        assert cache.is_dir()

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=str(tmp_path))
        assert syncer.cache_dir == tmp_path

    def test_default_cache_dir_is_set(self) -> None:
        syncer = FeedSyncer()
        assert syncer.cache_dir is not None
        assert isinstance(syncer.cache_dir, Path)


# ---------------------------------------------------------------------------
# sync_kev
# ---------------------------------------------------------------------------


class TestSyncKev:
    def test_sync_kev_writes_mirror_file(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        mock_resp = _make_mock_response(_MINIMAL_KEV_PAYLOAD)

        with patch(
            "services.enrichment.sources.sync.httpx.get", return_value=mock_resp
        ) as mock_get:
            result = syncer.sync_kev()

        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert "cisa.gov" in call_url or "cisa" in call_url.lower()

        assert result.success is True
        assert result.source == Source.KEV
        assert result.records_synced == 1
        assert result.target_path == tmp_path / MIRROR_FILENAMES[Source.KEV]
        assert result.error is None
        assert result.target_path.exists()
        saved = json.loads(result.target_path.read_text())
        assert saved["count"] == 1

    def test_sync_kev_returns_failure_on_http_error(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            side_effect=Exception("connection refused"),
        ):
            result = syncer.sync_kev()

        assert result.success is False
        assert result.source == Source.KEV
        assert result.error is not None
        assert "connection refused" in result.error

    def test_sync_kev_does_not_corrupt_existing_mirror_on_failure(self, tmp_path: Path) -> None:
        """Atomic write: failure during download must leave the existing mirror intact."""
        syncer = FeedSyncer(cache_dir=tmp_path)
        existing = tmp_path / MIRROR_FILENAMES[Source.KEV]
        existing.write_text('{"existing": true}', encoding="utf-8")

        with patch(
            "services.enrichment.sources.sync.httpx.get",
            side_effect=Exception("timeout"),
        ):
            result = syncer.sync_kev()

        assert result.success is False
        # Original file must be untouched
        assert existing.exists()
        assert json.loads(existing.read_text())["existing"] is True
        # No temp file left behind
        assert not (tmp_path / MIRROR_FILENAMES[Source.KEV]).with_suffix(".tmp").exists()


# ---------------------------------------------------------------------------
# sync_epss
# ---------------------------------------------------------------------------


class TestSyncEpss:
    def test_sync_epss_writes_mirror_file(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        mock_resp = _make_mock_response(_MINIMAL_EPSS_PAYLOAD)

        with patch(
            "services.enrichment.sources.sync.httpx.get", return_value=mock_resp
        ) as mock_get:
            result = syncer.sync_epss()

        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert "first.org" in call_url or "epss" in call_url.lower()

        assert result.success is True
        assert result.source == Source.EPSS
        assert result.records_synced == 1
        assert result.target_path == tmp_path / MIRROR_FILENAMES[Source.EPSS]

    def test_sync_epss_failure_on_network_error(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            side_effect=Exception("timeout"),
        ):
            result = syncer.sync_epss()

        assert result.success is False
        assert result.source == Source.EPSS
        assert result.error is not None


# ---------------------------------------------------------------------------
# sync_cve_org
# ---------------------------------------------------------------------------


class TestSyncCveOrg:
    def test_sync_cve_org_writes_mirror_file(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        mock_resp = _make_mock_response(_MINIMAL_CVE_ORG_PAYLOAD)

        with patch(
            "services.enrichment.sources.sync.httpx.get", return_value=mock_resp
        ) as mock_get:
            result = syncer.sync_cve_org()

        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert "cve.org" in call_url or "cveawg" in call_url or "cvelistV5" in call_url

        assert result.success is True
        assert result.source == Source.CVE_ORG
        assert result.target_path == tmp_path / MIRROR_FILENAMES[Source.CVE_ORG]

    def test_sync_cve_org_failure(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            side_effect=Exception("dns error"),
        ):
            result = syncer.sync_cve_org()

        assert result.success is False
        assert result.source == Source.CVE_ORG


# ---------------------------------------------------------------------------
# sync_all
# ---------------------------------------------------------------------------


class TestSyncAll:
    def test_sync_all_returns_three_results(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)

        def _side_effect(url: str, **kwargs: object) -> MagicMock:
            if "cisa.gov" in url or "kev" in url.lower():
                return _make_mock_response(_MINIMAL_KEV_PAYLOAD)
            if "first.org" in url or "epss" in url.lower():
                return _make_mock_response(_MINIMAL_EPSS_PAYLOAD)
            return _make_mock_response(_MINIMAL_CVE_ORG_PAYLOAD)

        with patch("services.enrichment.sources.sync.httpx.get", side_effect=_side_effect):
            results = syncer.sync_all()

        assert len(results) == 3
        sources = {r.source for r in results}
        assert Source.KEV in sources
        assert Source.EPSS in sources
        assert Source.CVE_ORG in sources

    def test_sync_all_partial_failure_does_not_abort(self, tmp_path: Path) -> None:
        """sync_all continues even if one source fails."""
        syncer = FeedSyncer(cache_dir=tmp_path)
        call_count = 0

        def _side_effect(url: str, **kwargs: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("first source failed")
            return _make_mock_response(_MINIMAL_EPSS_PAYLOAD)

        with patch("services.enrichment.sources.sync.httpx.get", side_effect=_side_effect):
            results = syncer.sync_all()

        assert len(results) == 3
        failures = [r for r in results if not r.success]
        successes = [r for r in results if r.success]
        assert len(failures) >= 1
        assert len(successes) >= 1

    def test_sync_all_result_types(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response(_MINIMAL_KEV_PAYLOAD),
        ):
            results = syncer.sync_all()

        for r in results:
            assert isinstance(r, SyncResult)
            assert r.synced_at is not None


# ---------------------------------------------------------------------------
# SyncResult metadata
# ---------------------------------------------------------------------------


class TestSyncResultMetadata:
    def test_successful_result_has_no_error(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response(_MINIMAL_KEV_PAYLOAD),
        ):
            result = syncer.sync_kev()

        assert result.success is True
        assert result.error is None
        assert result.synced_at is not None

    def test_failed_result_has_error_text(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            side_effect=Exception("some error"),
        ):
            result = syncer.sync_kev()

        assert result.success is False
        assert result.records_synced == 0
        assert "some error" in (result.error or "")


# ---------------------------------------------------------------------------
# Celery Task & CLI
# ---------------------------------------------------------------------------


class TestSyncFeedsCeleryTask:
    def test_celery_task_success(self, tmp_path: Path) -> None:
        from apps.api.tasks.sync_feeds import sync_feeds

        mock_results = [
            SyncResult(
                source=Source.KEV,
                target_path=tmp_path / "cisa_kev.json",
                records_synced=10,
                success=True,
            ),
            SyncResult(
                source=Source.EPSS,
                target_path=tmp_path / "epss_v4.json",
                records_synced=20,
                success=True,
            ),
        ]
        with patch.object(FeedSyncer, "sync_all", return_value=mock_results):
            summary = sync_feeds()

        assert summary[Source.KEV.value]["success"] is True
        assert summary[Source.KEV.value]["records"] == 10
        assert summary[Source.EPSS.value]["success"] is True
        assert summary[Source.EPSS.value]["records"] == 20

    def test_celery_task_partial_failure_summary(self, tmp_path: Path) -> None:
        from apps.api.tasks.sync_feeds import sync_feeds

        mock_results = [
            SyncResult(
                source=Source.KEV,
                target_path=tmp_path / "cisa_kev.json",
                records_synced=0,
                success=False,
                error="connection timeout",
            )
        ]
        with patch.object(FeedSyncer, "sync_all", return_value=mock_results):
            summary = sync_feeds()

        assert summary[Source.KEV.value]["success"] is False
        assert summary[Source.KEV.value]["error"] == "connection timeout"

    def test_celery_task_max_retries_exceeded(self) -> None:
        from celery.exceptions import MaxRetriesExceededError

        from apps.api.tasks.sync_feeds import sync_feeds

        with (
            patch.object(
                sync_feeds,
                "retry",
                side_effect=MaxRetriesExceededError("retries exhausted"),
            ),
            patch.object(FeedSyncer, "sync_all", side_effect=RuntimeError("disk full")),
        ):
            result = sync_feeds()

        assert "disk full" in result["error"]


class TestSyncFeedsCLI:
    def test_cli_all_success(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        mock_result = SyncResult(
            source=Source.KEV,
            target_path=tmp_path / "cisa_kev.json",
            records_synced=5,
            success=True,
        )
        with patch.object(FeedSyncer, "sync_all", return_value=[mock_result]):
            exit_code = main(["--source", "all", "--cache-dir", str(tmp_path)])

        assert exit_code == 0

    def test_cli_single_source_failure(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        mock_result = SyncResult(
            source=Source.KEV,
            target_path=tmp_path / "cisa_kev.json",
            records_synced=0,
            success=False,
            error="timed out",
        )
        with patch.object(FeedSyncer, "sync_kev", return_value=mock_result):
            exit_code = main(["--source", "kev", "--cache-dir", str(tmp_path)])

        assert exit_code == 1

    def test_cli_individual_sources_invoked(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        mock_res = SyncResult(
            source=Source.EPSS,
            target_path=tmp_path / "epss_v4.json",
            records_synced=1,
            success=True,
        )
        with patch.object(FeedSyncer, "sync_epss", return_value=mock_res) as m_epss:
            exit_code = main(["--source", "epss", "--cache-dir", str(tmp_path)])
            assert exit_code == 0
            m_epss.assert_called_once()

        mock_cve = SyncResult(
            source=Source.CVE_ORG,
            target_path=tmp_path / "cve_org.json",
            records_synced=1,
            success=True,
        )
        with patch.object(FeedSyncer, "sync_cve_org", return_value=mock_cve) as m_cve:
            exit_code = main(["--source", "cve_org", "--cache-dir", str(tmp_path)])
            assert exit_code == 0
            m_cve.assert_called_once()

    def test_cli_secondary_sources_invoked(self, tmp_path: Path) -> None:
        from services.enrichment.sync_feeds import main

        for src_name, method_name, src_enum in [
            ("vulnrichment", "sync_vulnrichment", Source.VULNRICHMENT),
            ("euvd", "sync_euvd", Source.EUVD),
            ("exploitdb", "sync_exploitdb", Source.EXPLOITDB),
            ("metasploit", "sync_metasploit", Source.METASPLOIT),
        ]:
            mock_res = SyncResult(
                source=src_enum,
                target_path=tmp_path / f"{src_name}.json",
                records_synced=1,
                success=True,
            )
            with patch.object(FeedSyncer, method_name, return_value=mock_res) as m_sync:
                exit_code = main(["--source", src_name, "--cache-dir", str(tmp_path)])
                assert exit_code == 0
                m_sync.assert_called_once()


class TestSyncSecondaryFeeds:
    """Tests for syncing secondary threat intelligence sources."""

    def test_sync_vulnrichment(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        payload = {"CVE-2025-0001": {"cveId": "CVE-2025-0001", "cvss_score": 8.1}}
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response(payload),
        ):
            res = syncer.sync_vulnrichment()

        assert res.success is True
        assert res.source == Source.VULNRICHMENT
        assert res.records_synced == 1
        assert res.target_path.exists()

    def test_sync_euvd(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        payload = [{"cve_id": "CVE-2025-0002", "cvss_score": 6.5}]
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response(payload),
        ):
            res = syncer.sync_euvd()

        assert res.success is True
        assert res.source == Source.EUVD
        assert res.records_synced == 1
        assert res.target_path.exists()

    def test_sync_exploitdb_csv_parsing(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        csv_text = (
            "id,file,description,date_published,author,type,platform,"
            "port,date_added,date_updated,verified,codes\n"
            "50592,exploits/multiple/remote/50592.py,Log4j RCE,2021-12-15,author,"
            "remote,all,0,2021-12-15,2021-12-16,1,CVE-2021-44228\n"
        )
        mock_resp = MagicMock()
        mock_resp.text = csv_text
        mock_resp.raise_for_status = MagicMock()

        with patch("services.enrichment.sources.sync.httpx.get", return_value=mock_resp):
            res = syncer.sync_exploitdb()

        assert res.success is True
        assert res.source == Source.EXPLOITDB
        assert res.records_synced == 1
        saved = json.loads(res.target_path.read_text())
        assert "CVE-2021-44228" in saved
        assert saved["CVE-2021-44228"]["exploit_ids"] == ["EDB-50592"]

    def test_sync_metasploit_metadata_parsing(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        payload = {
            "exploit/multi/http/log4shell_header_injection": {
                "name": "Log4Shell Header Injection",
                "references": ["CVE-2021-44228"],
            }
        }
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response(payload),
        ):
            res = syncer.sync_metasploit()

        assert res.success is True
        assert res.source == Source.METASPLOIT
        assert res.records_synced == 1
        saved = json.loads(res.target_path.read_text())
        assert "CVE-2021-44228" in saved
        assert saved["CVE-2021-44228"]["module_names"] == [
            "exploit/multi/http/log4shell_header_injection"
        ]

    def test_sync_all_include_secondary_returns_seven_results(self, tmp_path: Path) -> None:
        syncer = FeedSyncer(cache_dir=tmp_path)
        with patch(
            "services.enrichment.sources.sync.httpx.get",
            return_value=_make_mock_response({"CVE-2021-44228": {}}),
        ):
            results = syncer.sync_all(include_secondary=True)

        assert len(results) == 7
        sources = {r.source for r in results}
        assert Source.KEV in sources
        assert Source.EPSS in sources
        assert Source.CVE_ORG in sources
        assert Source.VULNRICHMENT in sources
        assert Source.EUVD in sources
        assert Source.EXPLOITDB in sources
        assert Source.METASPLOIT in sources

