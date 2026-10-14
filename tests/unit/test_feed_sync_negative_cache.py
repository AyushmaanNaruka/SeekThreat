"""Targeted sync bookkeeping: per-source gaps, upstream not-found entries, time budget.

- A CVE known to one per-CVE mirror is still missing from the others; each source is
  synced only for its own gaps.
- An upstream 404 (or no exact match) is recorded in ``<name>.notfound.json`` with
  ``checked_at`` and is not fetched again until the TTL passes. The mirror file the
  readers parse keeps its format.
- A time budget stops new lookups once spent, so one huge scan cannot hold the
  enrichment worker indefinitely; the remainder is reported as deferred.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from packages.schema.models.provenance import Source
from services.enrichment.sources import CVEOrgSource
from services.enrichment.sources.sync import (
    NOT_FOUND_TTL_SECONDS,
    TARGETED_SOURCES,
    FeedSyncer,
    mirror_path,
    missing_cve_ids_by_source,
    not_found_path,
    read_not_found,
)


def _cve_org_handler(found: set[str], requested: list[str]):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        cve = request.url.path.rsplit("/", 1)[-1]
        requested.append(cve)
        if cve in found:
            return httpx.Response(200, json={"cveMetadata": {"cveId": cve}, "containers": {}})
        return httpx.Response(404)

    return handler


def _syncer(tmp_path: Path, handler, **kw) -> FeedSyncer:  # type: ignore[no-untyped-def]
    return FeedSyncer(
        cache_dir=tmp_path, transport=httpx.MockTransport(handler), sleep=lambda _s: None, **kw
    )


class TestNotFoundEntries:
    def test_upstream_404_is_recorded_with_checked_at(self, tmp_path: Path) -> None:
        requested: list[str] = []
        result = _syncer(tmp_path, _cve_org_handler(set(), requested)).sync_cve_org(
            ["CVE-2099-0001"]
        )
        assert result.success is True
        sidecar = not_found_path(mirror_path(tmp_path, Source.CVE_ORG))
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        assert set(data) == {"CVE-2099-0001"}
        checked = datetime.fromisoformat(data["CVE-2099-0001"]["checked_at"])
        assert abs((datetime.now(UTC) - checked).total_seconds()) < 60
        # The mirror itself is untouched (nothing was found).
        assert not mirror_path(tmp_path, Source.CVE_ORG).exists()

    def test_recent_not_found_is_not_refetched(self, tmp_path: Path) -> None:
        requested: list[str] = []
        handler = _cve_org_handler(set(), requested)
        _syncer(tmp_path, handler).sync_cve_org(["CVE-2099-0001"])
        assert requested == ["CVE-2099-0001"]

        result = _syncer(tmp_path, handler).sync_cve_org(["CVE-2099-0001"])
        assert requested == ["CVE-2099-0001"], "re-fetched a CVE recorded as not found"
        assert result.success is True
        assert "skipped" in (result.note or "")

    def test_expired_not_found_is_refetched(self, tmp_path: Path) -> None:
        sidecar = not_found_path(mirror_path(tmp_path, Source.CVE_ORG))
        old = datetime.now(UTC) - timedelta(seconds=NOT_FOUND_TTL_SECONDS + 60)
        sidecar.write_text(
            json.dumps({"CVE-2099-0001": {"checked_at": old.isoformat()}}), encoding="utf-8"
        )
        requested: list[str] = []
        _syncer(tmp_path, _cve_org_handler({"CVE-2099-0001"}, requested)).sync_cve_org(
            ["CVE-2099-0001"]
        )
        assert requested == ["CVE-2099-0001"]
        # Found now: the negative entry is dropped and the mirror holds the record.
        assert "CVE-2099-0001" not in read_not_found(mirror_path(tmp_path, Source.CVE_ORG))
        assert "CVE-2099-0001" in json.loads(
            mirror_path(tmp_path, Source.CVE_ORG).read_text(encoding="utf-8")
        )

    def test_reader_ignores_not_found_sidecar(self, tmp_path: Path) -> None:
        requested: list[str] = []
        _syncer(tmp_path, _cve_org_handler({"CVE-2021-44228"}, requested)).sync_cve_org(
            ["CVE-2021-44228", "CVE-2099-0001"]
        )
        src = CVEOrgSource(cache_file=mirror_path(tmp_path, Source.CVE_ORG))
        assert src.count() == 1
        assert src.lookup("CVE-2099-0001") is None


class TestMissingBySource:
    def test_known_to_one_mirror_is_still_missing_from_others(self, tmp_path: Path) -> None:
        mirror_path(tmp_path, Source.CVE_ORG).write_text(
            json.dumps({"CVE-2021-44228": {}}), encoding="utf-8"
        )
        missing = missing_cve_ids_by_source(tmp_path, ["CVE-2021-44228", "CVE-2024-3400"])
        assert set(missing) == set(TARGETED_SOURCES)
        assert missing["cve_org"] == ["CVE-2024-3400"]
        for name in ("vulnrichment", "euvd", "nvd"):
            assert missing[name] == ["CVE-2021-44228", "CVE-2024-3400"]

    def test_fresh_not_found_entries_are_not_missing(self, tmp_path: Path) -> None:
        sidecar = not_found_path(mirror_path(tmp_path, Source.VULNRICHMENT))
        sidecar.write_text(
            json.dumps({"CVE-2024-3400": {"checked_at": datetime.now(UTC).isoformat()}}),
            encoding="utf-8",
        )
        missing = missing_cve_ids_by_source(tmp_path, ["CVE-2024-3400"])
        assert missing["vulnrichment"] == []
        assert missing["nvd"] == ["CVE-2024-3400"]

    def test_corrupt_mirror_means_everything_missing(self, tmp_path: Path) -> None:
        mirror_path(tmp_path, Source.NVD).write_text("not json", encoding="utf-8")
        assert missing_cve_ids_by_source(tmp_path, ["CVE-2024-3400"])["nvd"] == ["CVE-2024-3400"]

    def test_sync_missing_runs_each_source_only_for_its_gaps(self, tmp_path: Path) -> None:
        seen: dict[str, list[str]] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.setdefault(request.url.host, []).append(str(request.url))
            return httpx.Response(404)

        results = _syncer(tmp_path, handler).sync_missing_cve_records(
            {"cve_org": [], "nvd": ["CVE-2024-3400"], "euvd": []}
        )
        assert [r.key for r in results] == ["nvd"]
        assert set(seen) == {"services.nvd.nist.gov"}


class TestTimeBudget:
    def test_lookups_stop_once_the_budget_is_spent(self, tmp_path: Path) -> None:
        clock = iter([0.0, 0.0, 0.0, 100.0, 100.0, 100.0, 100.0])
        requested: list[str] = []
        syncer = _syncer(
            tmp_path,
            _cve_org_handler({"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"}, requested),
            time_budget_seconds=10.0,
            clock=lambda: next(clock),
        )
        result = syncer.sync_cve_org(["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"])
        assert requested == ["CVE-2021-0001", "CVE-2021-0002"]
        assert result.success is True
        assert result.cve_ids_synced == ("CVE-2021-0001", "CVE-2021-0002")
        assert "1 deferred" in (result.note or "")

    def test_cve_ids_synced_lists_only_new_records(self, tmp_path: Path) -> None:
        requested: list[str] = []
        result = _syncer(tmp_path, _cve_org_handler({"CVE-2021-44228"}, requested)).sync_cve_org(
            ["CVE-2021-44228", "CVE-2099-0001"]
        )
        assert result.cve_ids_synced == ("CVE-2021-44228",)
