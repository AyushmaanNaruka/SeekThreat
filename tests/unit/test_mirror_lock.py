"""Per-mirror exclusive lock and the targeted-sync read-merge-write it protects.

Post-scan tasks and the 02:00 beat sync can run at the same time (and the CLI can
run beside either), each doing read-merge-write on the same per-CVE mirror file.
Without a lock the later writer drops the earlier writer's additions.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from packages.schema.models.provenance import Source
from services.enrichment.sources.locking import (
    MirrorLock,
    MirrorLockTimeout,
    lock_path_for,
)
from services.enrichment.sources.sync import FeedSyncer, mirror_path


class TestMirrorLock:
    def test_lock_file_holds_owner_and_is_removed_on_release(self, tmp_path: Path) -> None:
        target = tmp_path / "cve_org.json"
        lock_file = lock_path_for(target)
        with MirrorLock(target):
            assert lock_file.exists()
            owner = json.loads(lock_file.read_text(encoding="utf-8"))
            assert owner["pid"] == os.getpid()
            assert owner["host"] == socket.gethostname()
            assert owner["token"]
        assert not lock_file.exists()

    def test_released_even_when_the_body_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "nvd.json"
        with pytest.raises(RuntimeError), MirrorLock(target):
            raise RuntimeError("boom")
        assert not lock_path_for(target).exists()

    def test_second_holder_waits_then_times_out(self, tmp_path: Path) -> None:
        target = tmp_path / "euvd.json"
        with MirrorLock(target):
            started = time.monotonic()
            with pytest.raises(MirrorLockTimeout), MirrorLock(target, timeout=0.3):
                pass
            assert time.monotonic() - started >= 0.3
        # The timed-out waiter must not have removed the holder's lock.
        assert not lock_path_for(target).exists()

    def test_stale_lock_is_broken(self, tmp_path: Path) -> None:
        target = tmp_path / "vulnrichment.json"
        lock_file = lock_path_for(target)
        lock_file.write_text(
            json.dumps({"pid": 999999, "host": "other-container", "token": "dead"}),
            encoding="utf-8",
        )
        old = time.time() - 3600
        os.utime(lock_file, (old, old))

        with MirrorLock(target, stale_after=60, timeout=2):
            owner = json.loads(lock_file.read_text(encoding="utf-8"))
            assert owner["token"] != "dead"
        assert not lock_file.exists()

    def test_fresh_foreign_lock_is_not_broken(self, tmp_path: Path) -> None:
        target = tmp_path / "vulnrichment.json"
        lock_file = lock_path_for(target)
        lock_file.write_text(
            json.dumps({"pid": 1, "host": "other-container", "token": "alive"}),
            encoding="utf-8",
        )
        with pytest.raises(MirrorLockTimeout), MirrorLock(target, stale_after=600, timeout=0.2):
            pass
        assert json.loads(lock_file.read_text(encoding="utf-8"))["token"] == "alive"

    def test_release_does_not_remove_a_lock_someone_else_now_holds(self, tmp_path: Path) -> None:
        target = tmp_path / "cve_org.json"
        lock_file = lock_path_for(target)
        lock = MirrorLock(target)
        lock.acquire()
        # Simulate our lock having been broken as stale and re-taken by another holder.
        lock_file.write_text(json.dumps({"pid": 1, "host": "x", "token": "other"}), "utf-8")
        lock.release()
        assert lock_file.exists()

    def test_mutual_exclusion_between_threads(self, tmp_path: Path) -> None:
        target = tmp_path / "nvd.json"
        inside = 0
        overlap = False
        guard = threading.Lock()

        def worker() -> None:
            nonlocal inside, overlap
            for _ in range(5):
                with MirrorLock(target, timeout=10):
                    with guard:
                        inside += 1
                        if inside > 1:
                            overlap = True
                    time.sleep(0.005)
                    with guard:
                        inside -= 1

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert overlap is False


class TestConcurrentTargetedMerges:
    def test_two_interleaved_merges_both_survive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both syncers fetch, then merge at once; neither addition is lost."""
        both_fetched = threading.Barrier(2)
        original_read = FeedSyncer._existing_mirror

        def slow_read(self: FeedSyncer, source: Source) -> dict[str, Any]:
            # Widen the read -> write window: unlocked, both threads would read the
            # same (empty) mirror here and the second write would drop the first.
            data = original_read(self, source)
            time.sleep(0.1)
            return data

        monkeypatch.setattr(FeedSyncer, "_existing_mirror", slow_read)

        def handler(request: httpx.Request) -> httpx.Response:
            cve = request.url.path.rsplit("/", 1)[-1]
            # Both threads have finished reading/fetching before either merges.
            both_fetched.wait(timeout=5)
            return httpx.Response(200, json={"cveMetadata": {"cveId": cve}, "containers": {}})

        def run(cve: str, results: dict[str, Any]) -> None:
            syncer = FeedSyncer(
                cache_dir=tmp_path,
                transport=httpx.MockTransport(handler),
                sleep=lambda _s: None,
            )
            results[cve] = syncer.sync_cve_org([cve])

        results: dict[str, Any] = {}
        threads = [
            threading.Thread(target=run, args=(cve, results))
            for cve in ("CVE-2021-44228", "CVE-2024-3400")
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r.success for r in results.values())
        saved = json.loads(mirror_path(tmp_path, Source.CVE_ORG).read_text(encoding="utf-8"))
        assert set(saved) == {"CVE-2021-44228", "CVE-2024-3400"}
        assert not lock_path_for(mirror_path(tmp_path, Source.CVE_ORG)).exists()

    def test_merge_reads_the_mirror_inside_the_lock(self, tmp_path: Path) -> None:
        """A write landing between fetch and merge is kept (the read happens under lock)."""
        target = mirror_path(tmp_path, Source.CVE_ORG)

        def handler(request: httpx.Request) -> httpx.Response:
            # Another writer lands its record after our fetch but before our merge.
            target.write_text(json.dumps({"CVE-2014-0160": {}}), encoding="utf-8")
            cve = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"cveMetadata": {"cveId": cve}, "containers": {}})

        syncer = FeedSyncer(
            cache_dir=tmp_path, transport=httpx.MockTransport(handler), sleep=lambda _s: None
        )
        assert syncer.sync_cve_org(["CVE-2021-44228"]).success
        assert set(json.loads(target.read_text(encoding="utf-8"))) == {
            "CVE-2014-0160",
            "CVE-2021-44228",
        }

    def test_lock_timeout_is_reported_not_raised(self, tmp_path: Path) -> None:
        target = mirror_path(tmp_path, Source.CVE_ORG)

        def handler(request: httpx.Request) -> httpx.Response:
            cve = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"cveMetadata": {"cveId": cve}, "containers": {}})

        syncer = FeedSyncer(
            cache_dir=tmp_path,
            transport=httpx.MockTransport(handler),
            sleep=lambda _s: None,
            lock_timeout_seconds=0.2,
        )
        with MirrorLock(target):
            result = syncer.sync_cve_org(["CVE-2021-44228"])
        assert result.success is False
        assert "lock" in (result.error or "").lower()
