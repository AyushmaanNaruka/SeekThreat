"""Tests for process-level in-memory mirror caching (Task 1).

Verifies that bulk mirrors (especially FIRST EPSS with ~385k rows, as well as KEV,
ExploitDB, and Metasploit) are loaded once per process and reused across
FusionEngine and source client instantiations without repeated disk I/O or JSON parsing.

Key invariants tested:
1. Multiple source instances on the same file share the identical in-memory record dictionary.
2. In-memory cache is keyed by (path, sha256, synced_at, mtime, size).
3. Modifying the mirror file or updating the .meta.json sidecar triggers an atomic reload.
4. Instance-level clear() does not mutate or clear the shared process cache.
5. clear_mirror_cache() successfully purges the process-level cache.
6. Thread safety under concurrent initialization with double-checked locking.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from packages.schema.models.provenance import Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.sources import (
    CISAKevSource,
    ExploitDBSource,
    FirstEPSSSource,
    MetasploitSource,
)
from services.enrichment.sources.base import clear_mirror_cache

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "enrichment"


@pytest.fixture(autouse=True)
def _reset_mirror_cache() -> None:
    """Ensure a clean mirror cache before and after every test."""
    clear_mirror_cache()
    yield
    clear_mirror_cache()


class TestEPSSMirrorCache:
    """Tests for FirstEPSSSource process-level caching."""

    def test_epss_reuses_in_memory_cache_across_instances(self) -> None:
        fixture_path = FIXTURES_DIR / "epss_v4_sample.json"
        source1 = FirstEPSSSource(cache_file=fixture_path)
        assert source1.is_loaded
        count1 = source1.count()
        assert count1 > 0

        # Second instance must reuse the identical dictionary in memory
        source2 = FirstEPSSSource(cache_file=fixture_path)
        assert source2.is_loaded
        assert source2.count() == count1
        assert source1._cache is source2._cache, (
            "Expected exact same dictionary reference in memory"
        )

        # Lookups are consistent
        rec1 = source1.lookup("CVE-2021-44228")
        rec2 = source2.lookup("CVE-2021-44228")
        assert rec1 is rec2

    def test_epss_cache_invalidation_on_meta_sidecar_change(self, tmp_path: Path) -> None:
        """Updating .meta.json sidecar sha256/synced_at triggers cache reload."""
        mirror_file = tmp_path / "epss_v4.json"
        meta_file = tmp_path / "epss_v4.meta.json"

        # Write initial mirror payload
        initial_data = {
            "score_date": "2026-10-01",
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"},
            ],
        }
        mirror_file.write_text(json.dumps(initial_data), encoding="utf-8")
        initial_meta: dict[str, Any] = {
            "sha256": "initial_hash_111",
            "synced_at": "2026-10-01T00:00:00Z",
            "record_count": 1,
            "source_url": "https://example.com/epss",
        }
        meta_file.write_text(json.dumps(initial_meta), encoding="utf-8")

        s1 = FirstEPSSSource(cache_file=mirror_file)
        assert s1.count() == 1
        rec1 = s1.lookup("CVE-2021-44228")
        assert rec1 is not None
        assert abs(rec1.epss - 0.97) < 1e-4

        # Update mirror with new CVE and updated metadata sidecar
        updated_data = {
            "score_date": "2026-10-02",
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.98", "percentile": "0.995"},
                {"cve": "CVE-2022-22947", "epss": "0.89", "percentile": "0.95"},
            ],
        }
        mirror_file.write_text(json.dumps(updated_data), encoding="utf-8")
        updated_meta: dict[str, Any] = {
            "sha256": "updated_hash_222",
            "synced_at": "2026-10-02T00:00:00Z",
            "record_count": 2,
            "source_url": "https://example.com/epss",
        }
        meta_file.write_text(json.dumps(updated_meta), encoding="utf-8")

        # New instance must detect changed sha256/synced_at and reload
        s2 = FirstEPSSSource(cache_file=mirror_file)
        assert s2.count() == 2
        assert s2._cache is not s1._cache
        rec2 = s2.lookup("CVE-2021-44228")
        assert rec2 is not None
        assert abs(rec2.epss - 0.98) < 1e-4
        assert s2.lookup("CVE-2022-22947") is not None

    def test_instance_clear_does_not_mutate_process_cache(self) -> None:
        fixture_path = FIXTURES_DIR / "epss_v4_sample.json"
        s1 = FirstEPSSSource(cache_file=fixture_path)
        assert s1.count() > 0
        cached_dict_before = s1._cache

        # Clearing s1 only unbinds s1's index without mutating the cached dict
        s1.clear()
        assert not s1._loaded
        assert len(cached_dict_before) > 0, "Shared process cache dict must not be emptied"

        # A new instance should still retrieve the loaded cache
        s2 = FirstEPSSSource(cache_file=fixture_path)
        assert s2.count() > 0
        assert s2.is_loaded
        assert s2._cache is cached_dict_before

    def test_clear_mirror_cache_purges_process_cache(self) -> None:
        fixture_path = FIXTURES_DIR / "epss_v4_sample.json"
        s1 = FirstEPSSSource(cache_file=fixture_path)
        assert s1.count() > 0

        # Purge process-level mirror cache
        clear_mirror_cache(Source.EPSS)

        # New instance loads fresh
        s2 = FirstEPSSSource(cache_file=fixture_path)
        assert s2.count() > 0
        assert s1._cache is not s2._cache

    def test_concurrent_source_loading_thread_safety(self) -> None:
        fixture_path = FIXTURES_DIR / "epss_v4_sample.json"

        def _load_epss() -> FirstEPSSSource:
            return FirstEPSSSource(cache_file=fixture_path)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(_load_epss) for _ in range(16)]
            instances = [f.result() for f in futures]

        first_cache = instances[0]._cache
        for inst in instances:
            assert inst._cache is first_cache
            assert inst.count() > 0

    def test_epss_repeated_instantiation_performance(self) -> None:
        """Verify repeated instantiations reuse cached dictionary in microseconds."""
        import time

        fixture_path = FIXTURES_DIR / "epss_v4_sample.json"
        s0 = FirstEPSSSource(cache_file=fixture_path)
        assert s0.is_loaded

        start = time.perf_counter()
        for _ in range(200):
            s = FirstEPSSSource(cache_file=fixture_path)
            assert s._cache is s0._cache
        elapsed = time.perf_counter() - start

        # 200 instantiations should take well under 500ms (<2.5ms per instantiation on Windows NTFS)
        assert elapsed < 0.5, f"Repeated instantiations took {elapsed:.4f}s"


class TestBulkMirrorsProcessCache:
    """Verify other bulk catalog sources (KEV, ExploitDB, Metasploit) benefit from caching."""

    def test_cisa_kev_reuses_cache_across_instances(self) -> None:
        fixture_path = FIXTURES_DIR / "cisa_kev_sample.json"
        k1 = CISAKevSource(cache_file=fixture_path)
        k2 = CISAKevSource(cache_file=fixture_path)
        assert k1.is_loaded
        assert k2.is_loaded
        assert k1._cache is k2._cache

    def test_exploitdb_reuses_cache_across_instances(self) -> None:
        fixture_path = FIXTURES_DIR / "exploitdb_sample.json"
        e1 = ExploitDBSource(cache_file=fixture_path)
        e2 = ExploitDBSource(cache_file=fixture_path)
        assert e1.is_loaded
        assert e2.is_loaded
        assert e1._cache is e2._cache

    def test_metasploit_reuses_cache_across_instances(self) -> None:
        fixture_path = FIXTURES_DIR / "metasploit_sample.json"
        m1 = MetasploitSource(cache_file=fixture_path)
        m2 = MetasploitSource(cache_file=fixture_path)
        assert m1.is_loaded
        assert m2.is_loaded
        assert m1._cache is m2._cache

    def test_fusion_engine_instances_share_underlying_mirrors(self, tmp_path: Path) -> None:
        """Creating multiple FusionEngines with cache_dir reuses in-memory mirror caches."""
        (tmp_path / "epss_v4.json").write_text(
            (FIXTURES_DIR / "epss_v4_sample.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (tmp_path / "cisa_kev.json").write_text(
            (FIXTURES_DIR / "cisa_kev_sample.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (tmp_path / "exploitdb.json").write_text(
            (FIXTURES_DIR / "exploitdb_sample.json").read_text(encoding="utf-8"), encoding="utf-8"
        )
        (tmp_path / "metasploit.json").write_text(
            (FIXTURES_DIR / "metasploit_sample.json").read_text(encoding="utf-8"), encoding="utf-8"
        )

        engine1 = FusionEngine(cache_dir=tmp_path)
        engine2 = FusionEngine(cache_dir=tmp_path)

        assert engine1.first_epss.count() > 0
        assert engine1.first_epss._cache is engine2.first_epss._cache
        assert engine1.cisa_kev._cache is engine2.cisa_kev._cache
        assert engine1.exploitdb._cache is engine2.exploitdb._cache
        assert engine1.metasploit._cache is engine2.metasploit._cache
