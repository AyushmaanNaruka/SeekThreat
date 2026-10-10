# Level 2 of Layer 2 Second Part — Walkthrough

**Level title:** Feed Sync Job (Off-Request-Path Mirror Synchronization)  
**Branch:** `mayank_level2_second`  
**Date completed:** 2026-10-05  
**PR scope:** `services/enrichment/sources/sync.py`, `services/enrichment/sync_feeds.py`, `apps/api/tasks/sync_feeds.py`, `apps/api/worker.py`, `apps/api/tasks/__init__.py`, `tests/unit/test_feed_sync.py`, `tests/unit/test_worker_registration.py`, `DECISIONS.md`.  

---

## 1. What this level was

In Layer 2 first part, `SourceSynchronizer` in `services/enrichment/sources/sync.py` was introduced to atomically persist already-fetched dictionaries into cache directories. However, no actual download job existed to populate `ENRICHMENT_CACHE_DIR` with upstream threat feeds.

### Core Objectives & Constraints
1. **Network Isolation (Rule 5):** "Mirror sources locally. Don't hit APIs on the request path." Network calls are strictly forbidden during finding enrichment (`EnrichmentService` and `FusionEngine`). Network I/O is confined exclusively to the off-request-path sync job.
2. **Offline Mirror Guard:** [`tests/unit/test_offline_mirror.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_offline_mirror.py) patches network clients and ensures request-path enrichment executes completely offline. It must continue passing without modification.
3. **Canonical Filenames (`MIRROR_FILENAMES`):** Writer (`FeedSyncer`) and reader (`FusionEngine`) share the exact same mapping contract defined in [`services/enrichment/sources/sync.py`](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/sync.py#L46-L56).
4. **Atomic Write Safety:** Interrupted or failed downloads must never corrupt or partially overwrite an existing local cache file.
5. **Dual Invocability:**
   - **Celery Beat:** Automated daily background sync in production workers.
   - **Standalone CLI:** Direct script execution for container bootstrapping, CI environments, and air-gapped prep without needing the Celery/API stack running.

---

## 2. Test-Driven Development (Tests First)

Following strict TDD protocol, [`tests/unit/test_feed_sync.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_feed_sync.py) was written prior to implementing `FeedSyncer`.

### Test Suite Structure (25 Tests)
- `TestMirrorFilenames`: Validates mapping fidelity for `Source.KEV` (`cisa_kev.json`), `Source.EPSS` (`epss_v4.json`), and `Source.CVE_ORG` (`cve_org.json`), along with path resolution helper `mirror_path()`.
- `TestFeedSyncerInit`: Validates cache directory creation, `str` vs `Path` coercion, and fallback to `settings.enrichment_cache_dir`.
- `TestSyncKev`: Validates fetching CISA KEV JSON, error handling on HTTP non-200/exceptions, and atomic write retention (existing file left intact when download fails).
- `TestSyncEpss`: Validates FIRST EPSS v4 retrieval with query parameter `?all=true` and failure isolation.
- `TestSyncCveOrg`: Validates CVE Services API pagination and record dictionary transformation.
- `TestSyncAll`: Confirms all three feeds are processed sequentially, and partial failure of one feed does not abort subsequent feeds.
- `TestSyncResultMetadata`: Verifies `SyncResult` dataclass properties (success flag, records synced, timestamp, target path, optional error text).
- `TestSyncFeedsCeleryTask`: Validates Celery task execution, structured summary dictionary return, and retry backoff on unhandled exceptions.
- `TestSyncFeedsCLI`: Validates command-line flag handling (`--source all`, `--source kev`, `--cache-dir`), logging, and exit codes (0 on success, 1 on failure).

In addition, [`tests/unit/test_worker_registration.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_worker_registration.py) was updated to test that the new Celery task `seekthreat.sync_feeds.run` is registered upon importing `apps.api.worker` in an isolated subprocess.

---

## 3. Implementation Details

### A. [`services/enrichment/sources/sync.py`](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/sync.py) — `FeedSyncer`
- **Class `FeedSyncer`:** Takes `cache_dir`, `timeout_seconds`, and customizable feed endpoint URLs (`kev_url`, `epss_url`, `cve_org_url`).
- **Atomic Delegation:** Downloads the remote JSON via `httpx.get()` and passes the parsed payload directly to `SourceSynchronizer.sync_from_data()`, inheriting atomic file writes (writing to `.<filename>.tmp` before invoking `os.replace`).
- **`sync_cve_org()` Reshaping:** Normalizes MITRE CVE Services API response format into a keyed `{cve_id: record}` dictionary so it matches the expected local mirror structure for `CVEOrgSource`.
- **`SyncResult` Enhancement:** Added `synced_at: datetime = field(default_factory=lambda: datetime.now(UTC))` so result records can be instantiated without boilerplate timestamps while remaining immutable.

### B. [`services/enrichment/sync_feeds.py`](file:///e:/SeekThreat/SeekThreat/services/enrichment/sync_feeds.py) — Standalone CLI
- Fully independent runnable module:
  ```bash
  python -m services.enrichment.sync_feeds [--source kev|epss|cve_org|all] [--cache-dir DIR] [--timeout SECONDS]
  ```
- Reads `settings.enrichment_cache_dir` if available, but falls back cleanly to local defaults if run in an environment without database or API dependencies configured.
- Exits with status code `0` on full success and `1` if any feed fails.

### C. [`apps/api/tasks/sync_feeds.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/sync_feeds.py) — Celery Task
- Registered as `seekthreat.sync_feeds.run` on Celery queue `"enrichment"`.
- Configured with `bind=True`, `max_retries=2`, and `default_retry_delay=300`.
- Catches unhandled exceptions, logs backoff retries, and catches `MaxRetriesExceededError` to return a structured error dictionary rather than crashing unhandled.
- Produces a summary dictionary of results:
  ```json
  {
    "cisa.kev": {"success": true, "records": 1250},
    "epss": {"success": true, "records": 240000},
    "cve.org": {"success": true, "records": 1000}
  }
  ```

### D. [`apps/api/worker.py`](file:///e:/SeekThreat/SeekThreat/apps/api/worker.py) — Celery Beat Schedule
- Registered task route:
  ```python
  "seekthreat.sync_feeds.run": {"queue": "enrichment"}
  ```
- Configured beat schedule:
  ```python
  "sync-enrichment-feeds-daily": {
      "task": "seekthreat.sync_feeds.run",
      "schedule": 86400.0,  # 24 hours
  }
  ```
- Imported `sync_feeds` task module during worker bootstrap.

### E. [`tests/unit/test_worker_registration.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_worker_registration.py)
- Updated `EXPECTED_TASKS` from 2 to 3 Celery tasks:
  - `seekthreat.scans.execute`
  - `seekthreat.enrichment.enrich`
  - `seekthreat.sync_feeds.run`
- Added dedicated subprocess verification test: `test_sync_feeds_task_is_registered_by_importing_the_worker_module`.

---

## 4. Architectural Decision Logged

Logged in [`DECISIONS.md`](file:///e:/SeekThreat/SeekThreat/DECISIONS.md):
- **D-033: Off-request-path feed synchronization via FeedSyncer, Celery Beat, and CLI**
  - Documents the architecture, Rule 5 compliance, atomic write design, and zero-dependency footprint (`httpx` 0.28.1 already present in `requirements.txt`).

---

## 5. Verification & CI Health

All CI checks passed:

| Tool | Scope | Result |
|---|---|---|
| `ruff check` | Repository-wide | ✅ Passed (0 errors) |
| `ruff format --check` | Repository-wide | ✅ Passed (148 files checked, 0 unformatted) |
| `mypy` | `packages services apps` | ✅ Passed (0 new errors; 1 pre-existing local SQLAlchemy 2.0.35 quirk) |
| `pytest` | Unit tests (`test_feed_sync.py` + `test_offline_mirror.py`) | ✅ 25 passed |
| `pytest` | Worker registration (`test_worker_registration.py`) | ✅ 4 passed |
| `pytest` | Full repository test suite | ✅ **496 passed, 3 skipped** (up from 470 passed) |

---

## 6. Checklist Status

- [x] Tests written before implementation
- [x] Network calls isolated strictly to sync job, never on request path
- [x] `test_offline_mirror.py` unchanged and passing
- [x] Dependency verified (httpx 0.28.1 already in `requirements.txt`, MIT license)
- [x] Standalone CLI callable (`python -m services.enrichment.sync_feeds`)
- [x] Celery task and beat schedule wired in `apps/api/worker.py`
- [x] Worker registration test updated and passing in isolated subprocess
- [x] D-033 logged in `DECISIONS.md`
- [x] Status table updated in [`docs/mayank_implementation/level_2_second_part.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level_2_second_part.md)
- [x] CI green across ruff, mypy, and pytest

---

## 7. What Level 3 Picks Up

With the feed synchronization mechanism in place, `ENRICHMENT_CACHE_DIR` can be populated with real offline mirrors:
- `Source.KEV` → `cisa_kev.json`
- `Source.EPSS` → `epss_v4.json`
- `Source.CVE_ORG` → `cve_org.json`

Level 3 will now implement real local mirror readers for secondary sources:
1. `VulnrichmentSource` (SSVC decision, CVSS, CWE fallback)
2. `EUVDSource` (European Union Vulnerability Database fallback)
3. `ExploitDBSource` & `MetasploitSource` (exploit availability metadata for Layer 3 graph traversal, strictly respecting Hard Rule 4: IDs/names only, no exploit execution).
