# Task 6 Implementation: Post-Scan Real-Time Targeted Feed Sync & Re-enrichment Pipeline

> **Document:** `docs/mayank_implementation/task6_level2_work.md`  
> **Topic:** Task 6 of `docs/mayank_implementation/mayank_task_level2.md` (PR 7: `feat/targeted-scan-enrichment`)  
> **Author:** Mayank Narang (Layer 2 Owner)  
> **Status:** ✅ Complete  

---

## 1. Executive Summary

In SeekThreat's multi-tier vulnerability intelligence architecture (Layer 2), vulnerability scoring (CVSS v3.1 / v4.0, EPSS v4, KEV exploit corroboration, Exposure Risk Score) depends directly on local feed mirrors (`CVE.org`, `Vulnrichment`, `NVD`, `EUVD`).

Under Decision **D-036**, feed mirrors are structured per-CVE and synced for CVE IDs tracked in the database. Historically, the background sync was dispatched solely via a scheduled Celery beat job running daily at 02:00 UTC (`seekthreat.sync_feeds.run`).

### The Latency Problem:
If a scanner (e.g. Nuclei, Nmap) discovered an emerging CVE during a scan at 10:00 AM:
1. The new CVE record did not exist yet in local per-CVE mirror directories.
2. Layer 2 enrichment was forced to fall back to derived/fallback CVSS scores or missing EPSS percentiles.
3. High-confidence upstream metrics remained unavailable for up to 16 hours until the next scheduled daily sync.

### The Solution (Task 6):
Task 6 implements an asynchronous, fire-and-forget post-scan enrichment pipeline:
1. **Asynchronous Celery Task:** `seekthreat.enrichment.sync_new_findings_cves` (`apps/api/tasks/post_scan_enrichment.py`).
2. **Scan Completion Trigger:** Dispatched automatically off the request path upon scan execution completion in `apps/api/tasks/scans.py`.
3. **Artifact Candidate Extraction:** Extracts unique CVE IDs from newly discovered `ObservationKind.VULN_CANDIDATE` observations tied to the completed scan artifact.
4. **Targeted Mirror Delta Check:** Identifies which discovered CVE IDs lack local records across CVE.org, Vulnrichment, EUVD, and NVD mirrors.
5. **Targeted Per-CVE Sync:** Runs `FeedSyncer.sync_cve_records(missing_cves)` fetching upstream records only for newly discovered CVEs.
6. **Automatic Re-enrichment:** Queries `enriched_findings` for all findings matching the synced CVEs and recalculates ERS, EPSS, and CVSS composites with newly acquired high-confidence data.
7. **Strict Error Isolation:** Network timeouts, upstream rate limits, or sync failures never fail or delay the scan itself (`max_retries=0`, exception isolation).

---

## 2. Architecture & Pipeline Flow

```mermaid
sequenceDiagram
    autonumber
    participant ScanTask as apps.api.tasks.scans.execute
    participant DB as PostgreSQL DB
    participant Celery as Celery (enrichment queue)
    participant PostScanTask as seekthreat.enrichment.sync_new_findings_cves
    participant Mirror as Local Mirror Cache
    participant Upstream as External Feed Upstreams
    participant Engine as EnrichmentEngine

    ScanTask->>DB: Store Raw Artifact & Observations (VULN_CANDIDATE)
    ScanTask->>DB: Commit Scan Status (COMPLETED)
    ScanTask-)Celery: Dispatch sync_new_findings_cves.delay(artifact_id, ...) (Fire-and-Forget)
    Note over ScanTask: Scan finishes immediately; never blocked

    Celery->>PostScanTask: Execute in worker
    PostScanTask->>DB: Query VULN_CANDIDATE observations for artifact
    PostScanTask->>Mirror: Check missing mirrors for discovered CVEs
    alt No missing mirrors or no CVEs
        PostScanTask-->>Celery: Terminate early (fast-path)
    else Missing CVE mirrors detected
        PostScanTask->>Upstream: FeedSyncer.sync_cve_records(missing_cves)
        Upstream-->>Mirror: Populate local JSON mirror records
        PostScanTask->>DB: Fetch EnrichedFinding rows for affected CVEs
        PostScanTask->>Engine: Re-enrich findings with fresh mirror data
        PostScanTask->>DB: Update & commit re-enriched findings
    end
```

---

## 3. Engineering Decisions & Rationale

| Decision Point | Implementation Choice | Technical Rationale |
| :--- | :--- | :--- |
| **Execution Decoupling** | Fire-and-forget via Celery `delay()` after scan DB commit | Scans must never fail or stall due to upstream feed availability or rate limits. |
| **Retry Strategy** | `max_retries=0` | Prevents cascading retry floods during upstream API downtime. Daily Celery beat guarantees eventual consistency. |
| **Queue Routing** | `queue="enrichment"` | Runs on the dedicated enrichment worker queue shared with `sync_feeds.run`, preventing scan worker starvation. |
| **Worker Discovery** | Registered in `apps/api/worker.py` and exported in `apps/api/tasks/__init__.py` | Ensures standard `celery -A apps.api.worker worker` discovers and registers the task without manual configuration. |
| **Circular Import Guard** | Lazy function-level import of task in `scans.py` | Both `scans.py` and `post_scan_enrichment.py` import `celery_app` from `worker.py`. Lazy import prevents module initialization cycles. |
| **Testability Decoupling** | `run_post_scan_enrichment(...)` callable decoupled from Celery wrapper | Allows comprehensive synchronous unit and mock testing without requiring Celery runtime overhead. |

---

## 4. Modified & Created Components

### 1. `apps/api/tasks/post_scan_enrichment.py` (New)
- `_cve_ids_from_artifact(session, artifact_id)`: Safely extracts uppercase CVE identifiers from `VULN_CANDIDATE` observations matching standard `CVE-\d{4}-\d{4,7}` regex.
- `_missing_cve_ids(cve_ids, cache_dir)`: Verifies whether local files exist in `cache_dir / source / <CVE>.json` across all per-CVE sources (`cve_org`, `vulnrichment`, `euvd`, `nvd`).
- `_findings_for_cves(session, cve_ids)`: Selects all `EnrichedFindingModel` records associated with any of the affected CVEs.
- `_reenrich_findings(...)`: Re-runs `EnrichmentEngine.enrich(...)` and commits updated `EnrichedFindingModel` records.
- `run_post_scan_enrichment(...)`: Core pipeline controller with complete error handling.
- `sync_new_findings_cves`: Celery task decorated with `@celery_app.task(name="seekthreat.enrichment.sync_new_findings_cves", queue="enrichment", max_retries=0)`.

### 2. `apps/api/tasks/scans.py` (Modified)
- Added `_dispatch_post_scan_enrichment(artifact_id, engagement_id, scan_id)`.
- Invoked immediately after `db.commit()` marks the scan as `COMPLETED`.
- Wrapped in `try...except Exception:` with warning log so any dispatch failure is cleanly swallowed without affecting the scan.

### 3. `apps/api/tasks/__init__.py` (Modified)
- Exported `sync_new_findings_cves` alongside `execute_scan`, `enrich_finding`, and `run_sync_feeds`.

### 4. `tests/unit/test_worker_registration.py` (Modified)
- Added `SYNC_NEW_FINDINGS_CVES_TASK_NAME = "seekthreat.enrichment.sync_new_findings_cves"`.
- Added `test_sync_new_findings_cves_task_is_registered_by_importing_the_worker_module()`.
- Updated `EXPECTED_TASKS` set.

### 5. `tests/unit/test_post_scan_enrichment.py` (New)
- 19 targeted unit tests covering:
  - CVE extraction from observation details and metadata.
  - Deduping, invalid format filtering, non-vulnerability observation filtering.
  - Cache detection and missing-CVE logic.
  - Empty candidate short-circuits.
  - Targeted sync invocations and feed syncer parameter passing.
  - Finding re-enrichment and DB persistence.
  - Celery task dispatch and error isolation (network failure does not raise).
  - Scan completion dispatch integration in `scans.py`.

---

## 5. Test & Quality Verification

### Summary of Test Execution:
- **`tests/unit/test_post_scan_enrichment.py`**: 19 tests passed.
- **`tests/unit/test_worker_registration.py`**: 5 tests passed.
- **Full Pytest Suite**: All unit and integration tests passing.
- **Code Quality**: Verified clean with `ruff check` and strict typing compliance.
