# Track B Implementation: Feed Freshness, Staleness Policies & Health Monitoring

**Branch:** `mayank_level2_working`  
**Base Commit:** `a82986f` (PR #19 merged), following review fix `48d5f2b`  
**Owner:** Mayank (Layer 2 Owner)  
**Status:** Completed  
**Compliance Standard:** CLAUDE.md Non-Negotiables & DECISIONS.md D-030  

---

## 1. Executive Summary & Objective

In threat intelligence enrichment, the absence of an indicator is only meaningful if the intelligence source is fresh and authoritative. As highlighted in **D-030**:
> A local mirror that has not synced in 30 days confidently asserting `in_kev = False` is dangerous — it produces a false negative with unearned high confidence.

Track B implements end-to-end freshness governance across SeekThreat:
1. **Configurable Staleness Policy (B-1):** Downgrades confidence on affirmative negative assertions (`in_kev = False`, `has_public_exploit = False`, `has_metasploit_module = False`) when mirrors exceed the staleness threshold (default: 7 days), with explicit provenance auditing notes.
2. **Feed Status API (B-2):** Exposes `GET /feeds/status` reporting real metadata from `.meta.json` and `.notfound.json` sidecars across all 8 intelligence sources, strictly avoiding fabricated numbers (`synced_at: null`, `last_sync_result: "never"` when uninitialized).
3. **Dashboard Feed Health Panel (B-3):** A responsive, rich-aesthetic UI panel in `apps/web/components/FeedHealthPanel.tsx` integrated into `apps/web/app/dashboard/page.tsx`, displaying live sync state, freshness badges, and cache counts with auto-refresh.
4. **Daily Beat Sync Re-Enrichment (B-4):** Integrates post-sync findings re-enrichment into the Celery beat schedule (`sync_feeds` task), ensuring engagements referencing updated CVEs are automatically refreshed with keyset pagination and `system:celery_beat` audit tracking.

---

## 2. Progress Tracker

| Task | Component | Priority | Status | Verification Method | Primary Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B-1** | Staleness Policy & Confidence Downgrade | 🟡 Medium | ✅ Completed | Unit tests (`test_mirror_staleness.py`) | Configured `mirror_staleness_threshold_days = 7`; affirmative negatives from mirrors > 7d old downgraded to `MEDIUM` or `LOW` with `stale` note; positive hits remain `HIGH`. |
| **B-2** | `GET /feeds/status` API Endpoint | 🟡 Medium | ✅ Completed | Unit tests (`test_feeds_status.py`) | Created `apps/api/routers/feeds.py`, registered in `main.py`, audited as `feeds_status_read`, returns sidecar metadata without fabrication. |
| **B-3** | Dashboard Feed Health Panel | 🟢 Low | ✅ Completed | Frontend tests (`node --test`) & visual integration | Created `FeedHealthPanel.tsx`, integrated into dashboard overview and sidebar navigation (`activeNav === "Feeds"`). |
| **B-4** | Beat Sync Re-Enrichment | 🟡 Medium | ✅ Completed | Unit tests (`test_beat_sync_reenrichment.py`) | Added engagement-scoped re-enrichment to `sync_feeds.py` after successful sync, audited per engagement under `system:celery_beat`. |

---

## 3. Task B-1: Staleness Policy & Confidence Downgrade

### Architectural Invariants
- **Configuration:** `mirror_staleness_threshold_days: int = 7` in [apps/api/core/config.py](file:///e:/SeekThreat/SeekThreat/apps/api/core/config.py).
- **Age Calculation:** [BaseEnrichmentSource.mirror_age_days()](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/base.py) computes fractional age based on the mirror's `.meta.json` `synced_at` timestamp. If no sidecar exists, age cannot be proven and `None` is returned (`is_stale() == False`).
- **Affirmative Negative Downgrade in `FusionEngine`:**
  - **CISA KEV:** If `cisa_kev.is_stale()`, negative assertion (`in_kev = False`) is downgraded from `Confidence.HIGH` to `Confidence.MEDIUM`, with provenance note: `"fusion: KEV mirror stale (Xd); downgrading negative in_kev confidence"`. Confirmed hits (`in_kev = True`) remain `Confidence.HIGH`.
  - **ExploitDB:** If `exploitdb.is_stale()`, negative assertion (`has_public_exploit = False`) is downgraded from `Confidence.MEDIUM` to `Confidence.LOW`.
  - **Metasploit:** If `metasploit.is_stale()`, negative assertion (`has_metasploit_module = False`) is downgraded from `Confidence.MEDIUM` to `Confidence.LOW`.
- **Empty Catalog Rule:** Mirrors holding zero records evaluate `is_loaded == False`, returning `None` (unknown status) rather than negative assertions, adhering to CLAUDE.md.

---

## 4. Task B-2: `GET /feeds/status` API Endpoint

### Implementation Details
- **Router:** [apps/api/routers/feeds.py](file:///e:/SeekThreat/SeekThreat/apps/api/routers/feeds.py)
- **Response Schema:**
  ```python
  class FeedStatus(BaseModel):
      name: str
      synced_at: datetime | None
      record_count: int | None
      sha256: str | None
      last_sync_result: str  # "ok", "error", or "never"
      is_stale: bool
      not_found_cache_size: int
  ```
- **Auditing:** Emits `AuditLog` event with action `feeds_status_read` and target `feeds:all`.
- **Honest Null Semantics:** When no `.meta.json` sidecar exists on disk, `synced_at` is returned as `null`, `sha256` as `null`, and `last_sync_result` as `"never"`.

---

## 5. Task B-3: Dashboard Feed Health Panel

### Implementation Details
- **Component:** [apps/web/components/FeedHealthPanel.tsx](file:///e:/SeekThreat/SeekThreat/apps/web/components/FeedHealthPanel.tsx)
- **Dashboard Integration:** [apps/web/app/dashboard/page.tsx](file:///e:/SeekThreat/SeekThreat/apps/web/app/dashboard/page.tsx)
- **Features:**
  - Real-time display of all 8 feeds (`cve_org`, `cisa_kev`, `first_epss`, `nvd`, `vulnrichment`, `euvd`, `exploitdb`, `metasploit`).
  - Color-coded status pills: `Healthy` (green glow), `Stale` (amber alert), `Never synced` (neutral muted).
  - Metrics cards: Sync date, record count, SHA256 checksum prefix, negative cache count.
  - Interactive auto-refresh every 60 seconds with manual refresh button and loading indicators.
  - Accessible directly via the sidebar navigation ("Feed Health") and embedded on the main command center overview.

---

## 6. Task B-4: Beat Sync Re-Enrichment

### Implementation Details
- **Task:** [apps/api/tasks/sync_feeds.py](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/sync_feeds.py)
- **Workflow:**
  1. Post feed sync, collects set of `newly_synced_cves`.
  2. Identifies all `engagement_id`s containing findings that reference those CVEs via `_engagement_ids_for_cves()`.
  3. Iterates per affected engagement with keyset pagination (500 items per batch) to re-enrich findings using `EnrichmentService.enrich_finding()`.
  4. Emits `AuditLog` entry per re-enriched engagement with:
     - `actor = "system:celery_beat"`
     - `action = "findings_reenriched_beat_sync"`
     - `target = f"engagement:{engagement_id}/beat_sync"`
  5. Engagement isolation: An engagement with no findings matching updated CVEs is completely skipped.

---

## 7. Test Verification & Results

### Unit Tests
```bash
python -m pytest tests/unit/test_mirror_staleness.py tests/unit/test_feeds_status.py tests/unit/test_beat_sync_reenrichment.py -v
```
**Results:**
- `test_mirror_staleness.py`: 14 passed
- `test_feeds_status.py`: 8 passed
- `test_beat_sync_reenrichment.py`: 7 passed
- **Total:** **29 passed in 5.62s**

### Regression Suite
```bash
python -m pytest tests/unit/test_enrichment_fallback.py tests/unit/test_enrichment_mirror_wiring.py tests/unit/test_mirror_staleness.py tests/unit/test_feeds_status.py tests/unit/test_beat_sync_reenrichment.py -v
```
**Results:**
- **67 passed in 6.92s**, 0 failures.

### Frontend Test Suite
```bash
npm --prefix apps/web test
```
**Results:**
- **23 passed, 0 failures in 901ms**.
