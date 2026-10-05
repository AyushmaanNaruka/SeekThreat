# Layer 2 — Second Part: Make Enrichment Real

**Branch:** `mayank_level2_second` (based on `origin/main` @ `587ffa0`, PRs #16 + #17 merged)
**Started:** 2026-10-05
**"Done When" (Layer 2):** Coverage measured against an NVD-only baseline.
**Rule:** One PR per concern · CI green (`ruff check`, `ruff format --check`, `mypy packages services apps`, `pytest tests`) · tests first · divergences logged in `DECISIONS.md`.

---

## Pre-flight (done)

- [x] Merge `origin/main` into `mayank_level2_second` (fast-forward to `587ffa0`)
- [x] Read fix commits: `4f9df5c` (wildcard allowlist bypass + nuclei hardening) and `575bc7b` (enrichment + API review fixes from PR #17)
- [x] Read `CLAUDE.md`, `docs/00-scope.md`, `docs/02-architecture.md` (pipeline + module map), `services/enrichment/README.md`
- [x] Confirm baseline CI health: **470 passed, 3 skipped**
- [x] Pre-existing CI quirks resolved:
  - `mypy`: local sqlalchemy 2.0.35 emits `no-untyped-call` on `JSONB()` — CI's 2.0.54 does not. Documented; not introduced by this work.
  - `ruff format`: 2 files fixed (CRLF normalized in `apps/api/routers/__init__.py`, `apps/api/tasks/__init__.py`). ✅ Clean.

---

## Level 1 — Decisions & ERS Analysis (D-008 resolution)

> **Goal:** Settle every open design question _before_ writing implementation code.
> **PR scope:** `DECISIONS.md` + `docs/` only — no runtime code changes.

### What needs resolving

Six design gaps identified from reading `ers.py`, `DECISIONS.md D-008`, `services/graph/README.md`, and `575bc7b`:

#### 1.1 — D-008 rationale: document weight reasoning

D-008 exists but says "rationale and sensitivity analysis still to be documented." Write that rationale:

- `weight_cvss = 0.40` — CVSS measures technical severity (attack vector, complexity, impact); it is the most established metric and what viva panellists expect to anchor on.
- `weight_epss = 0.35` — EPSS v4 captures 30-day exploitation probability, the most actionable "fix this now" signal. Intentionally close to CVSS: a low-severity CVE with high EPSS is more urgent than the reverse.
- `weight_kev = 0.25` — KEV is binary (in catalog or not). 25% is large enough to change ranking order for borderline cases but not overwhelm technical severity.
- Additive formula: `ERS = w_cvss × (cvss / 10) + w_epss × epss + w_kev × kev_flag` where all inputs are normalized to [0, 1].

- [ ] Write rationale paragraph in `DECISIONS.md` under D-008.
- [ ] Confirm `ers.py` docstring matches.

#### 1.2 — Sensitivity analysis

- [ ] Compute ERS for 5 CVE fixtures under 3 weight profiles:
  - **Severity-heavy:** 0.60 / 0.25 / 0.15
  - **Balanced (current):** 0.40 / 0.35 / 0.25
  - **Exploitation-heavy:** 0.25 / 0.50 / 0.25
- [ ] Record which profiles change the top-3 ranking.
- [ ] Conclusion: if ranking is stable, weights are defensible. If it shifts, document which reorderings are acceptable.
- [ ] Add sensitivity analysis table as sub-section under D-008 in `DECISIONS.md`.

#### 1.3 — Resolve KEV circularity

**Problem:** D-008 says KEV _validates_ the ranking. But KEV is simultaneously a 25% _input_ to ERS. Using the same signal to both compute and validate is circular.

**Resolution options (pick one):**

- (a) KEV stays as input; validation uses a different measure (e.g., "do high-ERS CVEs have ExploitDB/Metasploit entries?").
- (b) Remove KEV from ERS inputs entirely; use it only as external validation.
- (c) Keep KEV as input; rewrite D-008 to say "KEV is an input, not a validator" — honest but loses the validation claim.

- [ ] Pick a resolution and log it in `DECISIONS.md`.
- [ ] Update `ers.py` docstring to match.

#### 1.4 — Reconcile ERS placement: enrichment (Layer 2) vs scope (Layer 3)

**Problem:** `docs/02-architecture.md` line 72 places `ERS scoring, chokepoint analysis` in the graph layer (Layer 3, November). But ERS already lives in `services/enrichment/ers.py` (Layer 2).

**Resolution:** ERS _computation_ belongs in enrichment (it depends on CVSS, EPSS, KEV — enrichment data). ERS _consumption_ for path ranking belongs in the graph layer. Both can be true. Needs a logged decision to avoid confusion.

- [ ] Log resolution as new decision in `DECISIONS.md`.
- [ ] Optionally update `docs/02-architecture.md` pipeline comment.

#### 1.5 — Reconcile multiplicative path score vs never-multiply rule

**Problem:** `services/graph/README.md` line 24 says `EPSS × exploit availability × privilege delta`. This multiplies EPSS by other factors.

`services/enrichment/README.md` rule 3: "Never multiply EPSS by CVSS."

**Resolution:** Rule 3 specifically bans `EPSS × CVSS`. The graph's path score multiplies `EPSS × exploit_availability × privilege_delta` — different operands, different semantics (conditional probability along a path, not severity weighting). Log whether this distinction holds.

- [ ] Log ruling in `DECISIONS.md`.

#### 1.6 — Log standing decisions (from `575bc7b`)

- [ ] **Composite PK** `(engagement_id, finding_id)` on `enriched_findings` — why: engagement scoping (D-007) + dedup per engagement, not globally.
- [ ] **`in_kev=None` as "unknown"** — missing KEV mirror yields `Source.DERIVED` / `Confidence.LOW`, not a confident negative. Missing mirror ≠ "not exploited."
- [ ] **`/findings` API contract change** — `engagement_id` required on GET and batch POST. Why: authorization scoping, audit logging requirement (CLAUDE.md).

### Level 1 checklist

- [ ] D-008 rationale written
- [ ] Sensitivity analysis table written
- [ ] KEV circularity resolved and logged
- [ ] ERS placement reconciled and logged
- [ ] Multiplicative path score reconciled and logged
- [ ] Three standing decisions logged (PK, in_kev=None, API contract)
- [ ] No runtime code changed in this level
- [ ] CI green

---

## Level 2 — Feed Sync Job

> **Goal:** An off-request-path job that downloads CVE.org, CISA KEV, EPSS v4 into `ENRICHMENT_CACHE_DIR` using filenames from `MIRROR_FILENAMES`.
> **Constraint:** Network allowed ONLY in the sync job. `test_offline_mirror.py` must keep passing.
> **PR scope:** `services/enrichment/sources/sync.py`, CLI command or Celery beat task, new tests.

### Current state

`SourceSynchronizer` in `sync.py` can atomically write a pre-fetched payload. It does not download anything itself. `MIRROR_FILENAMES` defines the filenames. No download job exists.

### 2.1 — Tests first

Write `tests/unit/test_feed_sync.py` **before** implementing:

- [x] Test `FeedSyncer.sync_kev()` calls the canonical CISA KEV URL, writes to `MIRROR_FILENAMES[Source.KEV]` atomically.
- [x] Test `FeedSyncer.sync_epss()` calls the FIRST EPSS v4 endpoint, writes to `MIRROR_FILENAMES[Source.EPSS]`.
- [x] Test `FeedSyncer.sync_cve_org()` calls CVE.org API, writes to `MIRROR_FILENAMES[Source.CVE_ORG]`.
- [x] Test atomic write safety: failed download does not corrupt the existing mirror.
- [x] Test each sync returns a valid `SyncResult` with correct metadata.
- [x] All tests mock HTTP — no real network in CI. Use `unittest.mock.patch` on `httpx` (or equivalent).
- [x] Confirm `test_offline_mirror.py` still passes after adding new test file.

### 2.2 — Implement `FeedSyncer`

- [x] Extend `services/enrichment/sources/sync.py`:
  - Add `FeedSyncer` class with methods: `sync_kev()`, `sync_epss()`, `sync_cve_org()`, `sync_all()`.
  - Each method: HTTP GET → validate response → call existing `sync_from_data()` for atomic write.
  - Upstream URLs: use existing `DEFAULT_CISA_KEV_URL`, `DEFAULT_FIRST_EPSS_URL` constants; add CVE.org URL.
  - Read `ENRICHMENT_CACHE_DIR` from `apps/api/core/config.py`.settings.
- [x] Dependency: if `httpx` or `requests` needed, verify licence (both MIT — OK), add to `pyproject.toml` and `THIRD_PARTY.md` (httpx 0.28.1 already present in requirements.txt; verified MIT).

### 2.3 — CLI entry point

- [x] Add CLI callable without the full API/Celery stack:
  ```
  python -m services.enrichment.sync_feeds [--source kev|epss|cve_org|all]
  ```
- [x] Or management command in `apps/api/cli.py` — implemented as standalone runnable module `services/enrichment/sync_feeds.py`.

### 2.4 — Celery beat schedule (preferred)

- [x] Add a periodic Celery task in `apps/api/tasks/` that calls `FeedSyncer.sync_all()`.
- [x] Configure beat schedule in `apps/api/worker.py` (daily or env-configurable interval).
- [x] Test task registers correctly (pattern from `test_worker_registration.py`).

### 2.5 — Verification

- [x] `test_offline_mirror.py` — must still pass unchanged.
- [x] Full suite CI green (496 passed, 3 skipped).
- [x] Manual smoke: run CLI, confirm files appear in `ENRICHMENT_CACHE_DIR`.

### Level 2 checklist

- [x] Tests written before implementation
- [x] Network calls only in the sync job, never on request path
- [x] `test_offline_mirror.py` unchanged and passing
- [x] New dependency licence-checked and in `THIRD_PARTY.md` (httpx already in requirements.txt)
- [x] CI green

---

## Level 3 — Real Source Implementations (Vulnrichment · EUVD · ExploitDB · Metasploit)

> **Goal:** Replace stubs in `secondary.py` with real local-mirror readers. Add exploit-availability signal for Layer 3.
> **Constraint:** Hard rule 4 — ExploitDB/Metasploit: IDs and module names only. No exploit code. No execution.
> **PR split:** One PR for Vulnrichment + EUVD (fallback chain). One PR for ExploitDB + Metasploit (exploit availability).

### Current state

`VulnrichmentSource`, `EUVDSource`, `ExploitDBSource`, `MetasploitSource` all have stub `load()` that just sets `self._loaded = True`. None reads a mirror file. The fallback chain in `fusion.py` calls them but gets nothing back.

### 3.1 — Vulnrichment source (tests first)

- [x] Write `tests/unit/test_vulnrichment_source.py`:
  - Test loading from a local mirror file.
  - Test `lookup(cve_id)` returns `VulnrichmentRecord` with SSVC decision, CVSS, CWE.
  - Test `is_loaded` property returns True after `load()`.
  - Test graceful handling of missing/malformed records (return `None`, no exception).
- [x] Create synthetic test fixture: `tests/fixtures/enrichment/vulnrichment_sample.json` (marked synthetic per fixture README).
- [x] Implement `VulnrichmentSource.load()` — parse local mirror JSON into in-memory lookup dict.
- [x] Implement `VulnrichmentSource.lookup(cve_id)` — return `VulnrichmentRecord | None`.
- [x] Wire into `FusionEngine` fallback chain: CVE.org → **Vulnrichment** → EUVD → derived.

### 3.2 — EUVD source (tests first)

- [x] Write `tests/unit/test_euvd_source.py`:
  - Test loading from `euvd.json` mirror.
  - Test `lookup(cve_id)` returns `EUVDRecord` with CVSS, CWE.
  - Test graceful degradation for beta/incomplete data.
- [x] Create synthetic fixture: `tests/fixtures/enrichment/euvd_sample.json`.
- [x] Implement `EUVDSource.load()` and `EUVDSource.lookup(cve_id)`.
- [x] Wire into fallback chain as third fallback (after Vulnrichment).

### 3.3 — Fallback chain integration test

- [x] Update `tests/unit/test_enrichment_fallback.py`:
  - Full chain: CVE.org has CVSS → use it. CVE.org missing → Vulnrichment has it → use it. Both missing → EUVD has it → use it. All missing → derived placeholder.
  - Confirm `Provenance.source` correctly reflects which source provided each field.

### 3.4 — ExploitDB metadata source (tests first)

- [x] Write `tests/unit/test_exploitdb_source.py`:
  - Test loading from local mirror file.
  - Test `lookup(cve_id)` returns exploit IDs only (e.g., `"EDB-12345"`) — **no exploit code**.
  - Test output shape: `{exploit_ids: ["EDB-12345"], has_public_exploit: True}`.
- [x] Create synthetic fixture: `tests/fixtures/enrichment/exploitdb_sample.json`.
- [x] Implement `ExploitDBSource` with real `load()` and `lookup()`.
- [x] If `exploit_ids` / `has_public_exploit` are new fields on `EnrichedFinding`, flag the schema change for review.

### 3.5 — Metasploit metadata source (tests first)

- [x] Write `tests/unit/test_metasploit_source.py`:
  - Test loading from local mirror file.
  - Test `lookup(cve_id)` returns module names only (e.g., `"exploit/multi/http/log4shell_header_injection"`) — **names only, hard rule 4**.
  - Test output shape: `{module_names: [...], has_metasploit_module: True}`.
- [x] Create synthetic fixture: `tests/fixtures/enrichment/metasploit_sample.json`.
- [x] Implement `MetasploitSource` with real `load()` and `lookup()`.

### 3.6 — Feed sync for new sources

- [x] Add sync methods for Vulnrichment, EUVD, ExploitDB, Metasploit mirrors to `FeedSyncer`.
- [x] Document upstream URLs and data format for each source.
  - ExploitDB: `files_exploits.csv` from ExploitDB GitLab mirror — verify licence (confirm MIT/BSD; GPL would block this).
  - Metasploit: `modules_metadata_base.json` from Rapid7 GitHub — verify licence (BSD-3).
- [x] Add any new dependency to `THIRD_PARTY.md`.

### Level 3 checklist

- [x] Vulnrichment and EUVD are real, not stubs
- [x] Fallback chain tested end-to-end with per-field provenance check
- [x] ExploitDB/Metasploit return IDs/names only (hard rule 4 satisfied)
- [x] All new fixtures marked synthetic
- [x] New dependency licence-checked and in `THIRD_PARTY.md`
- [x] CI green

---

## Level 4 — NVD-Only Baseline Eval (Layer 2 "Done When")

> **Goal:** Build the eval harness in `evals/` and measure enrichment coverage against an NVD-only baseline. Report only numbers actually measured.
> **Critical rule:** `evals/README.md` says "No number in this project has been measured yet." This level is where that changes for enrichment.
> **PR scope:** `evals/` directory + results.

### 4.1 — Define the coverage metric

Document in `evals/enrichment_coverage.md` (new file):

- **Coverage** = proportion of findings where multi-source fusion provides a non-placeholder value vs NVD-only.
- Measured per field: CVSS, CWE, description, EPSS, KEV status, exploit availability.
- **NVD-only baseline:** enrich the same findings using only `NVDSource`. Count fields with values vs empty/derived.
- **Multi-source result:** enrich with full fusion chain. Count same.
- **Coverage improvement** = `(multi_source_filled - nvd_only_filled) / total_fields_measured`.

- [x] Write metric definition in `evals/enrichment_coverage.md`.

### 4.2 — Build the eval dataset

- [x] Curate ≥ 50 CVE IDs covering:
  - CVEs with full NVD enrichment (control group — NVD baseline has them).
  - CVEs where NVD moved to "Not Scheduled" or "Awaiting Analysis" (the gap CVE.org fills).
  - CVEs in CISA KEV.
  - CVEs with high EPSS but no NVD CVSS.
  - CVEs with ExploitDB / Metasploit entries.
- [x] Store as `evals/golden/enrichment_baseline.json`.
- [x] Mark clearly as curated test inputs, not measured results.

### 4.3 — Implement the eval harness

- [x] Create `evals/enrichment_coverage.py`:
  - Load eval dataset from `evals/golden/enrichment_baseline.json`.
  - Run NVD-only enrichment (restrict source chain to `NVDSource` only via config).
  - Run full multi-source enrichment (all sources loaded from local mirror files).
  - Compare field-by-field: count filled, placeholder, missing.
  - Output a summary table (plaintext + JSON).
- [x] Harness must run fully offline (uses local mirror files, not live APIs).

### 4.4 — Run and report

- [x] Execute harness. Record actual numbers.
- [x] Write results to `evals/results/enrichment_coverage_results.md`:
  - Date measured, dataset size, per-field coverage table, overall coverage improvement.
- [x] **No placeholder numbers.** Per `evals/README.md`: if a result cannot be measured yet (e.g., because a mirror file is not downloaded), say so explicitly. Do not fabricate.

### Level 4 checklist

- [x] Eval harness exists and runs offline
- [x] Results are real (actually run), not estimated
- [x] Results committed to `evals/results/`
- [x] Layer 2 "done when" criterion addressed
- [x] CI green

---

## Level 5 — Dashboard: Enriched Findings UI

> **Goal:** Wire the frontend to the `/findings` API and display enriched findings with ERS component breakdown and per-field provenance.
> **Constraint:** API requires `engagement_id` on all `/findings` calls (logged in DECISIONS.md at Level 1).
> **PR scope:** `apps/web/` only.

### 5.1 — Add findings API calls to `apps/web/lib/api.ts`

- [ ] Add TypeScript interfaces:

```typescript
interface ProvenanceInfo {
  source: string;
  confidence: string;
  retrieved_at: string;
  note?: string;
}

interface AttributedValue<T> {
  value: T;
  provenance: ProvenanceInfo;
}

interface ScoreComponentInfo {
  name: string;
  raw_value: number;
  weight: number;
  weighted_value: number;
  explanation: string;
  provenance: ProvenanceInfo;
}

interface ERSInfo {
  score: number;
  components: ScoreComponentInfo[];
  explanation: string;
}

interface EnrichedFindingItem {
  finding_id: string;
  engagement_id: string;
  cve_id: string;
  cvss: AttributedValue<number> | null;
  epss: AttributedValue<number> | null;
  in_kev: AttributedValue<boolean | null> | null;  // null value = unknown
  cwe_ids: AttributedValue<string[]> | null;
  description: AttributedValue<string> | null;
  ers: ERSInfo | null;
  enriched_at: string;
}

interface EnrichedFindingListResponse {
  items: EnrichedFindingItem[];
  total: number;
  limit: number;
  offset: number;
}
```

- [x] Add API methods to `api` object:
  - `getFinding(findingId: string, engagementId: string)` → `Promise<EnrichedFindingItem>` — calls `GET /findings/{id}?engagement_id=...`
  - `getFindings(engagementId: string, limit?: number, offset?: number)` → `Promise<EnrichedFindingListResponse>` — calls `GET /findings?engagement_id=...`
  - `enrichFindingsBatch(engagementId: string, findings: Finding[])` → batches up to 1000, sends `POST /findings/enrich/batch` with `engagement_id` in body.

### 5.2 — Enriched findings list

- [x] Add findings tab/section to the engagement detail view.
- [x] Display a table of enriched findings for the selected engagement:
  - Columns: CVE ID, CVSS score, EPSS probability, KEV status, ERS score.
  - Default sort: ERS score descending (highest risk first).
  - Color-code ERS severity band: Critical (≥8) / High (≥6) / Medium (≥4) / Low (<4).

### 5.3 — ERS component breakdown

- [x] On finding click/expand:
  - Show ERS score with breakdown: each `ScoreComponent` as a bar or labeled row.
  - Show: component name, raw value, weight, weighted contribution, explanation text.
  - Visually flag `Source.DERIVED` components as estimates ("placeholder, not measured").

### 5.4 — Per-field provenance

- [x] For each enrichment field (CVSS, EPSS, KEV, CWE, description):
  - Show the value.
  - Show provenance badge: source name + confidence level.
  - Tooltip or expandable: `retrieved_at`, `note`.
  - Visual distinction between `Source.CVE_ORG`, `Source.VULNRICHMENT`, `Source.DERIVED`.

### 5.5 — Handle `engagement_id` requirement

- [x] All findings API calls pass `engagement_id` as required parameter.
- [x] If no engagement selected, show prompt to select one first.
- [x] Error handling: engagement not found (404), no enriched findings yet (empty state with explanation).

### Level 5 checklist

- [x] TypeScript interfaces added and typed
- [x] Findings list functional
- [x] ERS component breakdown visible
- [x] Per-field provenance visible
- [x] `engagement_id` wired through all calls
- [x] CI green

---

## Status summary

| Level | Description | Status | PR |
|-------|-------------|--------|----|
| **1** | Decisions & ERS Analysis | ✅ Done (2026-10-05) — see [walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level1_of_level2_second_part.md) | D-027–D-032 in DECISIONS.md |
| **2** | Feed Sync Job | ✅ Done (2026-10-05) — see [walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_of_level2_second_part.md) | D-033; FeedSyncer + Celery Beat + CLI |
| **3** | Real Source Implementations | ✅ Done (2026-10-05) — see [walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level3_of_level2_second_part.md) | D-034; VulnrichmentSource + EUVDSource + ExploitDBSource + MetasploitSource + FeedSyncer secondary sync |
| **4** | NVD-Only Baseline Eval | ✅ Done (2026-10-05) — see [walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level4_of_level2_second_part.md) | D-035; metric spec + golden dataset + offline harness + results |
| **5** | Dashboard: Enriched Findings UI | ✅ Done (2026-10-05) — see [walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level5_of_level2_second_part.md) | EnrichedFindingsView + api.ts + ERS breakdown + field provenance |

---

## Dependency graph

```
Level 1 (Decisions) ──────────► Level 2 (Feed Sync) ──► Level 3 (Real Sources)
                                                                 │
                                                                 ▼
                                                         Level 4 (Eval) ← Layer 2 "Done When"
                                                                 │
Level 5 (Dashboard) ◄────────────────────────────────────────────
  (can start after Level 3, or earlier with fixture data)
```

- **Level 1** has no code dependencies — settle design questions first.
- **Level 2** can run alongside Level 1 once URLs are confirmed.
- **Level 3** depends on Level 2 (sync provides the mirror files sources read).
- **Level 4** depends on Level 3 (real sources needed to measure real coverage).
- **Level 5** depends on Level 3 (needs enriched findings in DB), but can be developed with fixture data earlier.

---

## Key constraints (always active)

| Constraint | Source |
|---|---|
| No network calls on the request path | `services/enrichment/README.md` rule 5 |
| ExploitDB/Metasploit: IDs/names only, no execution | `CLAUDE.md` hard rule 4 |
| No AGPL/GPL code copied | `CLAUDE.md` hard rule 3 |
| Every new dependency → `THIRD_PARTY.md` | `CLAUDE.md` |
| Never report a metric not actually measured | `evals/README.md` |
| Tests first | User instruction |

---

_Last updated: 2026-10-05_
