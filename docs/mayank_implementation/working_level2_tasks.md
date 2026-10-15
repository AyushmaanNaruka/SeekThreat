# Working Level 2 Tasks — Post-PR #19 Review

**Context:** PR #19 merged as `a82986f`. Fix commit `48d5f2b` (2026-10-12) applied the reviewer's corrections: reinterpreted coverage numbers, relabelled ERS validation as smoke-level, deterministic tie rule, D-038/D-039/D-040/D-041 added/corrected. This file tracks the *open* follow-up work the review left behind.

**Branch convention:** one branch per PR, one PR per concern (CLAUDE.md).  
**Evidence rule:** every number must come from code you ran. Never write "verified" without a URL, a timestamp, and the value you observed.  
**D-039 is blocked** — leave graph-formula changes alone until Ayushmaan signs off.

---

## Track A — Real Measurement (Top Priority; Viva Defense Focus)

### Task A-1: Write a reproducible CVE selection rule and generate `eval_cve_list.txt`

**Why:** The current 50 CVEs were hand-picked famous CVEs. Any result on this set describes this set, not CVEs in general (documented in [evals/golden/README.md](file:///e:/SeekThreat/SeekThreat/evals/golden/README.md)). The viva question is "how did you pick these CVEs?" — "famous ones I knew" is not a defensible answer.

**What to do:**
1. **Write the selection rule in [evals/golden/README.md](file:///e:/SeekThreat/SeekThreat/evals/golden/README.md)**:
   - Stratified random sample: e.g., stratified by EPSS decile bins + KEV catalog + non-KEV control stratum (EPSS < 0.01 and not in KEV).
   - Fixed random seed (e.g., `SEED = 20261011`) for exact reproducibility.
   - Target $n \ge 50$.
   - Must be mechanically verifiable against local mirror files without live network calls.
2. **Implement selection generator script**:
   - Create `evals/scripts/generate_eval_cve_list.py`.
   - Reads local KEV mirror (`cisa_kev.json`) and EPSS mirror (`epss.csv` or `.csv.gz`).
   - Applies the stratified selection rule deterministically with fixed seed.
   - Outputs:
     - `evals/golden/eval_cve_list.txt` (sorted CVE IDs, one per line).
     - `evals/golden/eval_cve_selection_manifest.json` (mirror sha256s, synced_at, seed, strata counts, stratum mapping).
3. **Rebuild [evals/golden/enrichment_baseline.json](file:///e:/SeekThreat/SeekThreat/evals/golden/enrichment_baseline.json)**:
   - One entry per selected CVE.
   - Drop or rename cohorts B (`nvd_gap`) and D (`high_epss_no_nvd`) as NVD had CVSS for all of them in measured data.
   - Replace cohort names with real selection strata names (e.g., `epss_decile_9`, `non_kev_control`).
4. **Add unit test**:
   - Add `tests/unit/test_eval_cve_selection.py` validating deterministic output, manifest presence, and consistency with `eval_cve_list.txt`.

**Files touched:**
- [evals/golden/README.md](file:///e:/SeekThreat/SeekThreat/evals/golden/README.md)
- `evals/scripts/generate_eval_cve_list.py` (new)
- `evals/golden/eval_cve_list.txt`
- `evals/golden/eval_cve_selection_manifest.json` (new)
- [evals/golden/enrichment_baseline.json](file:///e:/SeekThreat/SeekThreat/evals/golden/enrichment_baseline.json)
- `tests/unit/test_eval_cve_selection.py` (new)

---

### Task A-2: Replace batch `verified_by` stamps with per-CVE evidence records

**Why:** Batch stamps (`verified_by: Mayank Narang` / `verified_at: 2026-10-11`) lack specific evidence. Viva examiner will ask for ground truth verification proof per CVE. Also, `CVE-2022-22965` is in KEV mirror but not flagged in `enrichment_baseline.json`.

**What to do:**
1. **Define per-CVE evidence block**:
   - In [evals/golden/enrichment_baseline.json](file:///e:/SeekThreat/SeekThreat/evals/golden/enrichment_baseline.json), add per-CVE evidence:
     - Checked URL / mirror entry
     - NVD CVSS present (score & vector)
     - KEV listed (true/false)
     - EUVD present (true/false/null)
     - Retrieval timestamp & observed values
2. **Fix `CVE-2022-22965`**:
   - Mark as KEV in `authoritative_source` and provide the KEV entry evidence.
3. **Add unit tests**:
   - In `tests/unit/test_golden_evidence.py`, assert every entry has complete evidence and `CVE-2022-22965` has `in_kev: true`.

**Files touched:**
- [evals/golden/enrichment_baseline.json](file:///e:/SeekThreat/SeekThreat/evals/golden/enrichment_baseline.json)
- [evals/golden/README.md](file:///e:/SeekThreat/SeekThreat/evals/golden/README.md)
- `tests/unit/test_golden_evidence.py` (new)

---

### Task A-3: Fair NVD-only baseline: parse KEV fields from NVD 2.0 API

**Why:** NVD 2.0 API records carry CISA KEV fields (`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`). `NVDSource` did not parse them, unfairly penalizing the NVD baseline and falsely attributing KEV detection solely to fusion gain (D-035).

**What to do:**
1. **Update `NVDSource` parser**:
   - Parse `cisaExploitAdd` and related fields into finding attributes.
   - Set `in_kev = True` with `Source.NVD` when present.
2. **Update baseline engine in [evals/enrichment_coverage.py](file:///e:/SeekThreat/SeekThreat/evals/enrichment_coverage.py)**:
   - Credit the baseline engine for KEV if NVD supplies `cisaExploitAdd`.
   - Separate EPSS reporting: report EPSS as "not available from NVD" rather than conflating it with multi-source CVSS/CWE fusion gain.
3. **Add unit test**:
   - `tests/unit/test_nvd_kev_parsing.py` verifying NVD parsing of KEV fields and handling of empty fields.

**Files touched:**
- [services/enrichment/sources/nvd.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/nvd.py) (or `services/enrichment/sources/base.py`)
- [evals/enrichment_coverage.py](file:///e:/SeekThreat/SeekThreat/evals/enrichment_coverage.py)
- `tests/unit/test_nvd_kev_parsing.py` (new)

---

### Task A-4: Re-run `enrichment_coverage.py` and `ers_validation.py` on fresh mirrors

**Why:** Pre-review results were based on old harness logic. Commit `48d5f2b` introduced deterministic ties, safe paths, and random baselines, but the real benchmark numbers must be regenerated on fresh mirrors with full auditability.

**What to do:**
1. **Sync mirrors** for the regenerated `eval_cve_list.txt`.
2. **Generate mirror manifest**:
   - Save `evals/results/mirror_manifest_<date>.json` with sha256 hashes, `synced_at`, record counts for each `.meta.json`.
3. **Execute coverage & validation runs**:
   - `python evals/enrichment_coverage.py ...`
   - `python evals/ers_validation.py ...`
4. **Commit raw results & markdown reports**:
   - Include the "excluding-EPSS" line and report exact figures honestly (e.g. "+0 pp for CVSS" if that is what emerges).

**Files touched:**
- `evals/results/mirror_manifest_*.json` (new)
- `evals/results/enrichment_coverage_results.json`
- `evals/results/enrichment_coverage_real.md`
- `evals/results/ers_validation_results.json`
- `evals/results/ers_validation_results.md`

---

### Task A-5: Full-ranking ERS validation metric (Average Precision / AUC with bootstrap CI)

**Why:** Evaluating top-5/10/15 precision on $n=50$ is dominated by single-CVE noise ($\pm 20$ pp per CVE). A metric over the full ranking (Average Precision / AUC-ROC with bootstrap confidence intervals) is statistically sound.

**What to do:**
1. **Add ranking metrics** to [evals/ers_validation.py](file:///e:/SeekThreat/SeekThreat/evals/ers_validation.py):
   - Average Precision (AP) across entire ranked list.
   - Area Under ROC Curve (AUC-ROC).
   - Non-parametric bootstrap resampling ($N = 1000$) to produce 95% Confidence Intervals (`[p_2.5, p_97.5]`).
2. **Update report formats**:
   - Display AP and AUC-ROC with CI as primary metric, keeping top-k as secondary illustration.
3. **Add unit test**:
   - In `tests/unit/test_ers_validation.py`, verify metric calculations and bootstrap intervals against known synthetic rankings.

**Files touched:**
- [evals/ers_validation.py](file:///e:/SeekThreat/SeekThreat/evals/ers_validation.py)
- [tests/unit/test_ers_validation.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_ers_validation.py)

---

## Track B — Feed Freshness and Health

### Task B-1: Staleness policy: lower confidence on negative assertions from stale mirrors

**Why:** D-030 risk: a mirror that hasn't synced in 30 days confidently asserting `in_kev = False` is dangerous. Stale mirrors must downgrade negative assertions.

**What to do:**
1. **Add config**:
   - `MIRROR_STALENESS_THRESHOLD_DAYS: int = 7` (configurable in [apps/api/core/config.py](file:///e:/SeekThreat/SeekThreat/apps/api/core/config.py)).
2. **Implement staleness downgrade in `BaseEnrichmentSource` / `FusionEngine`**:
   - If mirror age > threshold, negative results (`in_kev = False`, `has_public_exploit = False`) return `Confidence.MEDIUM` (or `LOW`) with explicit provenance note: `Mirror stale (X days old); negative result confidence reduced`.
   - Positive hits remain `Confidence.HIGH`.
   - Log staleness event via structured logging.
3. **Add unit tests**:
   - `tests/unit/test_mirror_staleness.py` testing fresh vs stale mirror confidence and provenance outputs.

**Files touched:**
- [apps/api/core/config.py](file:///e:/SeekThreat/SeekThreat/apps/api/core/config.py)
- [services/enrichment/sources/base.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/base.py)
- [services/enrichment/sources/cisa_kev.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/cisa_kev.py)
- [services/enrichment/sources/secondary.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/secondary.py)
- `tests/unit/test_mirror_staleness.py` (new)

---

### Task B-2: Add `GET /feeds/status` API endpoint

**Why:** Visibility into feed sync health, sha256 hashes, record counts, staleness, and negative cache sizes.

**What to do:**
1. **Create router [apps/api/routers/feeds.py](file:///e:/SeekThreat/SeekThreat/apps/api/routers/feeds.py)**:
   - Audit event logged on access (`feeds_status_read`).
   - For each of the 8 sources, read `.meta.json` sidecar and `.notfound.json` cache.
   - Fields: `name`, `synced_at`, `record_count`, `sha256`, `last_sync_result`, `is_stale`, `not_found_cache_size`.
   - If no sidecar, return `synced_at: null`, `last_sync_result: "never"` without fabricating numbers.
2. **Register route** in [apps/api/main.py](file:///e:/SeekThreat/SeekThreat/apps/api/main.py).
3. **Add unit tests**:
   - `tests/unit/test_feeds_status.py` verifying status reporting with and without sidecars/negative caches.

**Files touched:**
- `apps/api/routers/feeds.py` (new)
- [apps/api/main.py](file:///e:/SeekThreat/SeekThreat/apps/api/main.py)
- `tests/unit/test_feeds_status.py` (new)

---

### Task B-3: Add Feed Health panel to Dashboard

**Why:** Reviewer requires feed visibility in web UI with no fabricated data.

**What to do:**
1. **Create `apps/web/components/FeedHealthPanel.tsx`**:
   - Queries `GET /feeds/status`.
   - Displays mirror freshness, last sync date, record count, and stale/healthy badges.
   - Displays "Never synced" badge if `synced_at` is null.
2. **Integrate panel into dashboard**:
   - Add to `apps/web/app/dashboard/page.tsx`.

**Files touched:**
- `apps/web/components/FeedHealthPanel.tsx` (new)
- `apps/web/app/dashboard/page.tsx`

---

### Task B-4: Check and implement 02:00 beat sync re-enrichment

**Why:** Verify if daily beat sync triggers re-enrichment of findings whose CVEs received fresh records, matching the post-scan behavior from D-041.

**What to do:**
1. **Inspect `apps/api/tasks/sync_feeds.py`**:
   - Check if findings referencing updated CVEs are re-enriched.
2. **Implement engagement-scoped re-enrichment**:
   - If missing, trigger re-enrichment strictly scoped per engagement for CVEs updated during beat sync.
   - Keyset-paged, capped, and audited (`actor="system:celery_beat"`, target=`engagement:<id>/beat_sync`).
3. **Add unit tests**:
   - `tests/unit/test_beat_sync_reenrichment.py` verifying re-enrichment triggers and engagement isolation.

**Files touched:**
- [apps/api/tasks/sync_feeds.py](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/sync_feeds.py)
- `tests/unit/test_beat_sync_reenrichment.py` (new)

---

## Track C — CI and Robustness

### Task C-1: Add Frontend tests job to CI workflow (✅ Completed — see [trackC_level2.md](trackC_level2.md))

**Why:** Frontend tests (`npm --prefix apps/web test`) currently do not run in CI. Node 22+ is required for native TypeScript type-stripping in `node --test`.

**What was done:**
- Updated [.github/workflows/ci.yml](file:///e:/SeekThreat/SeekThreat/.github/workflows/ci.yml) with a `frontend-tests` job using Node 22.
- Verified locally with Node 22 (23/23 tests pass).

---

### Task C-2: Prevent 500 error on `GET /findings` from malformed legacy CVE IDs (✅ Completed — see [trackC_level2.md](trackC_level2.md))

**Why:** `EnrichedFindingModel.to_schema()` raises on malformed `cve_id` (ASCII regex check in D-040). If a single legacy row has an invalid ID, `GET /findings` returns a 500 server error for the entire page.

**What was done:**
1. Hardened read path:
   - In [apps/api/db/repositories.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/repositories.py), added `skip_invalid=True` in `get_by_engagement()` with structured warning logging.
   - In [apps/api/routers/findings.py](file:///e:/SeekThreat/SeekThreat/apps/api/routers/findings.py), handled `ValidationError` in `get_enriched_finding` to return 422 Unprocessable Entity instead of 500.
2. Created database remediation script [scripts/cleanup_malformed_cve_ids.py](file:///e:/SeekThreat/SeekThreat/scripts/cleanup_malformed_cve_ids.py).
3. Created unit tests in [tests/unit/test_findings_resilience.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_findings_resilience.py) (5/5 passed).

---

### Task C-3: Single Source of Truth for `Source` Enum: Generate shared JSON (✅ Completed — see [trackC_level2.md](trackC_level2.md))

**Why:** `Source` enum is currently duplicated in Python, regex-parsed in `test_provenance.py`, and hardcoded again in `findings.test.mjs`.

**What was done:**
1. Created [scripts/generate_source_enum.py](file:///e:/SeekThreat/SeekThreat/scripts/generate_source_enum.py) generating canonical [packages/schema/sources.json](file:///e:/SeekThreat/SeekThreat/packages/schema/sources.json).
2. Refactored consumers:
   - [tests/unit/test_provenance.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_provenance.py) asserts against `sources.json`.
   - [apps/web/tests/findings.test.mjs](file:///e:/SeekThreat/SeekThreat/apps/web/tests/findings.test.mjs) imports and asserts against `sources.json`.
3. Added CI check in [.github/workflows/ci.yml](file:///e:/SeekThreat/SeekThreat/.github/workflows/ci.yml) (`python scripts/generate_source_enum.py --check`).

---

## Track D — Licences (Human Verification Required — Hard Rule 3)

> [!IMPORTANT]
> Must be personally verified by visiting official URLs and recording exact terms and access dates.

### Task D-1: Verify NVD Terms of Use
- **URL**: https://nvd.nist.gov/developers/terms-of-use
- Record in [THIRD_PARTY.md](file:///e:/SeekThreat/SeekThreat/THIRD_PARTY.md): exact licence/terms, attribution requirements, commercial restrictions, check date.

### Task D-2: Verify CVE.org Terms of Use
- **URL**: https://www.cve.org/Legal/TermsOfUse
- Record in [THIRD_PARTY.md](file:///e:/SeekThreat/SeekThreat/THIRD_PARTY.md): licence type (CC BY or custom), restrictions, check date.

### Task D-3: Verify EUVD Terms and Legal Notice
- **URL**: https://euvd.enisa.europa.eu and https://www.enisa.europa.eu/legal-notice
- Confirm whether a specific data license exists. If not, record the legal notice terms and retain `TO VERIFY` status in [THIRD_PARTY.md](file:///e:/SeekThreat/SeekThreat/THIRD_PARTY.md).

### Task D-4: Confirm EUVD `/api/vulnerability` Endpoint Status
- Test `GET https://euvdservices.enisa.europa.eu/api/vulnerability?id=CVE-2021-44228` vs `GET https://euvdservices.enisa.europa.eu/api/search?text=CVE-2021-44228`.
- Record HTTP status code, response snippet, and behavior in [THIRD_PARTY.md](file:///e:/SeekThreat/SeekThreat/THIRD_PARTY.md) and [services/enrichment/sources/sync.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/sync.py).

---

## Task Matrix & Recommended Execution Order

| Task | Track | Priority | Dependencies / Prerequisite |
| :--- | :--- | :--- | :--- |
| **D-1..D-4** | Licences | 🔴 High | None (Human verification) |
| **C-1** | CI | 🔴 High | None |
| **C-2** | CI / Robustness | 🔴 High | None |
| **A-1** | Measurement | 🔴 High | None |
| **A-3** | Measurement | 🔴 High | None |
| **A-2** | Measurement | 🔴 High | After A-1 |
| **B-1** | Feed Health | 🟡 Medium | None |
| **B-2** | Feed Health | 🟡 Medium | None |
| **B-3** | Feed Health | 🟢 Low | After B-2 |
| **B-4** | Feed Health | 🟡 Medium | None |
| **A-4** | Measurement | 🔴 High | After A-1, A-2, A-3 |
| **A-5** | Measurement | 🟡 Medium | In parallel / after A-4 |
| **C-3** | CI / Robustness | 🟡 Medium | None |
