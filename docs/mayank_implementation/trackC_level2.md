# Track C Implementation: CI Automation, API Resilience & Schema Single Source of Truth

**Branch:** `mayank_level2_working`  
**Base Commit:** `a82986f` (PR #19 merged), following review fix `48d5f2b`  
**Owner:** Mayank (Layer 2 Owner)  
**Status:** Completed  
**Compliance Standard:** CLAUDE.md Non-Negotiables & DECISIONS.md D-040  

---

## 1. Executive Summary & Objective

Track C addresses CI test coverage, production read-path resilience, and cross-stack schema synchronization:
1. **Frontend CI Pipeline (C-1):** Frontend tests (`node --test`) previously were not executed in GitHub Actions CI. Track C adds a dedicated `frontend-tests` job using Node 22+ to `.github/workflows/ci.yml`.
2. **API Resilience Against Corrupted Legacy CVE IDs (C-2):** Strict ASCII CVE regex validation introduced in **D-040** caused `EnrichedFindingModel.to_schema()` to raise uncaught `ValidationError`s on legacy rows, returning a 500 server error that took down the entire paginated findings view. Track C hardens the read path in [EnrichedFindingRepository](file:///e:/SeekThreat/SeekThreat/apps/api/db/repositories.py) and [findings.py](file:///e:/SeekThreat/SeekThreat/apps/api/routers/findings.py) to skip malformed rows with structured warnings, returns 422 for single-row lookups, and provides a database repair utility [cleanup_malformed_cve_ids.py](file:///e:/SeekThreat/SeekThreat/scripts/cleanup_malformed_cve_ids.py).
3. **Single Source of Truth for `Source` Enum (C-3):** Eliminates triple maintenance of the intelligence `Source` enum across Python, regex parsing in tests, and JavaScript/TypeScript arrays. Generates [packages/schema/sources.json](file:///e:/SeekThreat/SeekThreat/packages/schema/sources.json) via [scripts/generate_source_enum.py](file:///e:/SeekThreat/SeekThreat/scripts/generate_source_enum.py), validates both frontend and backend tests against it, and enforces sync in CI.

---

## 2. Progress Tracker

| Task | Component | Priority | Status | Verification Method | Primary Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C-1** | Frontend CI Job | 🔴 High | ✅ Completed | GitHub Actions YAML validation & local test run | Added `frontend-tests` job using `actions/setup-node@v4` (Node 22) running `npm --prefix apps/web test`. |
| **C-2** | 500 Prevention on Malformed CVE IDs | 🔴 High | ✅ Completed | Unit tests (`test_findings_resilience.py`) | Hardened `EnrichedFindingRepository.get_by_engagement` with `skip_invalid=True` and structured warnings; `GET /findings` returns 200; created `cleanup_malformed_cve_ids.py`. |
| **C-3** | Single Source of Truth for `Source` Enum | 🟡 Medium | ✅ Completed | Unit tests (`test_provenance.py`), frontend tests, CI check | Created `scripts/generate_source_enum.py`, generated canonical `packages/schema/sources.json`, refactored `findings.test.mjs` and `test_provenance.py`, added CI check step. |

---

## 3. Task C-1: Frontend CI Pipeline

### Implementation Details
- **File touched:** [.github/workflows/ci.yml](file:///e:/SeekThreat/SeekThreat/.github/workflows/ci.yml)
- **Job Definition:**
  ```yaml
    frontend-tests:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4

        - uses: actions/setup-node@v4
          with:
            node-version: "22"
            cache: npm
            cache-dependency-path: apps/web/package-lock.json

        - name: Install dependencies
          run: npm --prefix apps/web ci

        - name: Frontend tests
          run: npm --prefix apps/web test
  ```
- **Local Validation:** Executed `npm --prefix apps/web test` — **23 suites / 23 tests passed** with Node 22 native test runner.

---

## 4. Task C-2: Prevent 500 Error on `GET /findings` from Malformed Legacy CVE IDs

### Problem Statement
In **D-040**, a strict validator was added to `Finding`:
```python
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
```
Legacy database rows created prior to D-040 (or contaminated through external data ingestion) might have whitespace, lowercase, null bytes, or malformed ID strings. When `GET /findings` iterated over database models, `m.to_schema()` raised an unhandled `ValidationError`, crashing the entire page request with HTTP 500 Internal Server Error.

### Architectural Fixes
1. **Repository Read Path Hardening ([apps/api/db/repositories.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/repositories.py)):**
   - Added `skip_invalid: bool = True` to `EnrichedFindingRepository.get_by_engagement()`.
   - Any row failing Pydantic `to_schema()` is caught and logged as a structured warning:
     ```python
     logger.warning(
         "Skipping malformed enriched finding row in engagement %s (finding_id=%s): %s",
         engagement_id,
         m.finding_id,
         exc,
         extra={"engagement_id": engagement_id, "finding_id": m.finding_id, "error": str(exc)},
     )
     ```
   - Valid rows on the page are returned normally (HTTP 200), preventing an isolated corrupted row from taking down the interface.
2. **Single Finding Endpoint Hardening ([apps/api/routers/findings.py](file:///e:/SeekThreat/SeekThreat/apps/api/routers/findings.py)):**
   - In `get_enriched_finding`, caught `(ValidationError, ValueError)` during `repo.get()`.
   - Returns a structured HTTP 422 Unprocessable Entity describing the malformed record instead of an unhandled 500 crash.
3. **Database Remediation Script ([scripts/cleanup_malformed_cve_ids.py](file:///e:/SeekThreat/SeekThreat/scripts/cleanup_malformed_cve_ids.py)):**
   - Scans `EnrichedFindingModel` rows.
   - Cleans salvageable CVE IDs (`\x00` removal, trimming, uppercasing).
   - Drops invalid identifiers that cannot be parsed.
   - Supports `--dry-run` (default) and `--apply` flags, and `--engagement-id` filter.
4. **Unit Tests ([tests/unit/test_findings_resilience.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_findings_resilience.py)):**
   - `test_get_findings_skips_malformed_cve_id_without_500`: verifies 200 OK and proper omission.
   - `test_get_single_malformed_finding_returns_422_not_500`: verifies 422 Unprocessable Entity.
   - `test_repo_get_by_engagement_respects_skip_invalid_flag`: verifies explicit opt-out behavior.
   - `test_cleanup_script_normalizes_and_drops`: verifies dry-run and commit flows for dirty data.

---

## 5. Task C-3: Single Source of Truth for `Source` Enum

### Problem Statement
The canonical intelligence `Source` enumeration was previously maintained in multiple disconnected places:
- Backend enum: [packages/schema/models/provenance.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py)
- Python test: regex-parsed TypeScript in `test_provenance.py`
- Frontend tests: hardcoded JS array in `findings.test.mjs`

### Implementation
1. **Generation Script ([scripts/generate_source_enum.py](file:///e:/SeekThreat/SeekThreat/scripts/generate_source_enum.py)):**
   - Directly imports `Source` enum from `packages.schema.models.provenance`.
   - Generates [packages/schema/sources.json](file:///e:/SeekThreat/SeekThreat/packages/schema/sources.json).
   - Provides `--check` flag that exits with code 1 if `sources.json` has drifted from the Python enum.
2. **Canonical JSON Specification ([packages/schema/sources.json](file:///e:/SeekThreat/SeekThreat/packages/schema/sources.json)):**
   ```json
   {
     "$schema": "http://json-schema.org/draft-07/schema#",
     "title": "SeekThreat Intelligence and Provenance Sources",
     "description": "Canonical list of intelligence and provenance sources derived from packages.schema.models.provenance.Source.",
     "sources": [
       "cve.org",
       "cisa.vulnrichment",
       "cisa.kev",
       "first.epss",
       "nvd",
       "enisa.euvd",
       "osv.dev",
       "github.advisories",
       "exploitdb",
       "metasploit",
       "bron",
       "derived",
       "scanner"
     ]
   }
   ```
3. **Consumer Refactoring:**
   - [tests/unit/test_provenance.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_provenance.py): Asserts exact parity between `Source` enum, `sources.json`, and frontend `PROVENANCE_SOURCES`.
   - [apps/web/tests/findings.test.mjs](file:///e:/SeekThreat/SeekThreat/apps/web/tests/findings.test.mjs): Loads `sources.json` directly via `node:fs` and asserts UI `PROVENANCE_SOURCES` matches the canonical sources list without hardcoding.
4. **CI Enforcement ([.github/workflows/ci.yml](file:///e:/SeekThreat/SeekThreat/.github/workflows/ci.yml)):**
   - Added step: `python scripts/generate_source_enum.py --check` in the CI `check` job.

---

## 6. Verification & Test Suite Status

### Unit & API Tests
```bash
python -m pytest tests/unit/test_findings_resilience.py tests/unit/test_provenance.py tests/unit/test_findings_api.py -v
```
**Results:**
- `test_findings_resilience.py`: 5 passed
- `test_provenance.py`: 7 passed
- `test_findings_api.py`: 23 passed
- **Total:** **35 passed in 11.10s**

### Architecture Guards
```bash
python -m pytest tests/architecture -v
```
**Results:**
- **11 passed in 1.45s** (Authorization gate & import firewall intact).

### Frontend Test Suite
```bash
npm --prefix apps/web test
```
**Results:**
- **23 passed in 788ms** (all suites passing against `sources.json`).

### Source Consistency Check
```bash
python scripts/generate_source_enum.py --check
```
**Results:**
- `OK: packages/schema/sources.json is up to date with backend Source enum.`
