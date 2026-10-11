# Task 7 Implementation: Frontend Contract Hardening & Cleanup

> **Document:** `docs/mayank_implementation/task7_level2_work.md`  
> **Topic:** Task 7 of `docs/mayank_implementation/mayank_task_level2.md` (PR 8: `fix/web-findings-contract`)  
> **Author:** Mayank Narang (Layer 2 Owner)  
> **Status:** ✅ Complete  

---

## 1. Executive Summary

In SeekThreat's full-stack architecture, Layer 2 (`services/enrichment`) provides multi-source vulnerability intelligence (CVSS, EPSS, CISA KEV, ExploitDB, Metasploit, EUVD, NVD, CVE.org, Vulnrichment) and Exposure Risk Scores (ERS) to the web UI (`apps/web`).

`apps/web/lib/findings.ts` strictly validates finding intelligence received from the FastAPI backend (`packages/schema/models/finding.py` and `packages/schema/models/provenance.py`). The frontend enforces an explicit whitelist of sources (`PROVENANCE_SOURCES`) and throws a runtime error if an unlisted source appears, rather than inventing or silently swallowing provenance.

### Task 7 Objectives:
1. **Source Enum Parity & Lock:** Verify 100% parity between backend `packages.schema.models.provenance.Source` and frontend `PROVENANCE_SOURCES`, establishing bi-directional automated contract tests so they cannot silently drift.
2. **API Client Audit:** Audit `enrichFindingsBatch` in `apps/web/lib/api.ts` against the backend FastAPI router (`apps/api/routers/findings.py`), harden its response interface, and document its architectural role.
3. **Module & Test Hygiene:** Eliminate typeless package JSON warnings emitted during test runs and ensure clean TypeScript and Node test execution (`npm test`).

---

## 2. Provenance Contract Parity & Automated Lock

### A. Parity Analysis

| Canonical Source Key | Backend Enum (`packages.schema.models.provenance.Source`) | Frontend Whitelist (`apps/web/lib/findings.ts`) | Status |
| :--- | :--- | :--- | :--- |
| `cve.org` | `Source.CVE_ORG` | `"cve.org"` | ✅ In Sync |
| `cisa.vulnrichment` | `Source.VULNRICHMENT` | `"cisa.vulnrichment"` | ✅ In Sync |
| `cisa.kev` | `Source.KEV` | `"cisa.kev"` | ✅ In Sync |
| `first.epss` | `Source.EPSS` | `"first.epss"` | ✅ In Sync |
| `nvd` | `Source.NVD` | `"nvd"` | ✅ In Sync |
| `enisa.euvd` | `Source.EUVD` | `"enisa.euvd"` | ✅ In Sync |
| `osv.dev` | `Source.OSV` | `"osv.dev"` | ✅ In Sync |
| `github.advisories` | `Source.GHSA` | `"github.advisories"` | ✅ In Sync |
| `exploitdb` | `Source.EXPLOITDB` | `"exploitdb"` | ✅ In Sync |
| `metasploit` | `Source.METASPLOIT` | `"metasploit"` | ✅ In Sync |
| `bron` | `Source.BRON` | `"bron"` | ✅ In Sync |
| `derived` | `Source.DERIVED` | `"derived"` | ✅ In Sync |
| `scanner` | `Source.SCANNER` | `"scanner"` | ✅ In Sync |

**Confidence Levels:**
- Backend: `Confidence.HIGH = "high"`, `Confidence.MEDIUM = "medium"`, `Confidence.LOW = "low"`
- Frontend: `CONFIDENCE_LEVELS = ["high", "medium", "low"]`
- Status: ✅ 100% in sync.

### B. Bi-Directional Automated Contract Tests

To guarantee that any future change in backend sources or frontend types immediately breaks CI if not mirrored:

1. **Backend Python Test (`tests/unit/test_provenance.py`)**:
   - `test_provenance_sources_match_frontend_contract`: Parses `apps/web/lib/findings.ts` via regex, extracts `PROVENANCE_SOURCES`, and asserts set equality against `Source` enum values.
   - `test_confidence_levels_match_frontend_contract`: Asserts set equality between `Confidence` enum values and frontend `CONFIDENCE_LEVELS`.

2. **Frontend TypeScript Test (`apps/web/tests/findings.test.mjs`)**:
   - `enforces exact parity with backend packages.schema.models.provenance.Source`: Asserts all 13 canonical sources exist with 0 duplicates.
   - `enforces confidence levels contract`: Verifies `["high", "low", "medium"]`.
   - `normalizes every valid source without throwing`: Validates `normalizeProvenance` for all 13 sources.
   - `rejects unauthorized sources and malformed confidence`: Verifies rejection of unknown sources.

---

## 3. API Client Audit & Hardening (`apps/web/lib/api.ts`)

### Findings:
- The backend exposes `POST /findings/enrich/batch` (`apps/api/routers/findings.py`) returning `BatchEnrichResponse(status, count, finding_ids, items)`.
- `apps/web/lib/api.ts` included `enrichFindingsBatch`, which omitted `finding_ids` and did not expose the backend's `async_dispatch` option.

### Changes Implemented:
1. **Response Interface Updated:**
   ```typescript
   export interface BatchEnrichResult {
     status: string;
     count: number;
     finding_ids?: string[];
     items?: EnrichedFindingItem[];
   }
   ```
2. **Method Signature & Documentation Hardening:**
   ```typescript
   /**
    * POST /findings/enrich/batch
    *
    * Submits a batch of findings (up to 1000) for synchronous or asynchronous enrichment
    * against the backend findings router (`apps/api/routers/findings.py`).
    *
    * In standard SeekThreat workflows, findings enrichment is automatically triggered
    * post-scan via Celery (`seekthreat.enrichment.sync_new_findings_cves`). This client
    * method preserves API contract parity for direct batch enrichment operations,
    * script-driven re-enrichments, and future batch UI workflows.
    */
   async enrichFindingsBatch(
     engagementId: string,
     findings: Record<string, unknown>[],
     asyncDispatch = false
   ): Promise<BatchEnrichResult>
   ```

---

## 4. Node.js Test Warning Elimination

### Issue:
During `npm test`, Node emitted:
```
(node:...) [MODULE_TYPELESS_PACKAGE_JSON] Warning: Module type of file:///.../apps/web/lib/findings.ts is not specified and it doesn't parse as CommonJS.
```
### Fix:
Added `"type": "module"` to `apps/web/package.json`.
- Eliminates the module reparsing warning completely.
- Fully compatible with Next.js 16, TypeScript 5, and Node test runner.

---

## 5. Verification & Test Results

```
> web@0.1.0 test
> node --test tests/polling.test.mjs tests/findings.test.mjs

ℹ tests 23
ℹ suites 5
ℹ pass 23
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 1016.8906
```

- **Frontend Tests (`npm test`):** 23/23 tests passing with **0 warnings** and **0 failures**.
- **TypeScript Typecheck (`tsc --noEmit`):** 0 errors.
- **Backend Tests (`pytest tests/unit/test_provenance.py`):** 7/7 tests passing.
- **Python Quality Checks:** `ruff check` and `ruff format --check` clean.
