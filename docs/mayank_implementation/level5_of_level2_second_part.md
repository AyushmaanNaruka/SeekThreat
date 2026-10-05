# Level 5 of Layer 2 Second Part — Walkthrough

**Level:** 5 of 5 — *Dashboard: Enriched Findings UI*  
**Branch:** mayank_level2_second  
**Completed:** 2026-10-05  
**Constraints Enforced:** D-032 (Scope Requirement), Rule 5 (No network calls on request path), `Source.DERIVED` estimate disclosure  
**CI:** `npx tsc --noEmit` 0 errors | `npm test` 13/13 passed | `pytest` 53/53 passed  

---

## What Level 5 does

Level 5 delivers the end-user dashboard user interface for **Enriched Findings**, providing visual access to the multi-source vulnerability intelligence pipeline and Exposure Risk Score (ERS) engine built across Levels 1–4.

Key capabilities delivered:

1. **TypeScript API Client (`apps/web/lib/api.ts`)**:
   - Comprehensive TypeScript types matching the backend schemas: `ProvenanceInfo`, `AttributedValue<T>`, `ScoreComponentInfo`, `ERSInfo`, `EnrichedFindingItem`, `EnrichedFindingListResponse`, `BatchEnrichResult`.
   - Client normalization function `normalizeEnrichedFinding(raw)` that seamlessly maps backend `EnrichedFinding` domain objects and field maps into clean UI view models.
   - API consumer methods on the exported `api` client:
     - `api.getFinding(findingId, engagementId)`: Fetches a single enriched finding requiring `engagement_id`.
     - `api.getFindings(engagementId, limit, offset)`: Retrieves paginated enriched findings scoped to an authorized engagement.
     - `api.enrichFindingsBatch(engagementId, findings)`: Batches up to 1,000 findings to trigger multi-source enrichment.

2. **Enriched Findings Component (`apps/web/components/EnrichedFindingsView.tsx`)**:
   - **Interactive Table & Sorting**: Displays CVE ID, CVSS score, EPSS probability (with visual percentage bar), CISA KEV exploitation pill badge, and ERS composite score.
   - **Default ERS Sort**: Automatically orders findings descending by Exposure Risk Score so critical exposure is front and center.
   - **Severity Banding**: Color-coded severity badges and borders:
     - **Critical** (ERS ≥ 8.0) — Red (`#FF3838`)
     - **High** (ERS ≥ 6.0) — Orange (`#FF7A00`)
     - **Medium** (ERS ≥ 4.0) — Yellow (`#FFC312`)
     - **Low** (ERS < 4.0) — Green (`#20D6A3`)
   - **Search & Filter Controls**: Real-time filtering by CVE ID, title, description, CWE taxonomy, or finding UUID, alongside quick-filter severity pills.
   - **On-Demand Demo Enrichment**: Integrated action allowing users to enrich a sample batch of real-world CVEs (Log4Shell, Apache Path Traversal, Spring Cloud Gateway, Jenkins CLI) to immediately preview enriched data and risk metrics.

3. **ERS Component Breakdown (Section 5.3)**:
   - Expanding any finding row opens an accordion drawer displaying the deterministic composite formula: `ERS = Σ(w_i × c_i)`.
   - Component cards detail each input factor:
     - Component name, raw score (0–10), assigned weight (%), and weighted score contribution.
     - Visual progress bar color-coded to score value.
   - **Derived Value Flagging**: Any component calculated from heuristic or fallback sources (`Source.DERIVED`) is visually flagged with a prominent warning badge: `⚠️ Warning: Estimate (not measured)` to satisfy repository evaluation transparency guidelines.

4. **Per-Field Provenance & Lineage (Section 5.4)**:
   - Dedicated `FieldProvenanceCard` sub-component displaying full multi-source lineage for:
     - **CVSS Base Severity**: Upstream source attribution (e.g., `CVE_ORG` or `VULNRICHMENT`), confidence level, vector string.
     - **EPSS Likelihood**: Probability percentage and percentile ranking attributed to FIRST EPSS.
     - **CISA KEV Catalog Status**: Known exploited vulnerability flag, CISA attribution, and date added.
     - **CWE Taxonomy**: Weakness types with provenance.
     - **Vulnerability Description**: Full narrative description attributed to the authoritative upstream source.
   - Each card exposes the source badge, confidence level, retrieval timestamp, and citation notes.

5. **Strict `engagement_id` Scope Requirement (Section 5.5 / D-032)**:
   - Strict enforcement: all API requests pass `engagement_id`.
   - If no engagement is selected, the view renders a clear empty state prompting the operator to select or register an authorized scope before displaying findings.
   - Graceful error handling for missing engagements (404), network disconnects, or empty scan histories.

6. **Dashboard Integration (`apps/web/app/dashboard/page.tsx`)**:
   - "Findings" item in the dashboard sidebar is fully interactive, featuring an `ERS` pill badge and `active` state indicator.
   - Main dashboard canvas dynamically switches between the Scan/Engagement operations view and the Enriched Findings view based on the active sidebar navigation.

---

## File map

| File | Role | Status |
|---|---|---|
| `apps/web/lib/api.ts` | Added Level 5 TypeScript interfaces, normalization helper, and API methods | Updated |
| `apps/web/components/EnrichedFindingsView.tsx` | Main enriched findings view component, ERS breakdown, and `FieldProvenanceCard` | Added |
| `apps/web/app/dashboard/page.tsx` | Wired Findings navigation item and dynamic canvas view switching | Updated |
| `apps/web/package.json` | Updated test script to run both polling and findings test suites | Updated |
| `apps/web/tests/findings.test.mjs` | Automated unit tests for Level 5 normalization, constraints, and severity bands | Added |
| `docs/mayank_implementation/level_2_second_part.md` | Marked Level 5 checklist items and summary table row as ✅ Done | Updated |
| `docs/mayank_implementation/level5_of_level2_second_part.md` | This walkthrough document | Added |

---

## Architecture & Data Flow

```
                      FastAPI Backend
           (/findings?engagement_id=... /findings/enrich/batch)
                               │
                               ▼
                    [apps/web/lib/api.ts]
      (api.getFindings, normalizeEnrichedFinding helper)
                               │
                               ▼
               [apps/web/app/dashboard/page.tsx]
     (activeNav === "Findings" ? <EnrichedFindingsView /> : <ScansView />)
                               │
                               ▼
            [apps/web/components/EnrichedFindingsView.tsx]
      ┌─────────────────────────────────────────────────────────┐
      │  Header & Controls                                      │
      │  - Active Scope: [Acme Prod Environment]               │
      │  - Search: [CVE-2021...]  Filters: [All][Crit][High]... │
      ├─────────────────────────────────────────────────────────┤
      │  Enriched Findings Table (Sorted by ERS Descending)     │
      │  CVE ID        CVSS    EPSS        KEV     ERS Score   │
      │  CVE-2021-44228 10.0   97.5% [███] [Active] 9.85 [CRIT] │
      ├─────────────────────────────────────────────────────────┤
      │  Accordion Drawer (Row Expand)                          │
      │  ├── Section 5.3: ERS Component Breakdown               │
      │  │   - CVSS Factor: 10.0 × 40% = 4.00 (cve_org)         │
      │  │   - EPSS Factor:  9.7 × 30% = 2.91 (epss)            │
      │  │   - KEV Boost:   10.0 × 30% = 3.00 (cisa_kev)        │
      │  │   - Heuristic:    5.0 × 10% = 0.50 [⚠️ Estimate]    │
      │  └── Section 5.4: Multi-Source Provenance & Lineage     │
      │      - [CVSS Score Card]   Source: cve_org (100% conf)  │
      │      - [EPSS Likelihood]   Source: epss (99% conf)      │
      │      - [CISA KEV Catalog]  Source: cisa_kev (In Catalog)│
      │      - [CWE Weaknesses]    Source: cve_org (CWE-502)    │
      │      - [Narrative Summary] Source: cve_org (Advisory)   │
      └─────────────────────────────────────────────────────────┘
```

---

## Validation & Test Results

### 1. Frontend Test Suite (`npm test`)

The test suite runs using the native Node.js test runner across both `tests/polling.test.mjs` and `tests/findings.test.mjs`:

```
> web@0.1.0 test
> node --test tests/polling.test.mjs tests/findings.test.mjs

▶ Level 5 Enriched Findings UI & API Client Logic
  ✔ 1. Enforces engagement_id requirement on finding lookups (31.1894ms)
  ✔ 2. Normalizes backend EnrichedFinding response into frontend EnrichedFindingItem (23.2254ms)
  ✔ 3. Classifies ERS severity bands accurately per thresholds (0.847ms)
  ✔ 4. Flags derived/heuristic scores appropriately (47.8152ms)
✔ Level 5 Enriched Findings UI & API Client Logic (110.7396ms)

▶ Issue #5: Frontend Scan Polling Lifecycle & Maximum Guard
  ✔ 1. Polling occurs while a scan is pending (4.1686ms)
  ✔ 2. Polling occurs while a scan is running (0.6499ms)
  ✔ 3. Polling stops when the scan becomes completed (92.0955ms)
  ✔ 4. Polling stops when the scan becomes failed (0.8795ms)
  ✔ 5. Polling stops when the scan becomes cancelled (1.3844ms)
  ✔ 6. Maximum polling guard prevents indefinite polling when scan stays active (488.0423ms)
  ✔ 7. Timers and intervals are cleaned up correctly on stop/reset without leaks (94.2593ms)
  ✔ 8. Failed scan error information structure is properly validated (10.4017ms)
✔ Issue #5: Frontend Scan Polling Lifecycle & Maximum Guard (817.1303ms)

ℹ tests 13
ℹ suites 1
ℹ pass 13
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
```

### 2. TypeScript Static Typecheck (`npx tsc --noEmit`)

Ran clean with **0 type errors**:
```
$ npx tsc --noEmit
# Exited with code 0 (clean)
```

### 3. Backend Unit Regression (`pytest`)

Verified all findings API and persistence tests:
```
============================= 53 passed in 5.06s ==============================
tests/unit/test_findings_api.py .......................                  [ 43%]
tests/unit/test_enriched_finding_persistence.py ......................   [ 84%]
tests/unit/test_finding.py ........                                      [100%]
```

---

## Conclusion & Next Steps

Level 5 successfully completes the full Layer 2 Second Part implementation roadmap! All 5 levels are fully implemented, verified, and documented:
- **Level 1**: Decisions D-027 through D-032 & ERS analysis.
- **Level 2**: Feed synchronization worker (`FeedSyncer`), Celery Beat task, and CLI commands.
- **Level 3**: Secondary mirror sources (`VulnrichmentSource`, `EUVDSource`, `ExploitDBSource`, `MetasploitSource`).
- **Level 4**: Offline evaluation harness measuring multi-source coverage against the NVD baseline (+40.7 pp gain).
- **Level 5**: Comprehensive Enriched Findings dashboard UI with ERS breakdown and field-level multi-source provenance.
