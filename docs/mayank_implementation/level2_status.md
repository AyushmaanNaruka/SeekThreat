# Track 2 (Enrichment) Status & Roadmap

**Current Local Date:** September / October 2026  
**Milestone Focus:** Layer 2 — Enrichment & Multi-Source Intelligence Fusion ([docs/02-architecture.md](file:///e:/SeekThreat/SeekThreat/docs/02-architecture.md#L361))  
**"Done When" Criterion:** *A raw [Finding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L22) is turned into an [EnrichedFinding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L48) with fused, attributed, scored intelligence across canonical sources with measured coverage against an NVD-only baseline.*  
**Primary Architecture Reference:** [services/enrichment/README.md](file:///e:/SeekThreat/SeekThreat/services/enrichment/README.md)

---

## 1. Executive Summary & Why It Matters

In April 2026, the National Vulnerability Database (NVD) discontinued routine enrichment for the vast majority of CVEs — reserving full CVE enrichment (CVSS scores, CWE categorization, CPE mappings) for only ~15–20% of high-priority cases (KEV entries, federal software, and EO 14028 critical software). Over 29,000 older and ongoing vulnerabilities were marked "Not Scheduled."

Any legacy vulnerability management tool relying solely on NVD for CVSS scores now returns empty metadata for most findings.

**Track 2 (Enrichment)** in `services/enrichment/` is SeekThreat's multi-source intelligence fusion engine and one of the core research contributions of this project. It ingests raw findings and fuses multiple intelligence sources (CVE.org, CISA KEV, FIRST EPSS v4, and secondary sources) with strict fallback chains, non-optional provenance tracking, and an explainable Exposure Risk Score (ERS).

### The Non-Negotiable Invariants

1. **Every fused field carries an `Attributed[T]` wrapper:** An unattributed value is unrepresentable, not just discouraged ([packages/schema/models/provenance.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L62)).
2. **Deterministic fallback chain:** `CVE.org -> CISA Vulnrichment -> ENISA EUVD -> derived`. Derived values must be explicitly labeled with `Source.DERIVED`.
3. **Never multiply EPSS × CVSS:** FIRST is explicit that the mathematical product of EPSS (probability) and CVSS (severity) is meaningless.
4. **Additive, explainable ERS (D-008):** Hand-tuned, documented weights. Every score renders its own `ScoreComponent` breakdown — no opaque risk numbers.
5. **KEV validates; it does not train:** CISA KEV membership provides an additive validation boost for active exploitation; it never solely dictates the score, nor is the score trained on KEV.
6. **Local mirror / cache — zero request-time API calls:** Intelligence sources are mirrored locally on disk/DB via scheduled synchronization jobs. The request-time pipeline queries only local cache.
7. **Idempotent persistence:** Upserting an `EnrichedFinding` must produce identical state with zero duplicate records.
8. **Decoupled from Track 1:** Track 2 builds and tests against hand-built fixture `Finding` objects from day one, wiring to live scanner output once both tracks are ready.

---

## 2. Architecture & Data Flow

```
   Raw Scanner Finding
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ services/enrichment                                         │
│                                                             │
│  1. Local Source Queries (Offline Mirrors, zero live calls) │
│     ├── sources/cve_org.py   (Canonical CVSS / CWE)         │
│     ├── sources/cisa_kev.py  (Active exploitation flag)     │
│     └── sources/epss.py      (EPSS v4 probability)          │
│                                                             │
│  2. Multi-Source Fusion (fusion.py)                         │
│     ├── Fallback Chain: CVE.org ──► Vulnrichment ──► EUVD   │
│     └── Mandatory Attributed[T] Provenance Wrapping         │
│                                                             │
│  3. Exposure Risk Scoring (ers.py)                          │
│     ├── Additive Components (CVSS + EPSS + KEV boost)       │
│     └── Self-explaining ScoreComponent breakdown            │
└─────────────────────────────────────────────────────────────┘
           │
           ▼
    EnrichedFinding
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ apps/api/db (Persistence Repository)                        │
│  └── Idempotent Upsert into PostgreSQL (enriched_findings)  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Task Breakdown

```
[x] Task 1: Fixtures & Baseline Test Harness
[x] Task 2: Source Client Architecture & Offline Local Cache (CVE.org, KEV, EPSS v4)
[x] Task 3: Fusion Engine & Fallback Chain (fusion.py)
[x] Task 4: Exposure Risk Score Engine (ers.py & D-008)
[x] Task 5: Database Persistence & Idempotent Upsert (apps/api/db)
[x] Task 6: Enrichment Pipeline Coordinator & Worker Integration
[x] Task 7: Comprehensive Invariant Tests & Regression Suite
```

---

### Task 1: Fixtures & Baseline Test Harness
* **Status:** ✅ Complete — see [Task 1 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_1_level_2_walkthrough.md)
* **Objective:** Enable independent, parallel development of Track 2 without waiting for Track 1 collection pipelines, by constructing offline test fixtures representing findings and source feeds.
* **Scope & Deliverables:**
  1. Create hand-built `Finding` test fixtures in `tests/fixtures/findings/`:
     - Single CVE finding (Log4Shell `CVE-2021-44228` and Apache traversal `CVE-2021-41773`).
     - Multi-CVE finding (Spring Gateway / RCE bundle `CVE-2022-22947` + `CVE-2022-22965`).
     - Missing-CVSS finding (Jenkins CLI `CVE-2024-23897`, where NVD has no enrichment, but CVE.org CNA provides CVSS metrics).
     - Moderate non-KEV finding (`CVE-2020-7699` express-fileupload).
     - Non-CVE finding / scanner heuristic finding (`FINDING_HEURISTIC_NO_CVE`).
  2. Create offline cached feeds in `tests/fixtures/enrichment/`:
     - CVE.org JSON response fixtures in official v5.1 format (`cve_org_sample.json`).
     - CISA KEV JSON catalog slice with positive and negative KEV memberships (`cisa_kev_sample.json`).
     - FIRST EPSS v4 score fixtures with probability tiers from high to low (`epss_v4_sample.json`).
  3. Comprehensive unit test verification (`tests/unit/test_enrichment_fixtures.py` - 10/10 tests passing).
* **Target Files:**
  - `tests/fixtures/findings/baseline_findings.py`
  - `tests/fixtures/enrichment/cve_org_sample.json`
  - `tests/fixtures/enrichment/cisa_kev_sample.json`
  - `tests/fixtures/enrichment/epss_v4_sample.json`
  - `tests/unit/test_enrichment_fixtures.py`

---

### Task 2: Source Client Architecture & Offline Local Cache (`sources/`)
* **Status:** ✅ Complete — see [Task 2 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_2_level_2_walkthrough.md)
* **Objective:** Build local-first source clients for the 3 MVP intelligence feeds (CVE.org, CISA KEV, FIRST EPSS v4) with caching and local disk mirroring.
* **Scope & Deliverables:**
  1. Base Source Contract (`services/enrichment/sources/base.py`):
     - `BaseEnrichmentSource` contract enforcing local caching and strict offline lookup (zero network calls during request path).
     - `BaseSourceRecord` with `to_attributed()` method enforcing non-optional provenance and attribution.
  2. Implement MVP Source Clients:
     - **CVE.org (`services/enrichment/sources/cve_org.py`)**: Priority 1 client parsing CVE Services v5.1 records (CNA CVSS v3.1/v4.0 baseScore, vectorString, CWE problemTypes, descriptions).
     - **CISA KEV (`services/enrichment/sources/cisa_kev.py`)**: Priority 3 client parsing KEV catalog, providing confirmed active exploitation flags, date added, ransomware usage, and affirmative negative records for non-KEV vulnerabilities.
     - **FIRST EPSS v4 (`services/enrichment/sources/epss.py`)**: Priority 4 client parsing EPSS v4 probability scores and percentile rankings.
  3. Scheduled Mirroring / Sync Coordinator (`services/enrichment/sources/sync.py`):
     - Background sync helper `SourceSynchronizer` for scheduled batch feed refreshes with atomic file replacement.
  4. Secondary Source Stubs (`services/enrichment/sources/secondary.py`):
     - Prioritized stubs for CISA Vulnrichment, NVD 2.0, ENISA EUVD, OSV.dev, GitHub Advisories, ExploitDB, Metasploit.
  5. Automated unit tests (`tests/unit/test_enrichment_sources.py` - 11/11 tests passing).
* **Target Files:**
  - `services/enrichment/sources/__init__.py`
  - `services/enrichment/sources/base.py`
  - `services/enrichment/sources/cve_org.py`
  - `services/enrichment/sources/cisa_kev.py`
  - `services/enrichment/sources/epss.py`
  - `services/enrichment/sources/secondary.py`
  - `services/enrichment/sources/sync.py`
  - `tests/unit/test_enrichment_sources.py`

---

### Task 3: Fusion Engine & Fallback Chain (`fusion.py`)
* **Status:** ✅ Complete — see [Task 3 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_3_level_2_walkthrough.md)
* **Objective:** Fuse multi-source intelligence into standardized finding fields, implementing priority fallback logic and mandatory provenance encapsulation.
* **Scope & Deliverables:**
  1. Implement Fallback Chain (`services/enrichment/fusion.py`):
     - `CVE.org -> CISA Vulnrichment -> ENISA EUVD -> derived`.
     - When CVE.org provides CVSS/CWE, adopt with `Source.CVE_ORG` and `Confidence.HIGH`.
     - When CVE.org is missing metrics, fallback to `Source.VULNRICHMENT` or `Source.EUVD` (`Confidence.MEDIUM`).
     - When all external sources lack CVSS, synthesize a heuristic fallback labeled `Source.DERIVED` and `Confidence.LOW`.
  2. Provenance Attribution Guarantee:
     - Every fused attribute is wrapped in `Attributed[EnrichmentValue]` ([packages/schema/models/provenance.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L62)).
     - Unattributed values are completely unrepresentable.
     - Standard field names: `cvss_score`, `cvss_vector`, `cwe_ids`, `epss_score`, `epss_percentile`, `in_kev`, `kev_date_added`, `ransomware_use`, `summary`.
  3. Multi-CVE Aggregation:
     - Support findings that map to multiple CVEs by deterministically selecting maximum severity / most critical metrics while tracking provenance per field.
  4. Automated unit tests (`tests/unit/test_enrichment_fallback.py` - 10/10 tests passing).
* **Target Files:**
  - `services/enrichment/fusion.py`
  - `services/enrichment/__init__.py`
  - `tests/unit/test_enrichment_fallback.py`

---

### Task 4: Exposure Risk Score (ERS) Engine (`ers.py` & D-008)
* **Status:** ✅ Complete — see [Task 4 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_4_level_2_walkthrough.md)
* **Objective:** Implement the composite Exposure Risk Score with additive, hand-tuned weights, transparent explanations, and zero-opaque-number guarantees.
* **Scope & Deliverables:**
  1. Additive Formula Implementation (`services/enrichment/ers.py`):
     - Strict adherence to [DECISIONS.md D-008](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L633).
     - Component inputs normalized to 0.0–10.0 scale:
       * **CVSS Base Severity** (`weight: 0.40`).
       * **EPSS Exploit Likelihood** (`weight: 0.35`).
       * **CISA KEV Active Exploitation** (`weight: 0.25`).
     - Additive sum validation: `value = sum(c.value * c.weight)` (within `1e-6` tolerance).
  2. Hard Invariants & Negative Requirements:
     - **NEVER multiply EPSS × CVSS**: Explicit regression guard asserting `ers.value != (epss * cvss)`.
     - **KEV validates; it does not train**: KEV presence provides an additive validation boost (+2.5 ERS points), but never solely dictates the score.
  3. Self-Explaining Output:
     - Output constructed as `ExposureRiskScore` ([packages/schema/models/scoring.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/scoring.py#L40)).
     - Every component renders a non-empty human-readable explanation and valid `Provenance`.
  4. Integration with `FusionEngine.fuse_to_enriched_finding()`:
     - Automatically attaches verified `ExposureRiskScore` to `EnrichedFinding`.
  5. Automated unit tests (`tests/unit/test_ers_invariants.py` - 8/8 tests passing).
* **Target Files:**
  - `services/enrichment/ers.py`
  - `services/enrichment/__init__.py`
  - `tests/unit/test_ers_invariants.py`

---

### Task 5: Database Persistence & Idempotent Upsert (`apps/api/db`)
* **Status:** ✅ Complete — see [Task 5 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_5_level_2_walkthrough.md)
* **Objective:** Store `EnrichedFinding` in PostgreSQL with idempotent upserts to ensure repeat enrichment runs never duplicate or corrupt records.
* **Scope & Deliverables:**
  1. SQLAlchemy ORM Model:
     - Create `EnrichedFindingModel` in `apps/api/db/models.py`.
     - Fields: `finding_id` (PK, String/UUID), `engagement_id` (indexed), `fields` (JSONB / JSON), `ers_value` (Float, nullable), `ers_components` (JSONB / JSON, nullable), `enriched_at` (DateTime timezone-aware).
     - `to_schema()` and `from_schema()` conversion methods for bidirectional Pydantic serialization.
  2. Repository Layer:
     - Add `EnrichedFindingRepository` to `apps/api/db/repositories.py`.
     - Idempotent upsert logic: `ON CONFLICT (finding_id) DO UPDATE SET fields = EXCLUDED.fields, ers_value = EXCLUDED.ers_value, ers_components = EXCLUDED.ers_components, enriched_at = EXCLUDED.enriched_at`.
     - SQLite fallback for native unit testing (`session.merge`).
  3. Alembic Database Migration:
     - Add migration script `0004_create_enriched_findings.py` in `alembic/versions/`.
* **Target Files:**
  - `apps/api/db/models.py`
  - `apps/api/db/repositories.py`
  - `alembic/versions/0004_create_enriched_findings.py`

---

### Task 6: Enrichment Pipeline Coordinator & Worker Integration
* **Status:** ✅ Complete — see [Task 6 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_6_level_2_walkthrough.md)
* **Objective:** Provide a clean coordinator service that accepts `Finding` objects, queries local source mirrors, runs fusion, evaluates ERS, and persists results.
* **Scope & Deliverables:**
  1. Pipeline Orchestrator:
     - Implement `EnrichmentService` in `services/enrichment/service.py`.
     - Methods: `enrich_finding(finding: Finding) -> EnrichedFinding` and `enrich_batch(findings: list[Finding]) -> list[EnrichedFinding]`.
  2. Celery Worker Task / Async Dispatch:
     - Optional background worker task in `apps/api/tasks/enrichment.py` for asynchronous batch enrichment.
  3. API Exposure:
     - Router endpoints in `apps/api/routers/findings.py` (or enrichment router) to query enriched findings by finding ID or engagement ID.
* **Target Files:**
  - `services/enrichment/service.py`
  - `apps/api/tasks/enrichment.py` (if async queueing is needed)
  - `apps/api/routers/findings.py`

---

### Task 7: Comprehensive Invariant Tests & Regression Suite
* **Status:** ✅ Complete — see [Task 7 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_7_level_2_walkthrough.md)
* **Objective:** Guard all project rules with dedicated unit and architecture tests that prevent future regressions.
* **Scope & Deliverables:**
  1. **Fallback Chain Tests (`tests/unit/test_enrichment_fallback.py`)**:
     - Verify CVE.org -> Vulnrichment -> EUVD -> derived priority order under missing source scenarios.
  2. **Anti-Multiplication Regression Guard (`tests/unit/test_ers_invariants.py`)**:
     - Explicit test verifying `ers.value != finding.epss * finding.cvss`.
     - Verifies sum of weighted components equals `ers.value`.
  3. **Provenance Completeness Guard (`tests/unit/test_enrichment_provenance.py`)**:
     - Asserts that every single entry in `EnrichedFinding.fields` is an instance of `Attributed[T]` with valid `Source`, `Confidence`, and UTC `retrieved_at`.
  4. **KEV Invariant Tests (`tests/unit/test_kev_scoring.py`)**:
     - Asserts KEV presence increases score via additive boost, but does not arbitrarily peg score to maximum.
  5. **Offline Mirror Isolation Guard (`tests/unit/test_offline_mirror.py`)**:
     - Mocks socket/HTTP requests and verifies that `enrich_finding()` executes with zero outbound network calls.
  6. **Persistence Idempotency Tests (`tests/unit/test_enriched_finding_persistence.py`)**:
     - Runs upsert twice on identical `EnrichedFinding` and verifies exactly 1 row exists with byte-identical content.
* **Target Files:**
  - `tests/unit/test_enrichment_fallback.py`
  - `tests/unit/test_ers_invariants.py`
  - `tests/unit/test_enrichment_provenance.py`
  - `tests/unit/test_kev_scoring.py`
  - `tests/unit/test_offline_mirror.py`
  - `tests/unit/test_enriched_finding_persistence.py`

---

## 4. Deliverables Checklist & Progress

| Component | Target Location | Status | Owner |
|---|---|:---:|:---:|
| Finding & Enrichment Fixtures | `tests/fixtures/findings/`, `tests/fixtures/enrichment/` | ✅ Complete | Mayank |
| Source Client Base & Local Cache Contract | `services/enrichment/sources/base.py` | ✅ Complete | Mayank |
| MVP Source Client: CVE.org | `services/enrichment/sources/cve_org.py` | ✅ Complete | Mayank |
| MVP Source Client: CISA KEV | `services/enrichment/sources/cisa_kev.py` | ✅ Complete | Mayank |
| MVP Source Client: FIRST EPSS v4 | `services/enrichment/sources/epss.py` | ✅ Complete | Mayank |
| Background Mirroring / Sync Job | `services/enrichment/sources/sync.py` | ✅ Complete | Mayank |
| Multi-Source Fusion & Fallback Chain | `services/enrichment/fusion.py` | ✅ Complete | Mayank |
| Additive Exposure Risk Score (ERS) | `services/enrichment/ers.py` | ✅ Complete | Mayank |
| EnrichedFinding ORM Model & Migration | `apps/api/db/models.py`, `alembic/versions/` | ✅ Complete | Mayank |
| Idempotent EnrichedFinding Repository | `apps/api/db/repositories.py` | ✅ Complete | Mayank |
| Enrichment Pipeline Coordinator | `services/enrichment/service.py`, `apps/api/tasks/enrichment.py`, `apps/api/routers/findings.py` | ✅ Complete | Mayank |
| Fallback & Provenance Unit Tests | `tests/unit/test_enrichment_fallback.py`, `tests/unit/test_enrichment_provenance.py` | ✅ Complete | Mayank |
| ERS Anti-Multiplication & KEV Boost Guards | `tests/unit/test_ers_invariants.py`, `tests/unit/test_kev_scoring.py` | ✅ Complete | Mayank |
| Offline Execution & Persistence Tests | `tests/unit/test_offline_mirror.py`, `tests/unit/test_enriched_finding_persistence.py` | ✅ Complete | Mayank |

---

## 5. Notes & Practical Guidelines for Implementation

- **No live API calls during scans:** Never make outbound HTTP calls inside `enrich_finding()` or when an API request arrives. Feed files/databases must be hydrated locally ahead of time.
- **Typing with Pydantic v2:** Remember that `EnrichedFinding.fields` has type `dict[str, Attributed[EnrichmentValue]]`. Generic Pydantic instantiation should be typed with `Attributed[EnrichmentValue]` to avoid Pydantic v2 generic validation quirks (see PR #1 learnings).
- **Secondary sources roadmap:** Once the 3 MVP sources (CVE.org, CISA KEV, FIRST EPSS v4) are fully wired and tested end-to-end, secondary sources can be added seamlessly by creating additional clients in `services/enrichment/sources/` in accordance with `services/enrichment/README.md` (CISA Vulnrichment -> NVD 2.0 -> ENISA EUVD -> OSV.dev -> GitHub Advisories -> ExploitDB -> Metasploit).
