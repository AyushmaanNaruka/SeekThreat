# Layer 1 (Collection) Status & Roadmap

**Current Local Date:** September 2026  
**Milestone Focus:** Layer 1 — Collection (Scheduled for Month 1 / September)  
**"Done When" Criterion:** *A scan produces stored, provenanced observations.* ([docs/02-architecture.md](file:///e:/SeekThreat/SeekThreat/docs/02-architecture.md#L339))

---

## 1. Executive Summary

In SeekThreat's 4-layer architecture, **Layer 1 (Collection)** is responsible for running vulnerability and discovery scanners behind a single interface, strictly enforcing authorization before any scan begins, retaining raw tool outputs verbatim, and emitting immutable, provenance-tagged `Observation` facts.

This document details what has already been built and verified, and what tasks remain to complete Layer 1 end-to-end.

---

## 2. What Has Been Achieved (Completed)

### A. Data Schema & Immutability Invariants (`packages/schema`)
- [x] **Immutable Fact Models (`packages/schema/models/observation.py`)**:
  - `RawArtifact`: Verbatim tool output with content-addressed ID (`sha256`), content type, scanner name, and UTC capture timestamp.
  - `Observation`: Append-only, frozen record containing `observation_id`, `engagement_id`, `scanner`, `kind` (`HOST_UP`, `PORT_OPEN`, `SERVICE_VERSION`), `subject`, `attributes`, and `provenance`.
  - `ScanResult`: Immutable container returned by adapters holding `{artifact: RawArtifact, observations: tuple[Observation, ...]}` ([DECISIONS.md D-011](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L114)).
- [x] **Authorization & Engagement Models (`packages/schema/models/engagement.py`)**:
  - `Authorization`: Scoped by `engagement_id`, authorizer, time window (`valid_from`, `valid_to`), and allowlist.
  - Target matching logic: Fully supports IPv4/IPv6 CIDR ranges (e.g. `172.20.0.0/16`) and wildcard domains (e.g. `*.lab.internal`). Fails closed on any unauthorized target.
  - `ScanRequest`: Pydantic model passing target, authorization record, and scanner options.
- [x] **Downstream Schema Foundations**:
  - `Asset`, `Service`, `Finding`, and `EnrichedFinding` models (`packages/schema/models/asset.py`, `finding.py`).
  - `Attributed[T]` provenance wrapper (`packages/schema/models/provenance.py`) enforcing that no enriched field can be constructed without attribution.
  - `ExposureRiskScore` (`packages/schema/models/scoring.py`) with self-explaining additive components ([DECISIONS.md D-008](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L202)).

### B. Scanner Framework (`services/scanners`)
- [x] **Base Adapter Contract (`services/scanners/base.py`)**:
  - Abstract base class `ScannerAdapter`.
  - Enforces authorization check in `scan()` **before** `_execute()` is invoked.
  - Automatically calculates content hash and creates `RawArtifact`.
  - Provides overridable `_captured_at()` hook to ensure `_parse` remains a deterministic, replayable pure function.
- [x] **Reference Scanner: Nmap Adapter (`services/scanners/nmap_adapter.py`)**:
  - Subprocess execution (`nmap -sV -oX -`) with binary output capture (preventing newline translation errors).
  - Pure function parsing delegating to `services/scanners/nmap_xml.py`.
- [x] **Nmap XML Parser (`services/scanners/nmap_xml.py`)**:
  - Custom parser using stdlib `xml.etree.ElementTree` guarded against Billion-Laughs DoS and XXE ([DECISIONS.md D-013](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L50)).
  - Emits `HOST_UP`, `PORT_OPEN`, and `SERVICE_VERSION` observations.
  - Omits `method="table"` guesses from `SERVICE_VERSION` to prevent false-positive CVE matching downstream ([DECISIONS.md D-012](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L82)).
  - Sanitizes banner text by stripping control characters and enforcing length limits.

### C. Testing, Fixtures & Architecture Guards (`tests/`)
- [x] **Architecture Guards (`tests/architecture/`)**:
  - `test_authorization_gate.py`: Uses reflection to discover every `ScannerAdapter` subclass and asserts that unauthorized targets raise `AuthorizationError` before `_execute` runs.
  - `test_import_firewall.py`: AST-level test verifying that LLM assistant code cannot import scanner or graph internals.
- [x] **Offline Test Fixtures (`tests/fixtures/`)**:
  - Baseline nmap XML captured from lab targets (`tests/fixtures/nmap/lab_baseline.xml`).
  - Edge-case synthetic XML fixtures (down hosts, missing timestamps, dual-stack, malformed banners, DOCTYPE attacks).
  - Parsed baseline facts stored in `tests/fixtures/observations/lab_baseline.json`, enabling Layers 2–4 to run unit and integration tests without active containers.
- [x] **Unit Tests**: Over 115 passing tests covering scanner base, authorization CIDR/wildcard matching, and XML edge cases.

---

## 3. What Needs to Be Done (Pending Work)

To bring Layer 1 to completion and satisfy the September milestone, the following deliverables remain:

```
[DONE] Scan Execution -> [DONE] Pure Parse -> [PENDING] DB Store -> [PENDING] API Dispatch
```

### Task 1: Quick Maintenance — Fix 1 Failing Unit Test
* **Status:** ✅ Complete (119/119 tests passing)
* **File:** `tests/unit/test_finding.py`
* **Issue:** `test_enriched_field_carries_value_and_provenance_together` fails due to Pydantic v2 generic validation on `Attributed[EnrichmentValue]` vs `Attributed[float]`.
* **Action:** Updated test instantiation to use `Attributed[EnrichmentValue]`. Entire unit test suite is 100% green (119/119 passing).

### Task 2: Database Persistence & Migrations (Postgres + Alembic)
* **Status:** ✅ Complete — see [Task 2 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_2_level_1_walkthrough.md)
* **Requirements:**
  1. Configure Alembic in the repository root or under `apps/api`. (Implemented at root with `alembic.ini` and `alembic/`)
  2. Create SQLAlchemy ORM models for:
     - `raw_artifacts`: `artifact_id` (PK, sha256), `scanner`, `content`, `content_type`, `captured_at`. (Implemented in `apps/api/db/models.py`)
     - `observations`: `observation_id` (PK), `engagement_id` (indexed), `scanner`, `kind`, `subject`, `attributes` (JSONB), `artifact_id` (FK), `observed_at`, `provenance` (JSONB). (Implemented in `apps/api/db/models.py`)
  3. Write repository layer (`ObservationRepository`, `RawArtifactRepository`) with idempotent upserts so re-running scans does not duplicate facts. (Implemented in `apps/api/db/repositories.py`)

### Task 3: API Endpoints & Authorization Choke Point (`apps/api`)
* **Status:** Scaffold only (`apps/api/main.py` with `/health`).
* **Requirements:**
  1. Implement `apps/api/core/authorization.py`: API-layer authorization check verifying that requests have valid engagement credentials before jobs are accepted.
  2. Implement `apps/api/routers/engagements.py`:
     - `POST /engagements`: Create an engagement and register target allowlists.
     - `GET /engagements/{id}`: View engagement metadata and authorization scope.
  3. Implement `apps/api/routers/scans.py`:
     - `POST /scans`: Accept scan request, validate authorization, dispatch background job, and return `scan_id`.
     - `GET /scans/{id}`: Check scan status and observation counts.
  4. Structured audit logging: Log actor, target IP, authorization reference, and timestamp for every scan.

### Task 4: Asynchronous Queue & Infrastructure Integration (Celery + Redis)
* **Status:** Redis defined in compose, but Celery worker is not implemented.
* **Requirements:**
  1. Create `apps/api/tasks/scans.py` to run scanner adapters asynchronously outside the HTTP request lifecycle.
  2. Worker invokes `adapter.scan(request)` and saves the resulting `ScanResult` to Postgres via the persistence repository.
  3. Update `infra/docker-compose.yml`: Add `api` and `worker` services to the `core` profile (currently marked as `TODO`).

### Task 5: Second Core Scanner — Nuclei Adapter
* **Status:** ✅ Complete — see [Task 5 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_5_level_1_walkthrough.md)
* **Delivered:**
  1. `services/scanners/nuclei_adapter.py`: Nuclei scanner adapter with `-jsonl -silent` execution.
  2. `services/scanners/nuclei_json.py`: Deterministic NDJSON parser emitting `VULN_CANDIDATE` observations.
  3. `tests/fixtures/nuclei/`: Fixtures for baseline and edge cases.
  4. Automatic coverage via `tests/architecture/test_authorization_gate.py`.

### Task 6: Lab Expansion & Ground Truth Baseline (`lab/`)
* **Status:** ✅ Complete — see [Task 6 Walkthrough](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/task_6_level_1_walkthrough.md)
* **Delivered:**
  1. `lab/docker-compose.yml`: Expanded to 10 vulnerable targets across 3 isolated subnets (`dmz`, `internal`, `data`) with realistic multi-hop pivot points.
  2. `lab/ground_truth.yaml`: Authoritative ground truth denominator recording 10 hosts, expected CVEs with CVSS, 3 multi-hop attack paths, and known false positives.
  3. `tests/unit/test_ground_truth.py`: 11 tests verifying schema, topology, subnet allocations, and cross-consistency with compose.

### Task 7: Collection Web UI (`apps/web`)
* **Status:** Scaffold only.
* **Requirements:**
  1. Engagement creation screen (define target IP/CIDR and authorizer).
  2. Scan trigger and live status progress screen ("scanners behind one UI, no command line").

---

## 4. Deliverables Checklist & Progress

| Component | Target Location | Status | Owner |
|---|---|:---:|:---:|
| Schema Models (`Observation`, `RawArtifact`) | `packages/schema/models/` | ✅ Complete | Team |
| Authorization Gate & Tests | `services/scanners/base.py` | ✅ Complete | Dev A |
| Nmap Adapter & XML Parser | `services/scanners/nmap_*.py` | ✅ Complete | Dev A |
| Offline Observation Fixture | `tests/fixtures/observations/` | ✅ Complete | Dev A |
| Green Test Suite (175/175) | `tests/unit/` | ✅ Complete | Team |
| Postgres ORM & Alembic Migrations | `apps/api/db/` | ✅ Complete | Dev A |
| API Routers (`/engagements`, `/scans`) | `apps/api/routers/` | ✅ Complete | Dev A |
| Celery Worker & Redis Queue | `apps/api/tasks/` | ✅ Complete | Dev A |
| Nuclei Scanner Adapter | `services/scanners/nuclei_adapter.py` | ✅ Complete | Dev A / B |
| 8–12 Host Lab & `ground_truth.yaml` | `lab/` | ✅ Complete | Team |
| Web UI Scan Dispatch Screen | `apps/web/` | ⏳ Pending | Dev C |
