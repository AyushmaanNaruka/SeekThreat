# Layer 1 (Collection) Status & Roadmap

> **Document:** `docs/mayank_implementation/build.md`  
> **Topic:** Level 1 / Layer 1 (Collection) Progress & Next Steps  
> **Status:** Active Reference Document

---

## 1. Executive Summary

In SeekThreat's 4-layer architecture, **Layer 1 (Collection)** is responsible for running vulnerability and discovery scanners behind a single interface, strictly enforcing authorization before any scan begins, retaining raw tool outputs verbatim, and emitting immutable, provenance-tagged `Observation` facts.

- **Milestone Focus:** Layer 1 — Collection (Scheduled for Month 1 / September)
- **"Done When" Criterion:** *A scan produces stored, provenanced observations.* ([docs/02-architecture.md](file:///e:/SeekThreat/SeekThreat/docs/02-architecture.md#L339))

---

## 2. What Has Been Achieved (Completed)

### A. Data Schema & Immutability Invariants (`packages/schema`)
- [x] **Immutable Fact Models ([packages/schema/models/observation.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/observation.py))**:
  - `RawArtifact`: Verbatim tool output with content-addressed ID (`sha256`), content type, scanner name, and UTC capture timestamp.
  - `Observation`: Append-only, frozen record containing `observation_id`, `engagement_id`, `scanner`, `kind` (`HOST_UP`, `PORT_OPEN`, `SERVICE_VERSION`), `subject`, `attributes`, and `provenance`.
  - `ScanResult`: Immutable container returned by adapters holding `{artifact: RawArtifact, observations: tuple[Observation, ...]}` ([DECISIONS.md D-011](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L114)).
- [x] **Authorization & Engagement Models ([packages/schema/models/engagement.py](file:///e:/SeekThreat/SeekThreat/packages/schema/models/engagement.py))**:
  - `Authorization`: Scoped by `engagement_id`, authorizer, time window (`valid_from`, `valid_to`), and allowlist.
  - Target matching logic: Fully supports IPv4/IPv6 CIDR ranges (e.g. `172.20.0.0/16`) and wildcard domains (e.g. `*.lab.internal`). Fails closed on any unauthorized target.
  - `ScanRequest`: Pydantic model passing target, authorization record, and scanner options.
- [x] **Downstream Schema Foundations**:
  - `Asset`, `Service`, `Finding`, and `EnrichedFinding` models (`packages/schema/models/asset.py`, `finding.py`).
  - `Attributed[T]` provenance wrapper (`packages/schema/models/provenance.py`) enforcing that no enriched field can be constructed without attribution.
  - `ExposureRiskScore` (`packages/schema/models/scoring.py`) with self-explaining additive components ([DECISIONS.md D-008](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L202)).

### B. Scanner Framework (`services/scanners`)
- [x] **Base Adapter Contract ([services/scanners/base.py](file:///e:/SeekThreat/SeekThreat/services/scanners/base.py))**:
  - Abstract base class `ScannerAdapter`.
  - Enforces authorization check in `scan()` **before** `_execute()` is invoked.
  - Automatically calculates content hash and creates `RawArtifact`.
  - Provides overridable `_captured_at()` hook to ensure `_parse` remains a deterministic, replayable pure function.
- [x] **Reference Scanner: Nmap Adapter ([services/scanners/nmap_adapter.py](file:///e:/SeekThreat/SeekThreat/services/scanners/nmap_adapter.py))**:
  - Subprocess execution (`nmap -sV -oX -`) with binary output capture (preventing newline translation errors).
  - Pure function parsing delegating to `services/scanners/nmap_xml.py`.
- [x] **Nmap XML Parser ([services/scanners/nmap_xml.py](file:///e:/SeekThreat/SeekThreat/services/scanners/nmap_xml.py))**:
  - Custom parser using stdlib `xml.etree.ElementTree` guarded against Billion-Laughs DoS and XXE ([DECISIONS.md D-013](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L50)).
  - Emits `HOST_UP`, `PORT_OPEN`, and `SERVICE_VERSION` observations.
  - Omits `method="table"` guesses from `SERVICE_VERSION` to prevent false-positive CVE matching downstream ([DECISIONS.md D-012](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L82)).
  - Sanitizes banner text by stripping control characters and enforcing length limits.

### C. Testing, Fixtures & Architecture Guards (`tests/`)
- [x] **Architecture Guards ([tests/architecture/](file:///e:/SeekThreat/SeekThreat/tests/architecture/))**:
  - `test_authorization_gate.py`: Uses reflection to discover every `ScannerAdapter` subclass and asserts that unauthorized targets raise `AuthorizationError` before `_execute` runs.
  - `test_import_firewall.py`: AST-level test verifying that LLM assistant code cannot import scanner or graph internals.
- [x] **Offline Test Fixtures ([tests/fixtures/](file:///e:/SeekThreat/SeekThreat/tests/fixtures/))**:
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
* **Status:** ✅ Complete — 147/147 tests passing
* **Delivered:**
  1. **`apps/api/core/authorization.py`** — Centralized choke point; enforces time-window and CIDR/hostname allowlist gate before any scan job is accepted. Fails closed with `403 Forbidden` + structured audit event.
  2. **`apps/api/core/audit.py`** — Structured JSON audit logger recording actor, target, scanner, engagement reference, status, and UTC timestamp for every operation.
  3. **`apps/api/routers/engagements.py`** — `POST /engagements`, `GET /engagements/{id}`, `GET /engagements`.
  4. **`apps/api/routers/scans.py`** — `POST /scans` (202 + background dispatch), `GET /scans/{id}` (status + observation count), `GET /scans?engagement_id=`.
  5. **`tests/unit/test_api.py`** — 18 new unit tests covering happy path, all rejection scenarios (out-of-CIDR, expired auth, missing engagement), audit event assertions, and migration 0002 upgrade/downgrade.

### Task 4: Asynchronous Queue & Infrastructure Integration (Celery + Redis)
* **Status:** ✅ Complete (150/150 tests passing)
* **Delivered:**
  1. **`apps/api/worker.py`** — Celery app bootstrap configured with Redis broker/backend (`settings.redis_url`), JSON serialization, UTC timestamps, and a dedicated `scans` task queue.
  2. **`apps/api/tasks/scans.py`** — `execute_scan` Celery task that runs outside the HTTP lifecycle. Reconstructs `Authorization` from JSON transport, instantiates `NmapAdapter`, invokes scan, persists artifacts and observations idempotently via `save_scan_result`, updates scan status, and logs audit events (`scan.completed` / `scan.failed`).
  3. **`apps/api/routers/scans.py`** — Replaced in-process FastAPI `BackgroundTasks` with Celery asynchronous job dispatch via `execute_scan.delay()`.
  4. **`apps/api/Dockerfile`** — Single multi-purpose container image for both API server (`uvicorn`) and background worker (`celery`), including system `nmap` binaries and Python dependencies.
  5. **`infra/docker-compose.yml`** — Replaced `TODO` comments with `api` and `worker` container service definitions wired to `postgres` (health check condition) and `redis` under the `core` profile.
  6. **`tests/unit/test_celery_task.py`** & **`tests/unit/test_api.py`** — Unit tests covering Celery task execution, auth dict serialization round-trip, mocked scanner happy path, failure state handling, and API async task dispatch.
  7. **`DECISIONS.md`** — Added ADR **D-014** documenting the Celery + Redis architecture decision.

### Task 5: Second Core Scanner — Nuclei Adapter
* **Status:** ✅ Complete (164/164 tests passing)
* **Delivered:**
  1. **`services/scanners/nuclei_adapter.py`** — `NucleiAdapter(ScannerAdapter)` subclass. Invokes `nuclei -u <target> -jsonl -silent` as subprocess, parses NDJSON via `nuclei_json.py`, auto-discovered by `test_authorization_gate.py`.
  2. **`services/scanners/nuclei_json.py`** — Pure NDJSON/JSON-array parser. Emits `ObservationKind.VULN_CANDIDATE` observations with deterministic sha256 IDs. Preserves CVE IDs, CVSS scores, severity, matcher metadata, extracted results, and curl commands verbatim in `attributes`. Sanitizes control characters and truncates oversized fields.
  3. **`tests/fixtures/nuclei/`** — 6 fixture files: `lab_baseline.jsonl`, `single_cve.jsonl`, `empty.jsonl`, `json_array.json`, `malformed.jsonl`, `malicious_attributes.jsonl`.
  4. **`tests/unit/test_nuclei_json.py`** — 11 unit tests covering baseline parsing, CVE/CVSS extraction, empty output, JSON array format, malformed input, control character sanitization, attribute truncation, pure-function determinism, size-limit guard, timestamp parsing, and mocked adapter scan.
  5. **`tests/architecture/test_authorization_gate.py`** — Automatically covers `NucleiAdapter` (now 7 tests: 3 per adapter × 2 adapters + 1 discovery guard). Zero code changes needed.
  6. **`apps/api/tasks/scans.py`** — Added `elif scanner == "nuclei"` dispatch branch.
  7. **`DECISIONS.md`** — Added ADR **D-015** documenting Nuclei + NDJSON architecture decision.

### Task 6: Lab Expansion & Ground Truth Baseline (`lab/`)
* **Status:** ✅ Complete (175/175 tests passing)
* **Delivered:**
  1. **`lab/docker-compose.yml`** — Expanded to 10 vulnerable hosts across 3 isolated subnets (`dmz`: `172.20.1.0/24`, `internal`: `172.20.2.0/24`, `data`: `172.20.3.0/24`) with `internal: true` isolation, dual-homed bridge pivots (`dmz-proxy`, `spring-gateway`, `bastion-ssh`), and isolated `scanner` auditor container (`172.20.1.250`).
  2. **`lab/ground_truth.yaml`** — Authoritative ground truth denominator recording 10 hosts, 10 expected CVEs with CVSS scores & confidence ratings, 3 realistic multi-hop attack paths, and known scanner false positives.
  3. **`tests/unit/test_ground_truth.py`** — 11 automated unit tests verifying schema adherence, subnet matching, 8–12 host count constraint, attack path sequential validity, and strict docker-compose cross-consistency.
  4. **`DECISIONS.md`** — Added ADR **D-016** documenting multi-tier topology, multi-hop chains, and ground truth schema.

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
