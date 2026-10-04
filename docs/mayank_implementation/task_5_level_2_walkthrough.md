# Walkthrough - Task 5: Database Persistence & Idempotent Upsert (Track 2 — Enrichment)

> **Document:** `docs/mayank_implementation/task_5_level_2_walkthrough.md`  
> **Topic:** Task 5 (Track 2 Enrichment — Persistence, Schema Migration & Idempotent Upsert) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

In accordance with [level2_status.md](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_status.md#L180), [services/enrichment/README.md](file:///e:/SeekThreat/SeekThreat/services/enrichment/README.md#L45), and the architectural constraints of SeekThreat, **Task 5** implements the persistent storage layer for enriched findings.

Enrichment tasks are often re-triggered across engagement lifecycles (e.g., scheduled hourly feed refreshes, re-evaluating risk scores after CISA KEV catalog updates, or re-running failed scans). Storing enriched findings therefore requires **strict idempotency**: re-running enrichment on an existing finding must seamlessly update the existing record in-place rather than failing on primary key conflicts or producing duplicate historical rows.

### Load-Bearing Principles & Non-Negotiable Rules

1. **Strict Upsert Idempotency:**
   * Executing an upsert $N$ times with identical finding data must always result in exactly 1 persistent record.
   * If source enrichment data has evolved (e.g., CVSS updated or added to KEV), an upsert overwrites the finding's enrichment payload in-place without altering other records.
2. **Lossless Domain Round-Trip:**
   * An [EnrichedFinding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L38) domain object contains rich nested structures: [Attributed[EnrichmentValue]](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L65) with full provenance metadata, the underlying [Finding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L12), and an optional [ExposureRiskScore](file:///e:/SeekThreat/SeekThreat/packages/schema/models/scoring.py#L40) containing individual [ScoreComponent](file:///e:/SeekThreat/SeekThreat/packages/schema/models/scoring.py#L20) objects.
   * The database representation preserves the domain object completely. Reconstructing an `EnrichedFinding` from the database via `.to_schema()` produces a fully typed Pydantic model identical to the original input.
3. **Database Dialect Portability:**
   * In production, PostgreSQL provides native `ON CONFLICT (finding_id) DO UPDATE` semantics via `sqlalchemy.dialects.postgresql.insert`.
   * In local test environments and offline lab configurations, SQLite provides equivalent `sqlite_upsert` support. A generic `session.merge` fallback handles any auxiliary engine configurations.
4. **Schema Evolution & Migration Management:**
   * The database schema is managed via an explicit Alembic migration ([0004_create_enriched_findings.py](file:///e:/SeekThreat/SeekThreat/alembic/versions/0004_create_enriched_findings.py)), fully synchronized with SQLAlchemy metadata and verified against autogenerate diff checks in `test_alembic.py`.

---

## 2. What Was Built

### A. SQLAlchemy ORM Model: `EnrichedFindingModel`
* **File:** [apps/api/db/models.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/models.py)
* **Table:** `enriched_findings`
* **Key Columns:**
  * `finding_id` (`String(128)`, Primary Key): Matches `Finding.finding_id`.
  * `engagement_id` (`String(128)`, Indexed): Enables fast scoped queries by engagement.
  * `finding_data` (`JSON / JSONB`, Not Null): Stores the complete serialized `Finding` domain model.
  * `fields` (`JSON / JSONB`, Not Null): Stores the dictionary of attributed enrichment fields `dict[str, Attributed[EnrichmentValue]]`.
  * `ers_value` (`Float`, Nullable): Pre-extracted numerical composite ERS score for fast sorting and threshold filtering.
  * `ers_components` (`JSON / JSONB`, Nullable): Stores the serialized tuple of `ScoreComponent` objects.
  * `enriched_at` (`DateTime(timezone=True)`, Indexed): Timestamp of the enrichment run.
* **Conversion Methods:**
  * `from_schema(enriched: EnrichedFinding, enriched_at: datetime | None = None) -> EnrichedFindingModel`: Serializes Pydantic domain models to database columns using `model_dump(mode="json")`.
  * `to_schema() -> EnrichedFinding`: Deserializes database rows back into validated Pydantic models using `model_validate()`, correctly restoring `Attributed[EnrichmentValue]` generic structures and `ExposureRiskScore`.

---

### B. Idempotent Repository: `EnrichedFindingRepository`
* **File:** [apps/api/db/repositories.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/repositories.py)
* **Implemented Capabilities:**
  * `upsert(enriched: EnrichedFinding, enriched_at: datetime | None = None) -> EnrichedFindingModel`:
    * Detects database dialect (`postgresql`, `sqlite`, or generic).
    * Constructs native `INSERT ... ON CONFLICT (finding_id) DO UPDATE` statements for PostgreSQL and SQLite.
    * Uses `session.merge()` for generic dialects.
  * `upsert_all(enriched_findings: Sequence[EnrichedFinding], enriched_at: datetime | None = None) -> list[EnrichedFindingModel]`:
    * Batch upsert handling multiple findings in a single operation.
  * `get(finding_id: str) -> EnrichedFinding | None`:
    * Retrieves and reconstructs a single `EnrichedFinding` domain model.
  * `get_by_engagement(engagement_id: str, limit: int = 100, offset: int = 0) -> list[EnrichedFinding]`:
    * Retrieves paginated domain findings scoped to a specific engagement, ordered by `enriched_at DESC`.
  * `count_by_engagement(engagement_id: str) -> int`:
    * Returns the total count of enriched findings for an engagement.

---

### C. Database Migration: `0004_create_enriched_findings.py`
* **File:** [alembic/versions/0004_create_enriched_findings.py](file:///e:/SeekThreat/SeekThreat/alembic/versions/0004_create_enriched_findings.py)
* **Revision:** `0004` (revises `0003_create_audit_logs`)
* **Features:**
  * Supports PostgreSQL `JSONB` with automatic fallback to standard `JSON` for SQLite.
  * Creates indices on `engagement_id` and `enriched_at`.
  * Includes clean `downgrade()` implementation that drops indices and table.

---

### D. Package Exports
* **File:** [apps/api/db/__init__.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/__init__.py)
* Exported `EnrichedFindingModel` and `EnrichedFindingRepository` alongside existing models and repositories.

---

## 3. Verification & Test Results

### Dedicated Persistence Test Suite: `test_enriched_finding_persistence.py`
We created a comprehensive unit test suite in [tests/unit/test_enriched_finding_persistence.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_enriched_finding_persistence.py) covering three core areas:

1. **Model Round-Trip & Schema Fidelity (`TestEnrichedFindingModelRoundTrip`):**
   * `test_from_schema_populates_all_columns`: Verifies column extraction from Pydantic model.
   * `test_to_schema_reconstructs_finding`: Confirms `Finding` metadata survives storage.
   * `test_to_schema_reconstructs_attributed_fields`: Confirms `Attributed[EnrichmentValue]` and provenance sources survive JSON serialization and restoration.
   * `test_to_schema_reconstructs_ers`: Confirms `ExposureRiskScore` and all constituent `ScoreComponent` objects are fully reconstructed.
   * `test_to_schema_without_ers_produces_none`: Confirms findings without ERS are preserved accurately.
2. **Idempotency Invariants (`TestEnrichedFindingIdempotentUpsert`):**
   * `test_double_upsert_produces_exactly_one_row`: Asserts executing `upsert` twice results in `row_count == 1`.
   * `test_upserted_twice_with_same_data_yields_identical_content`: Verifies row contents remain byte-identical after repeated upserts.
   * `test_upsert_overwrites_stale_fields_on_re_enrichment`: Verifies re-enriching an existing finding with updated fields updates the database row in place.
   * `test_batch_upsert_all_produces_correct_row_count`: Verifies batch upserting $N$ findings creates exactly $N$ rows.
   * `test_batch_upsert_all_twice_stays_idempotent`: Verifies repeated batch upserts do not create duplicate rows.
3. **Repository Query Methods (`TestEnrichedFindingRepositoryQueries`):**
   * `test_get_returns_none_for_missing_id`: Verifies graceful `None` on missing primary key.
   * `test_get_by_engagement_returns_findings_for_that_engagement`: Verifies correct filtering by `engagement_id`.
   * `test_get_by_engagement_does_not_return_other_engagements`: Verifies engagement isolation.
   * `test_count_by_engagement_returns_correct_count`: Verifies count queries.
   * `test_get_by_engagement_respects_limit_and_offset`: Verifies pagination with disjoint pages.

```bash
python -m pytest tests/unit/test_enriched_finding_persistence.py -v
```

**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 15 items

tests\unit\test_enriched_finding_persistence.py ...............          [100%]

============================= 15 passed in 1.52s ==============================
```

---

### Migration Consistency Check: `test_alembic.py`

Verified that Alembic migrations match SQLAlchemy metadata with zero unexpected diffs:

```bash
python -m pytest tests/unit/test_alembic.py -v
```

**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 2 items

tests\unit\test_alembic.py ..                                            [100%]

============================== 2 passed in 1.83s ==============================
```

---

### Full Regression Suite Run

Executed the full unit test suite across the entire project:

```bash
python -m pytest tests/unit/ -v --tb=short
```

**Result:**
```text
======================= 281 passed, 1 skipped in 10.42s =======================
```

Zero regressions introduced across all 282 test cases.

---

## 4. Next Steps

With Task 5 complete, the remaining tasks under Level 2 Enrichment are:
* **Task 6:** Enrichment Pipeline Coordinator & Worker Integration ([services/enrichment/service.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/service.py) and Celery task integration).
* **Task 7:** Comprehensive Invariant Tests & Regression Suite (offline mirror tests and end-to-end integration tests).
