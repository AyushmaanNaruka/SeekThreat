# Walkthrough - Task 2: Database Persistence & Migrations (Postgres + Alembic)

> **Document:** `docs/mayank_implementation/task_2_level_1_walkthrough.md`  
> **Topic:** Task 2 (Layer 1 Collection — Database Persistence & Migrations) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

We implemented relational database persistence and Alembic migrations for **Layer 1 (Collection)** in SeekThreat, satisfying Task 2 from [`docs/mayank_implementation/build.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/build.md#L75-L83).

This persistence layer ensures that:
1. Raw tool outputs are stored verbatim in a content-addressed table (`raw_artifacts`).
2. Scanner observations are persisted in an immutable facts table (`observations`) linked via foreign key to the raw artifact.
3. Multiple executions or re-scans of the same target execute **idempotently** without throwing integrity errors or duplicating facts.
4. Database migrations can be safely managed and tested via Alembic.
5. Models and repositories support PostgreSQL in production and SQLite in-memory during offline test execution.

---

## 2. What Was Built

### A. Application Configuration
* **[apps/api/core/config.py](file:///e:/SeekThreat/SeekThreat/apps/api/core/config.py)**:
  * Application configuration using `pydantic-settings`.
  * Loads `DATABASE_URL` and `REDIS_URL` from `.env` or environment variables.
  * Normalizes PostgreSQL connection URLs to the psycopg3 driver dialect (`postgresql+psycopg://`) required by SQLAlchemy 2.0.

### B. SQLAlchemy ORM Models & Session Management
* **[apps/api/db/base.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/base.py)**:
  * Declarative `Base(DeclarativeBase)` foundation for all ORM models.
* **[apps/api/db/models.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/models.py)**:
  * `RawArtifactModel` (`raw_artifacts`):
    * `artifact_id`: String(128) PK (content-addressed SHA-256).
    * `scanner`: String(64), not null.
    * `content`: Text, not null.
    * `content_type`: String(128), not null.
    * `captured_at`: DateTime(timezone=True), not null.
    * Relationship `observations` with cascade delete-orphan.
  * `ObservationModel` (`observations`):
    * `observation_id`: String(128) PK.
    * `engagement_id`: String(128), not null, indexed.
    * `scanner`: String(64), not null.
    * `kind`: String(64), not null, indexed.
    * `subject`: String(512), not null.
    * `attributes`: `JSONB().with_variant(JSON, "sqlite")`, not null.
    * `artifact_id`: String(128) FK (`raw_artifacts.artifact_id`, ondelete="CASCADE"), indexed.
    * `observed_at`: DateTime(timezone=True), not null.
    * `provenance`: `JSONB().with_variant(JSON, "sqlite")`, not null.
  * **Domain Mapping**: `from_schema()` and `to_schema()` methods on both models to cleanly serialize and deserialize between Pydantic v2 domain models ([`packages/schema/models/observation.py`](file:///e:/SeekThreat/SeekThreat/packages/schema/models/observation.py)) and SQLAlchemy ORM entities.
  * **Multi-Dialect Compatibility**: Transparent support for PostgreSQL `JSONB` in production and standard SQLite `JSON` for fast offline unit tests.
* **[apps/api/db/session.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/session.py)**:
  * `get_engine()`, `SessionLocal` factory, and `get_db()` FastAPI session generator.

### C. Idempotent Repository Layer
* **[apps/api/db/repositories.py](file:///e:/SeekThreat/SeekThreat/apps/api/db/repositories.py)**:
  * `RawArtifactRepository`:
    * `save(artifact)`: Idempotently upserts `RawArtifact` using native `ON CONFLICT (artifact_id) DO NOTHING`. Re-running identical scans safely skips insertion without error.
    * `get(artifact_id)`: Retrieves artifact and restores to Pydantic domain model.
    * `exists(artifact_id)`: Existence check.
  * `ObservationRepository`:
    * `save(observation)`: Idempotent single observation upsert.
    * `save_all(observations)`: Batch idempotent upsert using `ON CONFLICT (observation_id) DO NOTHING`. Skips existing observation IDs.
    * `get(observation_id)`: Retrieves single observation by ID.
    * `get_by_engagement(engagement_id, kind=None)`: Retrieves observations for an engagement, with optional kind filter.
    * `get_by_artifact(artifact_id)`: Retrieves all observations derived from a given raw artifact.
    * `count_by_engagement(engagement_id, kind=None)`: High-performance observation count.
  * `save_scan_result(session, scan_result)`: Transactional helper that persists both the `RawArtifact` and its associated `tuple[Observation, ...]` in a single atomic transaction.

### D. Alembic Migration Setup
* **[alembic.ini](file:///e:/SeekThreat/SeekThreat/alembic.ini)**:
  * Configured at the repository root.
* **[alembic/env.py](file:///e:/SeekThreat/SeekThreat/alembic/env.py)**:
  * Reads database configuration from `apps.api.core.config.settings` and connects `Base.metadata`.
* **[alembic/versions/0001_initial_artifacts_and_observations.py](file:///e:/SeekThreat/SeekThreat/alembic/versions/0001_initial_artifacts_and_observations.py)**:
  * Initial migration defining tables `raw_artifacts` and `observations` with all columns, foreign key constraints (`CASCADE`), and indexes (`ix_observations_engagement_id`, `ix_observations_artifact_id`, `ix_observations_kind`, `ix_observations_engagement_kind`).

---

## 3. Verification & Test Results

### A. Persistence & Repository Tests (`tests/unit/test_persistence.py`)
Tested using an in-memory SQLite database with foreign key enforcement:
- **Model Roundtrip**: `RawArtifact` and `Observation` serialize to ORM entities and back to Pydantic models with identical fields and UTC timezone awareness.
- **Artifact Idempotency**: Calling `repo.save(artifact)` twice produces no errors and does not create duplicate records.
- **Observation Batch Idempotency**: Calling `repo.save_all([obs1, obs2])` multiple times preserves exact count without duplicate rows.
- **Cascade Deletion**: Deleting a `RawArtifactModel` automatically cascades and removes all linked `ObservationModel` records.
- **Real Lab Baseline Fixture**: Tested with [`tests/fixtures/observations/lab_baseline.json`](file:///e:/SeekThreat/SeekThreat/tests/fixtures/observations/lab_baseline.json); verified that calling `save_scan_result()` twice keeps the observation count identical.

### B. Alembic Migrations Test (`tests/unit/test_alembic.py`)
- Verified that `command.upgrade(config, "head")` creates all tables, foreign keys, and indexes.
- Verified that `command.downgrade(config, "base")` cleanly drops all tables and indexes without leaving stray objects.

### C. Test Suite Results
* **Task 2 Specific Tests:**
  ```powershell
  pytest tests/unit/test_persistence.py tests/unit/test_alembic.py -v
  # 10 passed in 4.11s
  ```
* **Full Repo Test Suite:**
  ```powershell
  pytest tests
  # 129 passed in 2.42s (100% green)
  ```
* **Architecture Guard Tests:**
  ```powershell
  pytest tests/architecture/ -v
  # 8 passed in 0.41s (import firewall and authorization gate verified)
  ```
