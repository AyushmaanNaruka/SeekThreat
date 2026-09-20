# Task 4 Walkthrough — Asynchronous Queue & Infrastructure Integration (Celery + Redis)

> **Layer:** 1 (Collection)  
> **Task:** 4 of 7  
> **Status:** ✅ Complete — 150/150 tests passing (+3 new Celery unit tests, 21 total API & Celery tests)  
> **Files touched:** 4 new files, 4 modified  

---

## 1. Goal

Decouple scan execution from the FastAPI HTTP request lifecycle by replacing the preliminary in-process `BackgroundTasks` with a dedicated **Celery + Redis distributed task queue**:

1. **Process Isolation:** The API server acknowledges the scan trigger (`202 Accepted`) immediately, while the scan executes inside an independent worker process.
2. **Durability & Re-queueing:** If an API container or worker crashes during execution, tasks in Redis are preserved (`task_acks_late=True`, `task_reject_on_worker_lost=True`).
3. **Safe Serialization:** Tasks communicate over Redis using Celery's `json` serializer to eliminate pickle deserialization vulnerabilities.
4. **Resilient Retries:** Built-in retry handling (`max_retries=3`, `default_retry_delay=30s`) with terminal failure state capture and audit logging.
5. **Container Orchestration:** Unified Docker build for API and Worker with Compose services wired to Redis and PostgreSQL.

---

## 2. Files Delivered & Modified

| File | Type | Purpose |
|---|:---:|---|
| [`apps/api/worker.py`](file:///e:/SeekThreat/SeekThreat/apps/api/worker.py) | New | Celery application instance bootstrap configured with Redis broker/backend and task routes. |
| [`apps/api/tasks/__init__.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/__init__.py) | New | Celery tasks package root. |
| [`apps/api/tasks/scans.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/scans.py) | New | `execute_scan` Celery task with JSON authorization reconstruction, adapter execution, idempotent DB persistence, and audit logging. |
| [`apps/api/routers/scans.py`](file:///e:/SeekThreat/SeekThreat/apps/api/routers/scans.py) | Modified | Replaces `BackgroundTasks` with `execute_scan.delay(...)`. |
| [`apps/api/Dockerfile`](file:///e:/SeekThreat/SeekThreat/apps/api/Dockerfile) | New | Unified Python 3.11 Debian-slim container image bundling `nmap`, Python packages, and uvicorn/celery entrypoints. |
| [`infra/docker-compose.yml`](file:///e:/SeekThreat/SeekThreat/infra/docker-compose.yml) | Modified | Adds `api` and `worker` services to the `core` profile, replacing previous TODO comments. |
| [`tests/unit/test_celery_task.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_celery_task.py) | New | Unit tests for authorization dict round-trip, mocked happy path, and failure state transitions. |
| [`tests/unit/test_api.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_api.py) | Modified | Updates test client fixture to monkeypatch `apps.api.tasks.scans.execute_scan.delay`. |
| [`DECISIONS.md`](file:///e:/SeekThreat/SeekThreat/DECISIONS.md) | Modified | Documents ADR **D-014** (Celery + Redis for async scan execution). |
| [`docs/mayank_implementation/build.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/build.md) | Modified | Updates progress checklist to mark Task 4 as complete. |

---

## 3. Design Walk-Through

### 3.1 Celery Application Bootstrap (`apps/api/worker.py`)

Configured centrally using application settings (`settings.redis_url`):

```python
celery_app = Celery(
    "seekthreat",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    enable_utc=True,
    timezone="UTC",
    task_routes={
        "seekthreat.scans.execute": {"queue": "scans"},
    },
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)
```

- **JSON Transport:** Disallows Python pickle to eliminate deserialization exploits.
- **Dedicated Queue:** `scans` route keeps heavy nmap/nuclei scans from monopolizing general-purpose tasks.
- **Late Ack:** Tasks are acknowledged only upon completion, preventing silent scan job drops.

### 3.2 The Async Task (`apps/api/tasks/scans.py`)

Because Celery messages must be JSON-serializable, complex Pydantic models cannot be sent directly across the Redis wire. The API serializes `Authorization` via:
```python
auth_dict = auth.model_dump(mode="json")
```
Inside the worker task, `Authorization` is reconstructed faithfully:
```python
@celery_app.task(
    bind=True,
    name="seekthreat.scans.execute",
    max_retries=3,
    default_retry_delay=30,
)
def execute_scan(
    self: Any,
    scan_id: str,
    engagement_id: str,
    scanner: str,
    target: str,
    options: dict[str, Any],
    authorization_dict: dict[str, Any],
) -> None:
    authorization = Authorization.model_validate(authorization_dict)
    ...
```

**Lifecycle execution flow:**
1. Opens an isolated worker DB session (`SessionLocal()`).
2. Marks scan status as `"running"`.
3. Dispatches to the requested adapter (`NmapAdapter`).
4. Idempotently writes `RawArtifact` and `Observation` rows via `save_scan_result(db, scan_result)`.
5. Marks scan status as `"completed"` with `artifact_id` and `completed_at`.
6. Emits structured audit event `scan.completed`.
7. Catches transient or fatal exceptions: marks status as `"failed"`, records `error_message`, and emits `scan.failed` audit event.

### 3.3 API Router Integration (`apps/api/routers/scans.py`)

In `POST /scans`, authorization is first verified at the choke point. Once accepted, the pending record is saved, and `execute_scan.delay(...)` is invoked:

```python
auth_dict = authorization.model_dump(mode="json")
execute_scan.delay(
    scan_id=scan.scan_id,
    engagement_id=scan.engagement_id,
    scanner=scan.scanner,
    target=scan.target,
    options=scan.options,
    authorization_dict=auth_dict,
)
```

### 3.4 Docker Containerization & Compose (`infra/docker-compose.yml`)

The root Dockerfile provides a multi-purpose runtime with `nmap` installed:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

In `infra/docker-compose.yml`, both `api` and `worker` are defined under the `core` profile with health-checked dependencies:

```yaml
  api:
    profiles: ["core"]
    build:
      context: ..
      dockerfile: apps/api/Dockerfile
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    command: uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

  worker:
    profiles: ["core"]
    build:
      context: ..
      dockerfile: apps/api/Dockerfile
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
    command: celery -A apps.api.worker.celery_app worker --loglevel=info --queues=scans
```

---

## 4. Test Verification

### Targeted Unit Tests
```bash
python -m pytest tests/unit/test_api.py tests/unit/test_celery_task.py -v
```
**Results:**
```
tests/unit/test_api.py ..................                                [ 85%]
tests/unit/test_celery_task.py ...                                       [100%]
============================= 21 passed in 13.40s =============================
```

### Full Repository Test Suite
```bash
python -m pytest tests/ -v
```
**Results:**
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 150 items

tests\architecture\test_authorization_gate.py ....                       [  2%]
tests\architecture\test_import_firewall.py ....                          [  5%]
tests\unit\test_alembic.py .                                             [  6%]
tests\unit\test_api.py ..................                                [ 18%]
tests\unit\test_authorization_matching.py .......................        [ 33%]
tests\unit\test_celery_task.py ...                                       [ 35%]
tests\unit\test_engagement.py ....                                       [ 38%]
tests\unit\test_finding.py ........                                      [ 43%]
tests\unit\test_graph_models.py .............                            [ 52%]
tests\unit\test_nmap_xml.py ...................................          [ 75%]
tests\unit\test_observation.py ...........                               [ 82%]
tests\unit\test_persistence.py .........                                 [ 88%]
tests\unit\test_provenance.py .....                                      [ 92%]
tests\unit\test_scanner_base.py .....                                    [ 95%]
tests\unit\test_scoring.py ......                                        [ 99%]
tests\unit\test_smoke.py .                                               [100%]

============================= 150 passed in 4.42s =============================
```

---

## 5. Summary & Next Steps

Task 4 completes the infrastructure wiring of the collection layer:
- Scan execution runs independently via Celery + Redis.
- Postgres stores raw artifacts and observations idempotently.
- Authorization is verified before any scan is queued or dispatched.
- All 150 automated tests pass cleanly.

**Next:** Task 5 — Second Core Scanner: Nuclei Adapter (`services/scanners/nuclei_adapter.py` and `nuclei_json.py`).
