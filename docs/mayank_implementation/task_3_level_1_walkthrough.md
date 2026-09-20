# Task 3 Walkthrough — API Endpoints & Authorization Choke Point

> **Layer:** 1 (Collection)  
> **Task:** 3 of 7  
> **Status:** ✅ Complete — 147/147 tests passing (+18 new)  
> **Files touched:** 6 new files, 1 modified  

---

## 1. Goal

Wire the persistence layer (Task 2) into a FastAPI surface with a **hard authorization choke point** that strictly enforces:

1. The scan target is inside an active engagement's CIDR/hostname allowlist.  
2. The engagement's authorization time window has not expired.  
3. Every check — pass or fail — is written to a structured audit log with actor, target, scanner, timestamp, and status.

> **Architecture rule (from `apps/api/README.md`):**  
> *"Authorization is enforced HERE, not in the UI."*  
> No scan record is created and no background job is dispatched until the choke point passes.

---

## 2. Files Delivered

| File | What It Does |
|---|---|
| `apps/api/core/authorization.py` | Choke-point function — validates time window + CIDR/allowlist |
| `apps/api/core/audit.py` | Structured JSON audit logger with in-memory record for test inspection |
| `apps/api/routers/engagements.py` | `POST /engagements`, `GET /engagements/{id}`, `GET /engagements` |
| `apps/api/routers/scans.py` | `POST /scans`, `GET /scans/{id}`, `GET /scans?engagement_id=` |
| `apps/api/main.py` | Mounts the two new routers |
| `tests/unit/test_api.py` | 18 unit tests for all endpoints and the authorization gate |

---

## 3. Design Walk-Through

### 3.1 The Authorization Choke Point

**`apps/api/core/authorization.py`**

```python
def verify_scan_authorization(
    engagement: Engagement,
    target: str,
    scanner: str = "scanner",
    actor: str | None = None,
) -> Authorization:
```

Called by `POST /scans` **before** a `ScanModel` row is created or any background task is queued. Three ordered checks, all failing with `403 Forbidden`:

| Order | Check | Reason |
|:---:|---|---|
| 1 | `now < auth.granted_at` | Authorization not yet active |
| 2 | `now > auth.expires_at` | Authorization window expired |
| 3 | `not auth.permits(target)` | Target outside CIDR/hostname allowlist |

Every branch — pass or fail — emits a structured audit event (`scan.rejected` or `scan.accepted`) **before** raising or returning. This means there is no code path that touches a scan record without an audit trail.

The function raises `AuthorizationDeniedError` (a subclass of `HTTPException`) so FastAPI surfaces it as a clean 403 with a human-readable `detail` field, without any additional error handling needed in the router.

---

### 3.2 Audit Logger

**`apps/api/core/audit.py`**

```python
def log_audit_event(
    event: str,       # e.g. "scan.accepted", "scan.rejected", "engagement.created"
    actor: str,
    target: str,
    engagement_id: str,
    scanner: str,
    status: str,      # "authorized" | "forbidden" | "success" | "error"
    details: dict | None = None,
) -> dict:
```

Writes a JSON-serialized record to `logging.getLogger("seekthreat.audit")` **and** appends to a module-level `_audit_events` list. The list is only for test inspection (`get_audit_log()` / `clear_audit_log()`).

---

### 3.3 Engagements Router

**`apps/api/routers/engagements.py`**

Three endpoints, all backed by `EngagementRepository` from Task 2:

#### `POST /engagements` → 201 Created

```json
{
  "engagement_id": "eng-001",
  "name": "Q3 Lab Assessment",
  "authorized_by": "lead-engineer",
  "allowlist": ["172.20.0.0/16"],
  "granted_at": "2026-09-01T00:00:00Z",
  "expires_at": "2026-09-30T23:59:59Z"
}
```

Validates using the `Authorization` and `Engagement` domain models (Pydantic). Emits `engagement.created` audit event on success.

#### `GET /engagements/{id}` → 200 / 404
#### `GET /engagements` → 200 list

---

### 3.4 Scans Router

**`apps/api/routers/scans.py`**

#### `POST /scans` → 202 Accepted

Authorization flow is strictly sequential:

```
1. Fetch engagement from DB         → 404 if missing
2. verify_scan_authorization()      → 403 if expired / out-of-scope
3. INSERT ScanModel (status=pending)
4. db.commit()
5. background_tasks.add_task(...)   → dispatches _execute_scan_task
6. Return 202 with scan_id + status
```

#### Background task: `_execute_scan_task`

Runs outside the HTTP request lifetime with its own `SessionLocal()` session:
1. Update status → `"running"`
2. Invoke the adapter: `NmapAdapter().scan(request)`
3. Persist results via `save_scan_result()` (idempotent, Task 2)
4. Update status → `"completed"` with `artifact_id` and `completed_at`
5. Emit `scan.completed` audit event

On any exception: rolls back, updates status → `"failed"`, emits `scan.failed`.

#### `GET /scans/{id}` → 200 / 404

Returns current scan status + `observation_count` (queried from `ObservationRepository`).

#### `GET /scans?engagement_id=` → 200 list

---

## 4. Unit Tests

**`tests/unit/test_api.py`** — 18 tests

### Test infrastructure

**`engine` fixture** — SQLite in-memory with `StaticPool` and `check_same_thread=False`:
- `StaticPool` is required because FastAPI runs sync route handlers in a thread pool.
- All ORM models imported before `Base.metadata.create_all()` to guarantee table registration.

**`api_client` fixture** — overrides `get_db` + monkeypatches the background task:
```python
monkeypatch.setattr(scans_module, "_execute_scan_task", lambda *a, **kw: None)
app.dependency_overrides[get_db] = lambda: db_session
```
The background task no-op prevents the test from connecting to the production DB or running a live nmap scan.

### Test coverage

| Group | Tests |
|---|:---:|
| `POST /engagements` | 4 |
| `GET /engagements/{id}` | 2 |
| `GET /engagements` | 2 |
| `POST /scans` (auth gate) | 6 |
| `GET /scans/{id}` | 2 |
| `GET /scans` | 1 |
| Alembic 0002 migration | 1 |

---

## 5. Test Run Result

```
147 passed in 2.88s
```

**+18 new tests. Zero regressions. 147/147 green.**

---

## 6. Key Design Decisions

### D-T3-01: Authorization before persistence
The DB row is only written **after** `verify_scan_authorization()` returns successfully. If auth fails, nothing is persisted and the audit log records the rejection.

### D-T3-02: Audit log is synchronous and unconditional
`log_audit_event()` is called inside `verify_scan_authorization()` on every branch — not in the router. Authorization logic and audit emission cannot be accidentally separated.

### D-T3-03: Background task uses its own DB session
`_execute_scan_task` calls `SessionLocal()` rather than receiving the request session, since the request session is closed when the HTTP response is returned.

### D-T3-04: Unit tests mock the background task
Unit tests verify the API contract (status codes, shapes, audit events). Live execution belongs to integration tests. Monkeypatching `_execute_scan_task` keeps the suite at ~3s total.

### D-T3-05: `StaticPool` for SQLite thread safety
FastAPI routes run in a `ThreadPoolExecutor`. `StaticPool` + `check_same_thread=False` forces SQLAlchemy to reuse a single connection so in-memory tests share state correctly.

---

## 7. What's Next

| Task | Description |
|---|---|
| **Task 4** | Replace `BackgroundTasks` with a Celery worker + Redis queue |
| **Task 5** | Nuclei scanner adapter |
| **Task 6** | Lab expansion to 8–12 hosts across 3 subnets |
| **Task 7** | Collection Web UI |
