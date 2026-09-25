"""Unit tests for Task 3: API Endpoints & Authorization Choke Point.

Tests cover:
- POST /engagements: create, validate, reject invalid
- GET /engagements/{id}: retrieve and 404
- GET /engagements: list
- POST /scans: authorization gate (authorized, unauthorized target, expired, 404 engagement)
- GET /scans/{id}: status and observation count
- Audit log events emitted
- Alembic migration 0002 upgrade/downgrade
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db import models as _models  # noqa: F401 – side-effect: registers all tables

# Import all ORM models *before* calling create_all so they register on Base.metadata
from apps.api.db.base import Base
from apps.api.db.session import get_db
from apps.api.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    """SQLite in-memory engine with FK enforcement and StaticPool for thread safety."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(eng, "connect")
    def set_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def db_session(engine):
    """Transactional session bound to the in-memory engine."""
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture
def api_client(db_session: Session, monkeypatch):
    """TestClient wired to override get_db with the isolated in-memory session.

    The Celery scan task's ``.delay()`` method is monkeypatched to a no-op so
    tests exercise only the API contract and authorization gate without needing
    a live Redis broker or running a live nmap scan.
    """
    import apps.api.tasks.scans as tasks_module

    class _NoopAsyncResult:
        id = "test-task-id"

    def _noop_delay(*args, **kwargs) -> _NoopAsyncResult:  # pragma: no cover
        """Unit tests do not dispatch real Celery tasks."""
        return _NoopAsyncResult()

    monkeypatch.setattr(tasks_module.execute_scan, "delay", _noop_delay)

    def _override_get_db():
        try:
            yield db_session
        finally:
            pass  # lifecycle managed by db_session fixture

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_audit_log():
    """Clear audit log before every test."""
    clear_audit_log()
    yield
    clear_audit_log()


def _future(hours: int = 1) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)


def _past(hours: int = 1) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _valid_engagement_payload(**overrides: Any) -> dict[str, Any]:
    return {
        "engagement_id": "eng-test-001",
        "name": "Lab Test Engagement",
        "authorized_by": "test-operator",
        "allowlist": ["172.20.0.0/16"],
        "granted_at": _past(2).isoformat(),
        "expires_at": _future(24).isoformat(),
        **overrides,
    }


# ---------------------------------------------------------------------------
# POST /engagements tests
# ---------------------------------------------------------------------------


def test_create_engagement_success(api_client: TestClient) -> None:
    resp = api_client.post("/engagements", json=_valid_engagement_payload())
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["engagement_id"] == "eng-test-001"
    assert data["authorized_by"] == "test-operator"
    assert "172.20.0.0/16" in data["allowlist"]


def test_create_engagement_rejects_empty_allowlist(api_client: TestClient) -> None:
    payload = _valid_engagement_payload(allowlist=[])
    resp = api_client.post("/engagements", json=payload)
    assert resp.status_code == 422, resp.text


def test_create_engagement_rejects_blank_authorized_by(api_client: TestClient) -> None:
    for bad_auth in ["", "   ", "\t"]:
        payload = _valid_engagement_payload(authorized_by=bad_auth)
        resp = api_client.post("/engagements", json=payload)
        assert resp.status_code == 422, (
            f"Expected 422 for authorized_by={bad_auth!r}, got: {resp.status_code}"
        )



def test_create_engagement_rejects_inverted_time_window(api_client: TestClient) -> None:
    payload = _valid_engagement_payload(
        granted_at=_future(2).isoformat(),
        expires_at=_future(1).isoformat(),
    )
    resp = api_client.post("/engagements", json=payload)
    # expires_at <= granted_at raises HTTPException 422 in the router
    assert resp.status_code in (422, 400), resp.text


def test_create_engagement_emits_audit_event(api_client: TestClient) -> None:
    api_client.post("/engagements", json=_valid_engagement_payload())
    events = get_audit_log()
    assert any(e["event"] == "engagement.created" for e in events)


# ---------------------------------------------------------------------------
# GET /engagements/{id} tests
# ---------------------------------------------------------------------------


def test_get_engagement_found(api_client: TestClient) -> None:
    api_client.post("/engagements", json=_valid_engagement_payload())
    resp = api_client.get("/engagements/eng-test-001")
    assert resp.status_code == 200, resp.text
    assert resp.json()["engagement_id"] == "eng-test-001"


def test_get_engagement_not_found(api_client: TestClient) -> None:
    resp = api_client.get("/engagements/no-such-eng")
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# GET /engagements tests
# ---------------------------------------------------------------------------


def test_list_engagements_empty(api_client: TestClient) -> None:
    resp = api_client.get("/engagements")
    assert resp.status_code == 200, resp.text
    assert resp.json() == []


def test_list_engagements_returns_created(api_client: TestClient) -> None:
    api_client.post("/engagements", json=_valid_engagement_payload())
    resp = api_client.get("/engagements")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) == 1


# ---------------------------------------------------------------------------
# POST /scans authorization gate tests
# ---------------------------------------------------------------------------


def _create_engagement(api_client: TestClient, **overrides: Any) -> str:
    payload = _valid_engagement_payload(**overrides)
    resp = api_client.post("/engagements", json=payload)
    assert resp.status_code == 201, f"Failed to create engagement: {resp.text}"
    return payload["engagement_id"]


def test_scan_target_within_cidr_accepted(api_client: TestClient) -> None:
    """Target inside the authorized CIDR returns 202 Accepted."""
    eng_id = _create_engagement(api_client)

    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": eng_id,
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["engagement_id"] == eng_id
    assert data["status"] == "pending"
    assert "scan_id" in data


def test_scan_target_outside_cidr_rejected(api_client: TestClient) -> None:
    """Target outside the authorized CIDR returns 403 Forbidden."""
    eng_id = _create_engagement(api_client)

    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": eng_id,
            "scanner": "nmap",
            "target": "10.0.0.1",
        },
    )
    assert resp.status_code == 403, resp.text


def test_scan_nonexistent_engagement_returns_404(api_client: TestClient) -> None:
    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": "does-not-exist",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp.status_code == 404, resp.text


def test_scan_expired_engagement_returns_403(api_client: TestClient) -> None:
    """An engagement whose authorization window has already closed returns 403."""
    eng_id = _create_engagement(
        api_client,
        engagement_id="eng-expired",
        granted_at=_past(48).isoformat(),
        expires_at=_past(1).isoformat(),
    )

    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": eng_id,
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp.status_code == 403, resp.text


def test_scan_rejected_emits_audit_event(api_client: TestClient) -> None:
    eng_id = _create_engagement(api_client)
    clear_audit_log()

    api_client.post(
        "/scans",
        json={
            "engagement_id": eng_id,
            "scanner": "nmap",
            "target": "10.0.0.1",  # outside allowlist
        },
    )

    events = get_audit_log()
    rejected_events = [e for e in events if e["event"] == "scan.rejected"]
    assert len(rejected_events) == 1, f"Expected 1 rejected event, got: {events}"
    assert rejected_events[0]["target"] == "10.0.0.1"
    assert rejected_events[0]["status"] == "forbidden"


def test_scan_accepted_emits_audit_event(api_client: TestClient) -> None:
    eng_id = _create_engagement(api_client)
    clear_audit_log()

    api_client.post(
        "/scans",
        json={
            "engagement_id": eng_id,
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )

    events = get_audit_log()
    accepted_events = [e for e in events if e["event"] == "scan.accepted"]
    assert len(accepted_events) == 1, f"Expected 1 accepted event, got: {events}"
    assert accepted_events[0]["status"] == "authorized"


# ---------------------------------------------------------------------------
# GET /scans/{id} tests
# ---------------------------------------------------------------------------


def test_get_scan_status_found(api_client: TestClient) -> None:
    eng_id = _create_engagement(api_client)
    create_resp = api_client.post(
        "/scans",
        json={"engagement_id": eng_id, "scanner": "nmap", "target": "172.20.1.10"},
    )
    assert create_resp.status_code == 202, create_resp.text
    scan_id = create_resp.json()["scan_id"]

    status_resp = api_client.get(f"/scans/{scan_id}")
    assert status_resp.status_code == 200, status_resp.text
    data = status_resp.json()
    assert data["scan_id"] == scan_id
    assert data["engagement_id"] == eng_id
    assert data["target"] == "172.20.1.10"
    assert data["observation_count"] == 0


def test_get_scan_not_found(api_client: TestClient) -> None:
    resp = api_client.get("/scans/no-such-scan")
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# GET /scans list tests
# ---------------------------------------------------------------------------


def test_list_scans_returns_accepted_scans(api_client: TestClient) -> None:
    eng_id = _create_engagement(api_client)
    r1 = api_client.post(
        "/scans", json={"engagement_id": eng_id, "scanner": "nmap", "target": "172.20.1.10"}
    )
    r2 = api_client.post(
        "/scans", json={"engagement_id": eng_id, "scanner": "nmap", "target": "172.20.1.11"}
    )
    assert r1.status_code == 202, r1.text
    assert r2.status_code == 202, r2.text

    resp = api_client.get(f"/scans?engagement_id={eng_id}")
    assert resp.status_code == 200, resp.text
    assert len(resp.json()) == 2


def test_list_scans_unfiltered_defaults_limit(api_client: TestClient) -> None:
    eng_id = _create_engagement(api_client)
    for i in range(3):
        r = api_client.post(
            "/scans",
            json={"engagement_id": eng_id, "scanner": "nmap", "target": f"172.20.1.{10 + i}"},
        )
        assert r.status_code == 202
    resp = api_client.get("/scans")
    assert resp.status_code == 200, resp.text
    items = resp.json()
    assert len(items) >= 3
    # Also verify custom limit works
    resp_limit = api_client.get("/scans?limit=2")
    assert resp_limit.status_code == 200
    assert len(resp_limit.json()) == 2



# ---------------------------------------------------------------------------
# Alembic migration 0002 tests
# ---------------------------------------------------------------------------


def test_alembic_migration_0002_upgrade_and_downgrade(tmp_path: Path) -> None:
    """Verify migration 0002 creates and cleanly drops engagements and scans tables."""
    from alembic.config import Config
    from sqlalchemy import create_engine, inspect

    from alembic import command

    db_file = tmp_path / "test_0002.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # Upgrade to head (includes 0001 and 0002)
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(db_url)
    tables = set(inspect(engine).get_table_names())
    assert "engagements" in tables, f"engagements not found in {tables}"
    assert "scans" in tables, f"scans not found in {tables}"

    eng_cols = {c["name"] for c in inspect(engine).get_columns("engagements")}
    expected_eng_cols = {
        "engagement_id",
        "name",
        "authorized_by",
        "allowlist",
        "granted_at",
        "expires_at",
        "created_at",
    }
    assert expected_eng_cols.issubset(eng_cols)

    scan_cols = {c["name"] for c in inspect(engine).get_columns("scans")}
    expected_scan_cols = {
        "scan_id",
        "engagement_id",
        "scanner",
        "target",
        "status",
        "options",
        "artifact_id",
        "created_at",
    }
    assert expected_scan_cols.issubset(scan_cols)

    engine.dispose()

    # Downgrade: head -> 0001 (removes engagements and scans only)
    command.downgrade(alembic_cfg, "0001")

    engine = create_engine(db_url)
    tables_after = set(inspect(engine).get_table_names())
    assert "engagements" not in tables_after, (
        f"engagements still present after downgrade: {tables_after}"
    )
    assert "scans" not in tables_after, f"scans still present after downgrade: {tables_after}"
    assert "raw_artifacts" in tables_after
    assert "observations" in tables_after
    engine.dispose()


# ---------------------------------------------------------------------------
# POST /engagements — duplicate engagement_id must not rewrite authorization
# ---------------------------------------------------------------------------


def test_create_engagement_duplicate_id_is_rejected(api_client: TestClient) -> None:
    """Re-POSTing an existing engagement_id must not silently succeed.

    The repository upserts by primary key, so without an existence check the
    second POST rewrote the authorization scope of a live engagement and
    returned 201 as though it had created something new.
    """
    first = api_client.post("/engagements", json=_valid_engagement_payload())
    assert first.status_code == 201, first.text

    second = api_client.post(
        "/engagements",
        json=_valid_engagement_payload(
            authorized_by="someone-else",
            allowlist=["0.0.0.0/0"],
        ),
    )
    assert second.status_code == 409, second.text


def test_create_engagement_duplicate_does_not_widen_allowlist(api_client: TestClient) -> None:
    """The original authorization must survive a rejected duplicate POST.

    This is the security-relevant half: CLAUDE.md hard rule 2 puts the
    allowlist and named authorizer at the centre of the scan gate, so an
    unauthenticated caller must not be able to replace either one.
    """
    api_client.post("/engagements", json=_valid_engagement_payload())

    api_client.post(
        "/engagements",
        json=_valid_engagement_payload(
            authorized_by="attacker",
            allowlist=["0.0.0.0/0"],
        ),
    )

    current = api_client.get("/engagements/eng-test-001").json()
    assert current["authorized_by"] == "test-operator"
    assert current["allowlist"] == ["172.20.0.0/16"]
    assert "0.0.0.0/0" not in current["allowlist"]


# ---------------------------------------------------------------------------
# POST /engagements — naive datetimes are a client error, not a server error
# ---------------------------------------------------------------------------


def test_create_engagement_rejects_naive_granted_at(api_client: TestClient) -> None:
    """A naive datetime is malformed input: 422, not an unhandled 500.

    require_aware() raised ValueError inside the route body, which FastAPI does
    not translate -- it surfaced as a 500. Validation belongs on the request
    model so the framework renders the error.
    """
    payload = _valid_engagement_payload(granted_at="2026-01-01T00:00:00")
    resp = api_client.post("/engagements", json=payload)
    assert resp.status_code == 422, resp.text


def test_create_engagement_rejects_naive_expires_at(api_client: TestClient) -> None:
    payload = _valid_engagement_payload(expires_at="2027-01-01T00:00:00")
    resp = api_client.post("/engagements", json=payload)
    assert resp.status_code == 422, resp.text


def test_create_engagement_accepts_non_utc_offset(api_client: TestClient) -> None:
    """Aware is the requirement, not UTC specifically."""
    payload = _valid_engagement_payload(
        granted_at="2026-01-01T00:00:00+05:30",
        expires_at="2027-01-01T00:00:00+05:30",
    )
    resp = api_client.post("/engagements", json=payload)
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# POST /scans — broker failure returns 503 and marks scan failed
# ---------------------------------------------------------------------------


def test_create_scan_broker_failure_returns_503(
    api_client: TestClient, monkeypatch
) -> None:
    """When the Celery broker is down, POST /scans returns 503.

    Before PR #14 the API fell back to an in-process thread, which violated
    hard rules 2 and 4 (wrong network context, broken audit trail, daemon
    thread could leave scans stuck). The 503 was the intentional behaviour:
    the caller knows the scan was not dispatched and can retry.
    """
    import apps.api.tasks.scans as tasks_module

    def _broker_down(*args: Any, **kwargs: Any) -> None:
        raise OSError("Redis connection refused")

    monkeypatch.setattr(tasks_module.execute_scan, "delay", _broker_down)

    api_client.post("/engagements", json=_valid_engagement_payload())
    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": "eng-test-001",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp.status_code == 503, resp.text
    assert "queue unavailable" in resp.json()["detail"].lower()


def test_create_scan_broker_failure_marks_scan_failed(
    api_client: TestClient, db_session: Session, monkeypatch
) -> None:
    """When the broker is down the scan row is left in 'failed' state.

    A 503 with no scan row would make recovery impossible. The row must
    exist and be in 'failed' state so the caller can diagnose the outage.
    """
    import apps.api.tasks.scans as tasks_module
    from apps.api.db.repositories import ScanRepository

    def _broker_down(*args: Any, **kwargs: Any) -> None:
        raise OSError("Redis connection refused")

    monkeypatch.setattr(tasks_module.execute_scan, "delay", _broker_down)

    api_client.post("/engagements", json=_valid_engagement_payload())

    resp = api_client.post(
        "/scans",
        json={
            "engagement_id": "eng-test-001",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp.status_code == 503, resp.text

    # Retrieve the failed scan row directly from the shared test DB session
    db_session.expire_all()
    scan_repo = ScanRepository(db_session)
    scans = scan_repo.list_by_engagement("eng-test-001")
    assert len(scans) == 1
    assert scans[0].status == "failed"
    assert scans[0].error_message is not None
    assert "Dispatch failed" in scans[0].error_message



def test_broker_failure_emits_dispatch_failed_audit_event(
    api_client: TestClient, monkeypatch
) -> None:
    """Broker outage must emit scan.dispatch_failed in the audit log."""
    import apps.api.tasks.scans as tasks_module

    def _broker_down(*args: Any, **kwargs: Any) -> None:
        raise OSError("Redis connection refused")

    monkeypatch.setattr(tasks_module.execute_scan, "delay", _broker_down)

    api_client.post("/engagements", json=_valid_engagement_payload())
    clear_audit_log()
    api_client.post(
        "/scans",
        json={
            "engagement_id": "eng-test-001",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )

    events = get_audit_log()
    failed_events = [e for e in events if e["event"] == "scan.dispatch_failed"]
    assert len(failed_events) == 1
    assert failed_events[0]["target"] == "172.20.1.10"



# ---------------------------------------------------------------------------
# CORS -- the browser-based dashboard (apps/web, Next.js dev server on
# http://localhost:3000) is a different origin from this API
# (http://localhost:8000). Without CORS middleware, every cross-origin
# browser request is blocked by the browser itself before it even reaches
# these routes. See docs/03-dashboard-spec.md, Blocker 1.
# ---------------------------------------------------------------------------


def test_health_reflects_allowed_origin_in_cors_header(api_client: TestClient) -> None:
    resp = api_client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert resp.status_code == 200, resp.text
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_preflight_options_request_succeeds_with_cors_headers(api_client: TestClient) -> None:
    resp = api_client.options(
        "/health",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.headers["access-control-allow-origin"] == "http://localhost:3000"
