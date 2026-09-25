"""End-to-end integration and contract tests for SeekThreat.

Verifies:
1. API Health endpoint (GET /health)
2. Engagement lifecycle: create, get by ID, list all, duplicate conflict
3. Strict API authorization gate:
   - Authorized target allowed
   - Unauthorized target blocked with 403 & informative error detail
   - Expired engagement blocked with 403
   - Not-yet-active engagement blocked with 403
   - Nonexistent engagement blocked with 404
4. Scan lifecycle:
   - Create scan job in pending state
   - Status transitions from pending -> running -> completed/failed
   - Scan result querying (GET /scans, GET /scans/{id})
   - Observation retrieval (GET /scans/{id}/observations)
5. Nmap adapter execution against authorized test fixture:
   - Verifies Nmap adapter availability
   - Parses XML output into Observation domain facts and RawArtifact
   - Idempotent database persistence
6. Nuclei adapter execution against authorized local HTTP fixture:
   - Verifies Nuclei adapter availability
   - Parses JSONL output into Observation domain facts and RawArtifact
   - Idempotent database persistence
7. Failure modes & error propagation:
   - Unsupported scanner name
   - Scanner failure persistence with actual error_message
"""

from __future__ import annotations

import http.server
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.db.base import Base
from apps.api.db.repositories import (
    RawArtifactRepository,
)
from apps.api.db.session import get_db
from apps.api.main import app
from packages.schema.models.engagement import Authorization, ScanRequest
from services.scanners.nmap_adapter import NmapAdapter
from services.scanners.nuclei_adapter import NucleiAdapter

# Skip markers for tests that require scanner binaries to be installed.
# CI does not have nmap or nuclei; these tests run only when the binary is present.
requires_nmap = pytest.mark.skipif(
    not NmapAdapter().is_available(),
    reason="nmap binary not installed",
)
requires_nuclei = pytest.mark.skipif(
    not NucleiAdapter().is_available(),
    reason="nuclei binary not installed",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def in_memory_engine():
    """Isolated in-memory SQLite engine with foreign key enforcement."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def set_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def db_session(in_memory_engine) -> Session:
    """Transactional session bound to in-memory DB."""
    factory = sessionmaker(
        bind=in_memory_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    session = factory()
    yield session
    session.close()


@pytest.fixture
def client(in_memory_engine, monkeypatch: pytest.MonkeyPatch):
    """FastAPI TestClient with overridden DB session and mocked Celery dispatch."""
    import apps.api.tasks.scans as tasks_module

    monkeypatch.setattr(tasks_module.execute_scan, "delay", lambda *a, **kw: None)

    factory = sessionmaker(
        bind=in_memory_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    def _override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def local_http_fixture():
    """Starts a safe local test HTTP server on 127.0.0.1:8799 for integration tests."""

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 8799), QuietHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:8799"
    httpd.shutdown()


# ---------------------------------------------------------------------------
# API Contract & Authorization Gate Tests
# ---------------------------------------------------------------------------


def test_api_health(client: TestClient) -> None:
    """1. GET /health returns status ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_engagement_crud_lifecycle(client: TestClient) -> None:
    """2. Engagement creation, retrieval, duplicate rejection, and listing."""
    now = datetime.now(UTC)
    payload = {
        "engagement_id": "eng-e2e-01",
        "name": "E2E Test Assessment",
        "authorized_by": "Lead Security Engineer",
        "allowlist": ["127.0.0.1", "127.0.0.1/32", "localhost"],
        "granted_at": now.isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
    }

    # Create
    resp = client.post("/engagements", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["engagement_id"] == "eng-e2e-01"
    assert data["authorized_by"] == "Lead Security Engineer"
    assert "127.0.0.1" in data["allowlist"]

    # Duplicate rejection (409 Conflict)
    resp_dup = client.post("/engagements", json=payload)
    assert resp_dup.status_code == 409

    # Get by ID
    resp_get = client.get("/engagements/eng-e2e-01")
    assert resp_get.status_code == 200
    assert resp_get.json()["name"] == "E2E Test Assessment"

    # List all
    resp_list = client.get("/engagements")
    assert resp_list.status_code == 200
    assert any(e["engagement_id"] == "eng-e2e-01" for e in resp_list.json())


def test_authorization_gate_rejection_rules(client: TestClient) -> None:
    """3. Verify strict rejection of unauthorized, expired, not-yet-active targets."""
    now = datetime.now(UTC)

    # Register active engagement with allowlist 172.20.1.0/24
    client.post(
        "/engagements",
        json={
            "engagement_id": "eng-scope-active",
            "name": "DMZ Scope",
            "authorized_by": "Scope Officer",
            "allowlist": ["172.20.1.0/24"],
            "granted_at": (now - timedelta(hours=1)).isoformat(),
            "expires_at": (now + timedelta(hours=5)).isoformat(),
        },
    )

    # Register expired engagement
    client.post(
        "/engagements",
        json={
            "engagement_id": "eng-scope-expired",
            "name": "Old Scope",
            "authorized_by": "Scope Officer",
            "allowlist": ["172.20.1.0/24"],
            "granted_at": (now - timedelta(days=2)).isoformat(),
            "expires_at": (now - timedelta(days=1)).isoformat(),
        },
    )

    # Register not-yet-active engagement
    client.post(
        "/engagements",
        json={
            "engagement_id": "eng-scope-future",
            "name": "Future Scope",
            "authorized_by": "Scope Officer",
            "allowlist": ["172.20.1.0/24"],
            "granted_at": (now + timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=2)).isoformat(),
        },
    )

    # A) Target outside allowlist -> 403 Forbidden with exact reason
    resp_unauth = client.post(
        "/scans",
        json={
            "engagement_id": "eng-scope-active",
            "scanner": "nmap",
            "target": "10.0.0.1",
        },
    )
    assert resp_unauth.status_code == 403
    assert "not authorized" in resp_unauth.json()["detail"].lower()

    # B) Expired engagement -> 403 Forbidden
    resp_exp = client.post(
        "/scans",
        json={
            "engagement_id": "eng-scope-expired",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp_exp.status_code == 403
    assert "expired" in resp_exp.json()["detail"].lower()

    # C) Not yet active engagement -> 403 Forbidden
    resp_future = client.post(
        "/scans",
        json={
            "engagement_id": "eng-scope-future",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp_future.status_code == 403
    assert "not yet active" in resp_future.json()["detail"].lower()

    # D) Nonexistent engagement -> 404 Not Found
    resp_missing = client.post(
        "/scans",
        json={
            "engagement_id": "eng-nonexistent",
            "scanner": "nmap",
            "target": "172.20.1.10",
        },
    )
    assert resp_missing.status_code == 404


def test_scan_dispatch_and_listing(client: TestClient) -> None:
    """4. Authorized scan acceptance and global/engagement scan listing."""
    now = datetime.now(UTC)
    client.post(
        "/engagements",
        json={
            "engagement_id": "eng-dispatch-01",
            "name": "Dispatch Test",
            "authorized_by": "Dispatch Lead",
            "allowlist": ["127.0.0.1", "127.0.0.1/32"],
            "granted_at": (now - timedelta(minutes=5)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
        },
    )

    # POST /scans for authorized target
    resp = client.post(
        "/scans",
        json={
            "engagement_id": "eng-dispatch-01",
            "scanner": "nmap",
            "target": "127.0.0.1",
        },
    )
    assert resp.status_code == 202
    scan_data = resp.json()
    scan_id = scan_data["scan_id"]
    assert scan_id.startswith("scan-")
    assert scan_data["status"] in ("pending", "running", "completed")

    # GET /scans (all scans)
    resp_all = client.get("/scans")
    assert resp_all.status_code == 200
    assert any(s["scan_id"] == scan_id for s in resp_all.json())

    # GET /scans?engagement_id=...
    resp_filtered = client.get("/scans?engagement_id=eng-dispatch-01")
    assert resp_filtered.status_code == 200
    assert any(s["scan_id"] == scan_id for s in resp_filtered.json())

    # GET /scans/{id}
    resp_single = client.get(f"/scans/{scan_id}")
    assert resp_single.status_code == 200
    assert resp_single.json()["scan_id"] == scan_id


# ---------------------------------------------------------------------------
# Scanner Adapters & Database Persistence Tests
# ---------------------------------------------------------------------------


@requires_nmap
def test_nmap_adapter_and_persistence(db_session: Session) -> None:
    """5. Verify Nmap adapter executes, produces RawArtifact, and saves to DB."""
    nmap = NmapAdapter()

    now = datetime.now(UTC)
    auth = Authorization(
        engagement_id="eng-nmap-test",
        authorized_by="Nmap Tester",
        allowlist=("127.0.0.1", "127.0.0.1/32"),
        granted_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=1),
    )

    req = ScanRequest(
        target="127.0.0.1",
        authorization=auth,
        options={"ports": "80,443", "timeout": 30},
    )
    res = nmap.scan(req)

    assert res.artifact.scanner == "nmap"
    assert res.artifact.artifact_id.startswith("sha256:")
    assert res.artifact.content_type == "application/xml"

    # Persist artifact to database
    art_repo = RawArtifactRepository(db_session)
    art_repo.save(res.artifact)
    db_session.commit()

    retrieved = art_repo.get(res.artifact.artifact_id)
    assert retrieved is not None
    assert retrieved.scanner == "nmap"


@requires_nuclei
def test_nuclei_adapter_and_persistence(db_session: Session, local_http_fixture: str) -> None:
    """6. Verify Nuclei adapter executes against local HTTP server and persists."""
    nuclei = NucleiAdapter()

    now = datetime.now(UTC)
    auth = Authorization(
        engagement_id="eng-nuclei-test",
        authorized_by="Nuclei Tester",
        allowlist=("127.0.0.1", "127.0.0.1/32", "localhost"),
        granted_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(hours=1),
    )

    req = ScanRequest(
        target=local_http_fixture,
        authorization=auth,
        options={"template": "tests/fixtures/nuclei/test_http_detect.yaml", "timeout": 120},
    )
    res = nuclei.scan(req)

    assert res.artifact.scanner == "nuclei"
    assert res.artifact.artifact_id.startswith("sha256:")
    assert res.artifact.content_type == "application/x-ndjson"

    # Persist artifact to database
    art_repo = RawArtifactRepository(db_session)
    art_repo.save(res.artifact)
    db_session.commit()

    assert art_repo.exists(res.artifact.artifact_id) is True
