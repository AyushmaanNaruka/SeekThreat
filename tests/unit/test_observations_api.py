"""Unit tests for the observation read path.

Observations were written to the database by Layer 1's Celery task from the
day it shipped, but nothing returned them over HTTP -- GET /scans/{id} only
ever reported an integer count. These two endpoints close that gap:

- GET /observations?engagement_id=          (engagement-scoped, cross-scan)
- GET /scans/{scan_id}/observations         (scoped to one scan's artifact)

Both paginated: a /24 nmap scan can produce thousands of rows.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log
from apps.api.db import models as _models  # noqa: F401 – side-effect: registers all tables
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    ObservationRepository,
    RawArtifactRepository,
    ScanRepository,
)
from apps.api.db.session import get_db
from apps.api.main import app
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
)
from packages.schema.models.provenance import Confidence, Provenance, Source

# ---------------------------------------------------------------------------
# Fixtures (duplicated per test_api.py's own convention -- no shared conftest)
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
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
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture
def api_client(db_session: Session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_audit_log():
    clear_audit_log()
    yield
    clear_audit_log()


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _seed_engagement(db_session: Session, engagement_id: str = "eng-001") -> None:
    now = datetime.now(UTC)
    EngagementRepository(db_session).save(
        Engagement(
            engagement_id=engagement_id,
            name="Test engagement",
            authorization=Authorization(
                engagement_id=engagement_id,
                authorized_by="test-operator",
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db_session.commit()


def _seed_artifact(db_session: Session, artifact_id: str = "sha256:" + "a" * 64) -> RawArtifact:
    artifact = RawArtifact(
        artifact_id=artifact_id,
        scanner="nmap",
        content="<nmaprun/>",
        content_type="application/xml",
        captured_at=datetime(2026, 9, 20, 10, 0, 0, tzinfo=UTC),
    )
    RawArtifactRepository(db_session).save(artifact)
    return artifact


def _observation(
    observation_id: str,
    artifact_id: str,
    engagement_id: str = "eng-001",
    kind: ObservationKind = ObservationKind.PORT_OPEN,
    observed_at: datetime | None = None,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        engagement_id=engagement_id,
        scanner="nmap",
        kind=kind,
        subject="172.20.1.10:80/tcp",
        attributes={"port": "80", "protocol": "tcp"},
        artifact_id=artifact_id,
        observed_at=observed_at or datetime(2026, 9, 20, 10, 0, 0, tzinfo=UTC),
        provenance=Provenance(
            source=Source.SCANNER,
            confidence=Confidence.HIGH,
            retrieved_at=datetime(2026, 9, 20, 10, 0, 0, tzinfo=UTC),
        ),
    )


def _make_payload(**overrides: Any) -> dict[str, Any]:
    now = datetime.now(UTC)
    payload = {
        "engagement_id": "eng-001",
        "name": "Test engagement",
        "authorized_by": "test-operator",
        "allowlist": ["172.20.0.0/16"],
        "granted_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=23)).isoformat(),
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# GET /observations
# ---------------------------------------------------------------------------


def test_list_observations_requires_engagement_id(api_client: TestClient) -> None:
    resp = api_client.get("/observations")
    assert resp.status_code == 422, resp.text


def test_list_observations_empty_for_unknown_engagement(api_client: TestClient) -> None:
    """An engagement nobody has heard of returns an empty page, not a 404.

    Mirrors GET /scans?engagement_id= -- both are query-filtered lists, and an
    unknown filter value is a valid (empty) result, not a missing resource.
    """
    resp = api_client.get("/observations", params={"engagement_id": "no-such-eng"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_list_observations_returns_seeded_observations(
    api_client: TestClient, db_session: Session
) -> None:
    _seed_engagement(db_session)
    artifact = _seed_artifact(db_session)
    obs_repo = ObservationRepository(db_session)
    obs_repo.save_all(
        [
            _observation("obs-1", artifact.artifact_id, kind=ObservationKind.HOST_UP),
            _observation("obs-2", artifact.artifact_id, kind=ObservationKind.PORT_OPEN),
        ]
    )
    db_session.commit()

    resp = api_client.get("/observations", params={"engagement_id": "eng-001"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    assert [o["observation_id"] for o in body["items"]] == ["obs-1", "obs-2"]

    first = body["items"][0]
    assert first["engagement_id"] == "eng-001"
    assert first["scanner"] == "nmap"
    assert first["kind"] == "host_up"
    assert first["subject"] == "172.20.1.10:80/tcp"
    assert first["attributes"] == {"port": "80", "protocol": "tcp"}
    assert first["artifact_id"] == artifact.artifact_id
    assert first["provenance"]["source"] == "scanner"
    assert first["provenance"]["confidence"] == "high"


def test_list_observations_kind_filter(api_client: TestClient, db_session: Session) -> None:
    _seed_engagement(db_session)
    artifact = _seed_artifact(db_session)
    obs_repo = ObservationRepository(db_session)
    obs_repo.save_all(
        [
            _observation("obs-host", artifact.artifact_id, kind=ObservationKind.HOST_UP),
            _observation("obs-port", artifact.artifact_id, kind=ObservationKind.PORT_OPEN),
        ]
    )
    db_session.commit()

    resp = api_client.get("/observations", params={"engagement_id": "eng-001", "kind": "host_up"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert [o["observation_id"] for o in body["items"]] == ["obs-host"]


def test_list_observations_invalid_kind_is_422(api_client: TestClient) -> None:
    resp = api_client.get(
        "/observations", params={"engagement_id": "eng-001", "kind": "not-a-real-kind"}
    )
    assert resp.status_code == 422, resp.text


def test_list_observations_pagination(api_client: TestClient, db_session: Session) -> None:
    _seed_engagement(db_session)
    artifact = _seed_artifact(db_session)
    obs_repo = ObservationRepository(db_session)
    obs_repo.save_all(
        [
            _observation(
                f"obs-{i:02d}",
                artifact.artifact_id,
                observed_at=datetime(2026, 9, 20, 10, i, 0, tzinfo=UTC),
            )
            for i in range(5)
        ]
    )
    db_session.commit()

    resp = api_client.get(
        "/observations",
        params={"engagement_id": "eng-001", "limit": 2, "offset": 2},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 5  # total reflects the full filtered set, not just this page
    assert body["limit"] == 2
    assert body["offset"] == 2
    assert [o["observation_id"] for o in body["items"]] == ["obs-02", "obs-03"]


def test_list_observations_limit_bounds(api_client: TestClient) -> None:
    too_small = api_client.get("/observations", params={"engagement_id": "eng-001", "limit": 0})
    assert too_small.status_code == 422, too_small.text

    too_large = api_client.get(
        "/observations", params={"engagement_id": "eng-001", "limit": 10_000}
    )
    assert too_large.status_code == 422, too_large.text


# ---------------------------------------------------------------------------
# GET /scans/{scan_id}/observations
# ---------------------------------------------------------------------------


def test_scan_observations_not_found(api_client: TestClient) -> None:
    resp = api_client.get("/scans/scan-does-not-exist/observations")
    assert resp.status_code == 404, resp.text


def test_scan_observations_empty_before_completion(
    api_client: TestClient, db_session: Session
) -> None:
    """A pending/running scan has no artifact yet -- an empty page, not an error."""
    _seed_engagement(db_session)
    ScanRepository(db_session).create(
        scan_id="scan-pending", engagement_id="eng-001", scanner="nmap", target="172.20.1.10"
    )
    db_session.commit()

    resp = api_client.get("/scans/scan-pending/observations")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_scan_observations_returns_observations_for_that_scan(
    api_client: TestClient, db_session: Session
) -> None:
    _seed_engagement(db_session)
    artifact = _seed_artifact(db_session)
    obs_repo = ObservationRepository(db_session)
    obs_repo.save_all(
        [
            _observation("obs-a", artifact.artifact_id, kind=ObservationKind.HOST_UP),
            _observation("obs-b", artifact.artifact_id, kind=ObservationKind.PORT_OPEN),
        ]
    )
    scan_repo = ScanRepository(db_session)
    scan_repo.create(
        scan_id="scan-done", engagement_id="eng-001", scanner="nmap", target="172.20.1.10"
    )
    scan_repo.update_status(
        scan_id="scan-done", status="completed", artifact_id=artifact.artifact_id
    )
    db_session.commit()

    resp = api_client.get("/scans/scan-done/observations")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    assert {o["observation_id"] for o in body["items"]} == {"obs-a", "obs-b"}


def test_scan_observations_kind_filter(api_client: TestClient, db_session: Session) -> None:
    _seed_engagement(db_session)
    artifact = _seed_artifact(db_session)
    obs_repo = ObservationRepository(db_session)
    obs_repo.save_all(
        [
            _observation("obs-a", artifact.artifact_id, kind=ObservationKind.HOST_UP),
            _observation("obs-b", artifact.artifact_id, kind=ObservationKind.PORT_OPEN),
        ]
    )
    scan_repo = ScanRepository(db_session)
    scan_repo.create(
        scan_id="scan-done", engagement_id="eng-001", scanner="nmap", target="172.20.1.10"
    )
    scan_repo.update_status(
        scan_id="scan-done", status="completed", artifact_id=artifact.artifact_id
    )
    db_session.commit()

    resp = api_client.get("/scans/scan-done/observations", params={"kind": "port_open"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert [o["observation_id"] for o in body["items"]] == ["obs-b"]
