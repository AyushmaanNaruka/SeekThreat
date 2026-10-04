"""Unit tests for the /findings API endpoints.

Verifies:
- GET /findings/{finding_id}?engagement_id=... (engagement-scoped retrieval, 404s, audit)
- GET /findings?engagement_id=... (pagination ordered by finding_id, audit)
- POST /findings/enrich (engagement + observation provenance gate, audit, persistence)
- POST /findings/enrich/batch (same gate, max batch size, async Celery dispatch)
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db import models as _models  # noqa: F401 – side-effect: registers all tables
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    RawArtifactRepository,
)
from apps.api.db.session import get_db
from apps.api.main import app
from apps.api.routers.findings import MAX_BATCH_SIZE
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import Finding
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.enrichment.service import EnrichmentService
from tests.fixtures.findings.baseline_findings import (
    ENGAGEMENT_ID,
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_LOG4SHELL,
    FINDING_SPRING_GATEWAY_RCE,
)

NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
AUTHORIZER = "lab-operator"
ARTIFACT_ID = "sha256:" + "b" * 64


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


def _seed_engagement(db_session: Session, engagement_id: str = ENGAGEMENT_ID) -> None:
    now = datetime.now(UTC)
    EngagementRepository(db_session).save(
        Engagement(
            engagement_id=engagement_id,
            name="Lab baseline engagement",
            authorization=Authorization(
                engagement_id=engagement_id,
                authorized_by=AUTHORIZER,
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db_session.commit()


def _seed_observations(
    db_session: Session,
    findings: Iterable[Finding],
    engagement_id: str = ENGAGEMENT_ID,
) -> None:
    """Persist one observation per observation_id the findings cite."""
    if not RawArtifactRepository(db_session).exists(ARTIFACT_ID):
        RawArtifactRepository(db_session).save(
            RawArtifact(
                artifact_id=ARTIFACT_ID,
                scanner="nuclei",
                content="{}",
                content_type="application/json",
                captured_at=NOW,
            )
        )
    observations = [
        Observation(
            observation_id=obs_id,
            engagement_id=engagement_id,
            scanner="nuclei",
            kind=ObservationKind.PORT_OPEN,
            subject="172.20.1.10:80/tcp",
            attributes={"port": "80"},
            artifact_id=ARTIFACT_ID,
            observed_at=NOW,
            provenance=Provenance(
                source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
            ),
        )
        for finding in findings
        for obs_id in finding.observation_ids
    ]
    ObservationRepository(db_session).save_all(observations)
    db_session.commit()


def _seed_lab(db_session: Session, findings: Iterable[Finding]) -> None:
    _seed_engagement(db_session)
    _seed_observations(db_session, findings)


def _batch_payload(findings: Iterable[Finding], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "findings": [f.model_dump(mode="json") for f in findings],
        "engagement_id": ENGAGEMENT_ID,
        "async_dispatch": False,
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# GET /findings/{finding_id} Tests
# ---------------------------------------------------------------------------


class TestGetEnrichedFindingEndpoint:
    """Tests for GET /findings/{finding_id}."""

    def test_get_requires_engagement_scope(self, api_client: TestClient) -> None:
        resp = api_client.get("/findings/nonexistent-001")
        assert resp.status_code == 422

    def test_get_unknown_engagement_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/findings/nonexistent-001?engagement_id=eng-missing")
        assert resp.status_code == 404

    def test_get_nonexistent_finding_returns_404(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        resp = api_client.get(f"/findings/nonexistent-001?engagement_id={ENGAGEMENT_ID}")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_get_existing_finding_returns_200_with_enriched_payload(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        service = EnrichmentService(repository=EnrichedFindingRepository(db_session))
        service.enrich_finding(FINDING_LOG4SHELL, persist=True)
        db_session.commit()

        resp = api_client.get(
            f"/findings/{FINDING_LOG4SHELL.finding_id}?engagement_id={ENGAGEMENT_ID}"
        )
        assert resp.status_code == 200
        data = resp.json()

        assert data["finding"]["finding_id"] == FINDING_LOG4SHELL.finding_id
        assert "fields" in data
        assert "cvss_score" in data["fields"]
        assert "ers" in data
        assert data["ers"]["value"] > 0.0

    def test_get_does_not_leak_findings_from_another_engagement(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        _seed_engagement(db_session, engagement_id="eng-other")
        service = EnrichmentService(repository=EnrichedFindingRepository(db_session))
        service.enrich_finding(FINDING_LOG4SHELL, persist=True)
        db_session.commit()

        resp = api_client.get(f"/findings/{FINDING_LOG4SHELL.finding_id}?engagement_id=eng-other")
        assert resp.status_code == 404

    def test_get_is_audited_with_actor_and_engagement(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        api_client.get(f"/findings/nonexistent-001?engagement_id={ENGAGEMENT_ID}")

        audits = [a for a in get_audit_log() if a["event"] == "findings.queried"]
        assert len(audits) == 1
        assert audits[0]["actor"] == AUTHORIZER
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID
        assert audits[0]["target"] == "nonexistent-001"


# ---------------------------------------------------------------------------
# GET /findings?engagement_id=... Tests
# ---------------------------------------------------------------------------


class TestListEnrichedFindingsEndpoint:
    """Tests for GET /findings with engagement filtering and pagination."""

    def test_list_unknown_engagement_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/findings?engagement_id=eng-missing")
        assert resp.status_code == 404

    def test_list_empty_engagement_returns_empty_page(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session, engagement_id="eng-empty")
        resp = api_client.get("/findings?engagement_id=eng-empty")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["offset"] == 0

    def test_list_is_audited(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        api_client.get(f"/findings?engagement_id={ENGAGEMENT_ID}")

        audits = [a for a in get_audit_log() if a["event"] == "findings.queried"]
        assert len(audits) == 1
        assert audits[0]["actor"] == AUTHORIZER
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID

    def test_list_findings_returns_paginated_records_ordered_by_finding_id(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        service = EnrichmentService(repository=EnrichedFindingRepository(db_session))
        service.enrich_batch(
            [
                FINDING_LOG4SHELL,
                FINDING_APACHE_PATH_TRAVERSAL,
                FINDING_SPRING_GATEWAY_RCE,
            ],
            persist=True,
        )
        db_session.commit()

        # Page 1: limit=2
        resp = api_client.get(f"/findings?engagement_id={ENGAGEMENT_ID}&limit=2&offset=0")
        assert resp.status_code == 200
        page1 = resp.json()
        assert len(page1["items"]) == 2
        assert page1["total"] == 3
        assert page1["limit"] == 2
        assert page1["offset"] == 0

        # Page 2: limit=2, offset=2
        resp2 = api_client.get(f"/findings?engagement_id={ENGAGEMENT_ID}&limit=2&offset=2")
        assert resp2.status_code == 200
        page2 = resp2.json()
        assert len(page2["items"]) == 1
        assert page2["total"] == 3

        ordered = [item["finding"]["finding_id"] for item in page1["items"] + page2["items"]]
        assert ordered == sorted(
            [
                FINDING_LOG4SHELL.finding_id,
                FINDING_APACHE_PATH_TRAVERSAL.finding_id,
                FINDING_SPRING_GATEWAY_RCE.finding_id,
            ]
        )


# ---------------------------------------------------------------------------
# POST /findings/enrich Tests
# ---------------------------------------------------------------------------


class TestEnrichSingleFindingEndpoint:
    """Tests for POST /findings/enrich."""

    def test_enrich_single_finding_synchronously(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, [FINDING_LOG4SHELL])
        payload = FINDING_LOG4SHELL.model_dump(mode="json")
        resp = api_client.post("/findings/enrich?persist=true", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        assert data["finding"]["finding_id"] == FINDING_LOG4SHELL.finding_id
        assert data["fields"]["cvss_score"]["value"] > 0.0
        assert data["ers"] is not None

        # Verify persisted in database
        repo = EnrichedFindingRepository(db_session)
        assert repo.get(FINDING_LOG4SHELL.finding_id, engagement_id=ENGAGEMENT_ID) is not None

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.complete"]
        assert len(audits) == 1
        assert audits[0]["actor"] == AUTHORIZER
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID

    def test_enrich_unknown_engagement_returns_404_and_audits(self, api_client: TestClient) -> None:
        resp = api_client.post("/findings/enrich", json=FINDING_LOG4SHELL.model_dump(mode="json"))
        assert resp.status_code == 404

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.rejected"]
        assert len(audits) == 1
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID

    def test_enrich_with_unknown_observation_ids_returns_422(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)  # engagement exists, observations do not
        resp = api_client.post("/findings/enrich", json=FINDING_LOG4SHELL.model_dump(mode="json"))
        assert resp.status_code == 422
        assert "obs-nuclei-log4j-001" in resp.json()["detail"]

        repo = EnrichedFindingRepository(db_session)
        assert repo.count_by_engagement(ENGAGEMENT_ID) == 0

    def test_enrich_with_observations_from_another_engagement_returns_422(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        _seed_engagement(db_session, engagement_id="eng-other")
        _seed_observations(db_session, [FINDING_LOG4SHELL], engagement_id="eng-other")

        resp = api_client.post("/findings/enrich", json=FINDING_LOG4SHELL.model_dump(mode="json"))
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /findings/enrich/batch Tests
# ---------------------------------------------------------------------------


class TestBatchEnrichFindingsEndpoint:
    """Tests for POST /findings/enrich/batch."""

    def test_batch_requires_engagement_id(self, api_client: TestClient) -> None:
        resp = api_client.post("/findings/enrich/batch", json={"findings": []})
        assert resp.status_code == 422

    def test_batch_enrich_empty_payload(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        resp = api_client.post(
            "/findings/enrich/batch",
            json={"findings": [], "engagement_id": ENGAGEMENT_ID},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "empty"
        assert resp.json()["count"] == 0

    def test_batch_unknown_engagement_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.post(
            "/findings/enrich/batch",
            json=_batch_payload([FINDING_LOG4SHELL], engagement_id="eng-missing"),
        )
        assert resp.status_code == 404

    def test_batch_rejects_findings_from_another_engagement(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session, engagement_id="eng-other")
        resp = api_client.post(
            "/findings/enrich/batch",
            json=_batch_payload([FINDING_LOG4SHELL], engagement_id="eng-other"),
        )
        assert resp.status_code == 422
        assert FINDING_LOG4SHELL.finding_id in resp.json()["detail"]

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.rejected"]
        assert len(audits) == 1
        assert audits[0]["engagement_id"] == "eng-other"

    def test_batch_rejects_unknown_observation_ids(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, [FINDING_LOG4SHELL])  # apache observations missing
        resp = api_client.post(
            "/findings/enrich/batch",
            json=_batch_payload([FINDING_LOG4SHELL, FINDING_APACHE_PATH_TRAVERSAL]),
        )
        assert resp.status_code == 422
        assert "obs-nmap-port80-001" in resp.json()["detail"]

    def test_batch_rejects_more_than_max_batch_size(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        too_many = [FINDING_LOG4SHELL] * (MAX_BATCH_SIZE + 1)
        resp = api_client.post("/findings/enrich/batch", json=_batch_payload(too_many))
        assert resp.status_code == 422

    def test_batch_enrich_synchronous(self, api_client: TestClient, db_session: Session) -> None:
        findings = [FINDING_LOG4SHELL, FINDING_APACHE_PATH_TRAVERSAL]
        _seed_lab(db_session, findings)
        resp = api_client.post("/findings/enrich/batch", json=_batch_payload(findings))
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["count"] == 2
        assert len(data["items"]) == 2

        # Verify records exist in database
        repo = EnrichedFindingRepository(db_session)
        assert repo.count_by_engagement(ENGAGEMENT_ID) == 2

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.complete"]
        assert len(audits) == 1
        assert audits[0]["actor"] == AUTHORIZER

    def test_batch_enrich_async_celery_dispatch(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        findings = [FINDING_LOG4SHELL, FINDING_APACHE_PATH_TRAVERSAL]
        _seed_lab(db_session, findings)

        with patch("apps.api.tasks.enrichment.enrich_findings.delay") as mock_delay:
            resp = api_client.post(
                "/findings/enrich/batch",
                json=_batch_payload(findings, async_dispatch=True),
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "dispatched"
        assert data["count"] == 2
        assert data["finding_ids"] == [
            FINDING_LOG4SHELL.finding_id,
            FINDING_APACHE_PATH_TRAVERSAL.finding_id,
        ]
        mock_delay.assert_called_once()
        kwargs = mock_delay.call_args.kwargs
        assert kwargs["engagement_id"] == ENGAGEMENT_ID
        assert kwargs["actor"] == AUTHORIZER

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.dispatched"]
        assert len(audits) == 1
        assert audits[0]["actor"] == AUTHORIZER

    def test_batch_broker_failure_returns_503_without_exception_text(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        findings = [FINDING_LOG4SHELL]
        _seed_lab(db_session, findings)

        with patch(
            "apps.api.tasks.enrichment.enrich_findings.delay",
            side_effect=ConnectionError("redis://secret-host:6379 refused"),
        ):
            resp = api_client.post(
                "/findings/enrich/batch",
                json=_batch_payload(findings, async_dispatch=True),
            )

        assert resp.status_code == 503
        assert "secret-host" not in resp.json()["detail"]

        audits = [a for a in get_audit_log() if a["event"] == "enrichment.dispatch_failed"]
        assert len(audits) == 1
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID
