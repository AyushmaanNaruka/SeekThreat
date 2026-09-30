"""Unit tests for the /findings API endpoints.

Verifies:
- GET /findings/{finding_id} (retrieval and 404 behavior)
- GET /findings?engagement_id=... (pagination, limit, offset)
- POST /findings/enrich (synchronous single finding enrichment & persistence)
- POST /findings/enrich/batch (synchronous and async Celery dispatch)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.db.base import Base
from apps.api.db.repositories import EnrichedFindingRepository
from apps.api.db.session import get_db
from apps.api.main import app
from packages.schema.models.finding import Finding
from services.enrichment.service import EnrichmentService
from tests.fixtures.findings.baseline_findings import (
    ENGAGEMENT_ID,
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_LOG4SHELL,
    FINDING_SPRING_GATEWAY_RCE,
)

NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)


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


# ---------------------------------------------------------------------------
# GET /findings/{finding_id} Tests
# ---------------------------------------------------------------------------


class TestGetEnrichedFindingEndpoint:
    """Tests for GET /findings/{finding_id}."""

    def test_get_nonexistent_finding_returns_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/findings/nonexistent-001")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_get_existing_finding_returns_200_with_enriched_payload(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        service = EnrichmentService(repository=EnrichedFindingRepository(db_session))
        service.enrich_finding(FINDING_LOG4SHELL, persist=True)
        db_session.commit()

        resp = api_client.get(f"/findings/{FINDING_LOG4SHELL.finding_id}")
        assert resp.status_code == 200
        data = resp.json()

        assert data["finding"]["finding_id"] == FINDING_LOG4SHELL.finding_id
        assert "fields" in data
        assert "cvss_score" in data["fields"]
        assert "ers" in data
        assert data["ers"]["value"] > 0.0


# ---------------------------------------------------------------------------
# GET /findings?engagement_id=... Tests
# ---------------------------------------------------------------------------


class TestListEnrichedFindingsEndpoint:
    """Tests for GET /findings with engagement filtering and pagination."""

    def test_list_empty_engagement_returns_empty_page(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/findings?engagement_id=eng-empty")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["offset"] == 0

    def test_list_findings_returns_paginated_records(
        self, api_client: TestClient, db_session: Session
    ) -> None:
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

        # Disjoint items check
        ids1 = {item["finding"]["finding_id"] for item in page1["items"]}
        ids2 = {item["finding"]["finding_id"] for item in page2["items"]}
        assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# POST /findings/enrich Tests
# ---------------------------------------------------------------------------


class TestEnrichSingleFindingEndpoint:
    """Tests for POST /findings/enrich."""

    def test_enrich_single_finding_synchronously(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        payload = FINDING_LOG4SHELL.model_dump(mode="json")
        resp = api_client.post("/findings/enrich?persist=true", json=payload)
        assert resp.status_code == 200

        data = resp.json()
        assert data["finding"]["finding_id"] == FINDING_LOG4SHELL.finding_id
        assert data["fields"]["cvss_score"]["value"] > 0.0
        assert data["ers"] is not None

        # Verify persisted in database
        repo = EnrichedFindingRepository(db_session)
        assert repo.get(FINDING_LOG4SHELL.finding_id) is not None


# ---------------------------------------------------------------------------
# POST /findings/enrich/batch Tests
# ---------------------------------------------------------------------------


class TestBatchEnrichFindingsEndpoint:
    """Tests for POST /findings/enrich/batch."""

    def test_batch_enrich_empty_payload(self, api_client: TestClient) -> None:
        resp = api_client.post("/findings/enrich/batch", json={"findings": []})
        assert resp.status_code == 200
        assert resp.json()["status"] == "empty"
        assert resp.json()["count"] == 0

    def test_batch_enrich_synchronous(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        findings_payload = [
            FINDING_LOG4SHELL.model_dump(mode="json"),
            FINDING_APACHE_PATH_TRAVERSAL.model_dump(mode="json"),
        ]
        resp = api_client.post(
            "/findings/enrich/batch",
            json={
                "findings": findings_payload,
                "engagement_id": ENGAGEMENT_ID,
                "async_dispatch": False,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["count"] == 2
        assert len(data["items"]) == 2

        # Verify records exist in database
        repo = EnrichedFindingRepository(db_session)
        assert repo.count_by_engagement(ENGAGEMENT_ID) == 2

    def test_batch_enrich_async_celery_dispatch(self, api_client: TestClient) -> None:
        findings_payload = [
            FINDING_LOG4SHELL.model_dump(mode="json"),
            FINDING_APACHE_PATH_TRAVERSAL.model_dump(mode="json"),
        ]

        with patch("apps.api.tasks.enrichment.enrich_findings.delay") as mock_delay:
            resp = api_client.post(
                "/findings/enrich/batch",
                json={
                    "findings": findings_payload,
                    "engagement_id": ENGAGEMENT_ID,
                    "async_dispatch": True,
                },
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
