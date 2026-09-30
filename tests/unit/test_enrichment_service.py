"""Unit tests for EnrichmentService coordinator and Celery enrichment worker task.

Verifies:
1. Single finding and batch enrichment through EnrichmentService.
2. Optional persistence dispatch and repository querying.
3. Celery async worker task execution, validation, transient retry, and audit logging.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db.base import Base
from apps.api.db.models import EnrichedFindingModel
from apps.api.db.repositories import EnrichedFindingRepository
from apps.api.tasks.enrichment import run_enrichment
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.provenance import Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.service import EnrichmentService
from tests.fixtures.findings.baseline_findings import (
    ENGAGEMENT_ID,
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_LOG4SHELL,
    FINDING_SPRING_GATEWAY_RCE,
)

NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def db_session() -> Session:
    """Isolated in-memory SQLite session with FK support."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def clean_audit() -> None:
    clear_audit_log()
    yield
    clear_audit_log()


# ---------------------------------------------------------------------------
# EnrichmentService Tests
# ---------------------------------------------------------------------------


class TestEnrichmentService:
    """Tests for the pipeline coordinator service."""

    def test_enrich_finding_in_memory_without_persistence(self) -> None:
        service = EnrichmentService()
        enriched = service.enrich_finding(FINDING_LOG4SHELL, persist=False)

        assert isinstance(enriched, EnrichedFinding)
        assert enriched.finding.finding_id == FINDING_LOG4SHELL.finding_id
        assert "cvss_score" in enriched.fields
        assert enriched.ers is not None
        assert enriched.ers.value > 0.0

    def test_enrich_finding_raises_if_persist_without_repo_or_session(self) -> None:
        service = EnrichmentService()
        with pytest.raises(ValueError, match="neither an active Session nor an EnrichedFindingRepository"):
            service.enrich_finding(FINDING_LOG4SHELL, persist=True)

    def test_enrich_finding_with_persistence(self, db_session: Session) -> None:
        repo = EnrichedFindingRepository(db_session)
        service = EnrichmentService(repository=repo)

        enriched = service.enrich_finding(
            FINDING_LOG4SHELL, persist=True, enriched_at=NOW
        )
        db_session.commit()

        # Verify persisted via repository get
        fetched = service.get_enriched_finding(FINDING_LOG4SHELL.finding_id)
        assert fetched is not None
        assert fetched.finding.finding_id == FINDING_LOG4SHELL.finding_id
        assert fetched.fields["cvss_score"].value == enriched.fields["cvss_score"].value
        assert fetched.ers is not None
        assert abs(fetched.ers.value - enriched.ers.value) < 1e-6  # type: ignore[union-attr]

    def test_enrich_batch_with_persistence(self, db_session: Session) -> None:
        repo = EnrichedFindingRepository(db_session)
        service = EnrichmentService(repository=repo)

        findings = [
            FINDING_LOG4SHELL,
            FINDING_APACHE_PATH_TRAVERSAL,
            FINDING_SPRING_GATEWAY_RCE,
        ]
        results = service.enrich_batch(findings, persist=True, enriched_at=NOW)
        db_session.commit()

        assert len(results) == 3
        count = service.count_by_engagement(ENGAGEMENT_ID)
        assert count == 3

        listed = service.get_by_engagement(ENGAGEMENT_ID)
        assert len(listed) == 3
        finding_ids = {ef.finding.finding_id for ef in listed}
        assert finding_ids == {f.finding_id for f in findings}

    def test_enrich_batch_empty_list_returns_empty(self) -> None:
        service = EnrichmentService()
        results = service.enrich_batch([])
        assert results == []

    def test_enrich_finding_with_explicit_session(self, db_session: Session) -> None:
        service = EnrichmentService()  # no repo bound at init
        enriched = service.enrich_finding(
            FINDING_APACHE_PATH_TRAVERSAL, persist=True, session=db_session
        )
        db_session.commit()

        # Query using same session
        fetched = service.get_enriched_finding(
            FINDING_APACHE_PATH_TRAVERSAL.finding_id, session=db_session
        )
        assert fetched is not None
        assert fetched.finding.finding_id == FINDING_APACHE_PATH_TRAVERSAL.finding_id


# ---------------------------------------------------------------------------
# Celery Worker Task Tests
# ---------------------------------------------------------------------------


class TestCeleryEnrichmentWorker:
    """Tests for run_enrichment worker execution and error handling."""

    def test_run_enrichment_success(self, db_session: Session) -> None:
        findings_data = [
            FINDING_LOG4SHELL.model_dump(mode="json"),
            FINDING_APACHE_PATH_TRAVERSAL.model_dump(mode="json"),
        ]

        with patch("apps.api.tasks.enrichment.SessionLocal", return_value=db_session):
            ids = run_enrichment(findings_data, engagement_id=ENGAGEMENT_ID)

        assert ids == [FINDING_LOG4SHELL.finding_id, FINDING_APACHE_PATH_TRAVERSAL.finding_id]

        # Verify audit log was recorded
        audits = get_audit_log()
        assert len(audits) == 1
        assert audits[0]["event"] == "enrichment.complete"
        assert audits[0]["status"] == "success"
        assert audits[0]["engagement_id"] == ENGAGEMENT_ID

    def test_run_enrichment_empty_returns_empty(self) -> None:
        result = run_enrichment([])
        assert result == []

    def test_run_enrichment_invalid_finding_raises_validation_error(self) -> None:
        invalid_data = [{"finding_id": "bad", "cve_ids": []}]  # missing mandatory fields
        with pytest.raises(ValidationError):
            run_enrichment(invalid_data)

    def test_run_enrichment_transient_error_triggers_celery_retry(
        self, db_session: Session
    ) -> None:
        findings_data = [FINDING_LOG4SHELL.model_dump(mode="json")]
        mock_task = MagicMock()
        mock_task.retry.side_effect = RuntimeError("RetryScheduled")

        with patch("apps.api.tasks.enrichment.SessionLocal", return_value=db_session):
            with patch.object(
                EnrichmentService, "enrich_batch", side_effect=IOError("DB connection lost")
            ):
                with pytest.raises(RuntimeError, match="RetryScheduled"):
                    run_enrichment(
                        findings_data, engagement_id=ENGAGEMENT_ID, task=mock_task
                    )

        mock_task.retry.assert_called_once()
