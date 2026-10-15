"""Unit tests for Task C-2: Resilience against malformed legacy CVE IDs.

Guards against 500 server errors on GET /findings when legacy database rows contain
malformed CVE IDs (e.g., whitespace, non-ASCII, or invalid formats).
Also tests scripts/cleanup_malformed_cve_ids.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.db import models as _models  # noqa: F401
from apps.api.db.base import Base
from apps.api.db.models import EngagementModel, EnrichedFindingModel
from apps.api.db.repositories import EnrichedFindingRepository
from apps.api.db.session import get_db
from apps.api.main import app
from scripts.cleanup_malformed_cve_ids import cleanup_malformed_cve_ids, sanitize_cve_id

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
ENGAGEMENT_ID = "eng-resilience-test"


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

    # Seed engagement
    eng_model = EngagementModel(
        engagement_id=ENGAGEMENT_ID,
        name="Resilience Test Engagement",
        authorized_by="security-lead",
        allowlist=["127.0.0.1"],
        granted_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
        created_at=NOW - timedelta(days=1),
    )
    session.add(eng_model)
    session.commit()

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


def _insert_finding_row(
    session: Session,
    finding_id: str,
    cve_ids: list[str],
    title: str = "Test Finding",
) -> EnrichedFindingModel:
    row = EnrichedFindingModel(
        engagement_id=ENGAGEMENT_ID,
        finding_id=finding_id,
        finding_data={
            "finding_id": finding_id,
            "engagement_id": ENGAGEMENT_ID,
            "asset_id": "ast-1",
            "scanner": "nmap",
            "observation_ids": ["obs-1"],
            "detected_at": NOW.isoformat(),
            "title": title,
            "severity": "HIGH",
            "cve_ids": cve_ids,
        },
        fields={},
        ers_value=None,
        ers_components=None,
        enriched_at=NOW,
    )
    session.add(row)
    session.commit()
    return row


class TestFindingsReadPathResilience:
    def test_get_findings_skips_malformed_cve_id_without_500(
        self,
        api_client: TestClient,
        db_session: Session,
    ) -> None:
        """A page of findings containing a row with malformed CVE ID must return 200, not 500."""
        # Valid finding
        _insert_finding_row(db_session, "fnd-valid-01", ["CVE-2021-44228"], "Valid Log4Shell")
        # Malformed legacy finding (e.g. invalid string failing CVE_ID_PATTERN)
        _insert_finding_row(db_session, "fnd-malformed-01", ["NOT-A-REAL-CVE"], "Corrupted Finding")
        # Another valid finding
        _insert_finding_row(db_session, "fnd-valid-02", ["CVE-2021-41773"], "Valid Path Traversal")

        resp = api_client.get(f"/findings?engagement_id={ENGAGEMENT_ID}")
        assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"

        data = resp.json()
        returned_ids = [item["finding"]["finding_id"] for item in data["items"]]
        # Valid rows must be present
        assert "fnd-valid-01" in returned_ids
        assert "fnd-valid-02" in returned_ids
        # Malformed row must have been gracefully omitted
        assert "fnd-malformed-01" not in returned_ids
        assert len(data["items"]) == 2

    def test_get_single_malformed_finding_returns_422_not_500(
        self,
        api_client: TestClient,
        db_session: Session,
    ) -> None:
        """Direct GET /findings/{id} on a malformed finding returns 422
        with structured explanation."""
        _insert_finding_row(db_session, "fnd-bad-id", ["INVALID_CVE_999"], "Malformed Record")

        resp = api_client.get(f"/findings/fnd-bad-id?engagement_id={ENGAGEMENT_ID}")
        assert resp.status_code == 422, f"Expected 422, got {resp.status_code}"
        assert "malformed" in resp.json()["detail"].lower()

    def test_repo_get_by_engagement_respects_skip_invalid_flag(
        self,
        db_session: Session,
    ) -> None:
        repo = EnrichedFindingRepository(db_session)
        _insert_finding_row(db_session, "fnd-val", ["CVE-2020-0001"])
        _insert_finding_row(db_session, "fnd-bad", ["MALFORMED"])

        # Default skip_invalid=True: skips the bad row
        items = repo.get_by_engagement(ENGAGEMENT_ID, skip_invalid=True)
        assert len(items) == 1
        assert items[0].finding.finding_id == "fnd-val"

        # Explicit skip_invalid=False: raises validation error
        with pytest.raises((ValidationError, ValueError)):
            repo.get_by_engagement(ENGAGEMENT_ID, skip_invalid=False)


class TestCleanupMalformedCveIdsScript:
    def test_sanitize_cve_id_helper(self) -> None:
        assert sanitize_cve_id("  cve-2021-44228 \n") == "CVE-2021-44228"
        assert sanitize_cve_id("CVE-2021-44228\x00") == "CVE-2021-44228"
        assert sanitize_cve_id("NOT-A-CVE") is None
        assert sanitize_cve_id(12345) is None
        assert sanitize_cve_id(None) is None

    def test_cleanup_script_normalizes_and_drops(self, db_session: Session) -> None:
        # Row with whitespace/lowercase and an unparseable ID
        _insert_finding_row(
            db_session,
            "fnd-dirty",
            ["  cve-2021-44228  ", "JUNK_IDENTIFIER"],
            "Dirty finding",
        )

        # Dry run does not commit
        dry_res = cleanup_malformed_cve_ids(db_session, apply=False, engagement_id=ENGAGEMENT_ID)
        assert dry_res["modified_rows"] == 1
        assert dry_res["rectified_cve_count"] == 1
        assert dry_res["dropped_cve_count"] == 1

        # Real run commits
        apply_res = cleanup_malformed_cve_ids(db_session, apply=True, engagement_id=ENGAGEMENT_ID)
        assert apply_res["modified_rows"] == 1

        # Now the row should be valid and deserializable!
        repo = EnrichedFindingRepository(db_session)
        finding = repo.get("fnd-dirty", engagement_id=ENGAGEMENT_ID)
        assert finding is not None
        assert finding.finding.cve_ids == ["CVE-2021-44228"]
