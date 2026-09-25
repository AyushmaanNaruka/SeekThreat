"""End-to-end pipeline tests over fixture data only -- no scanning, no lab.

These prove the full offline path Layers 2-4 will depend on: a `ScanResult`
snapshot (exactly what a real scan produces) goes in, and the same facts come
back out unchanged through two independent read paths -- the repository layer
directly, and the HTTP read endpoints (`GET /observations`,
`GET /scans/{id}/observations`). If persistence or the API serialization layer
silently dropped or mutated a field, this is what would catch it.

Unit tests already cover each piece (`test_persistence.py`,
`test_observations_api.py`, `test_observation_fixtures.py`). This suite is
concerned only with the seam between them: does what the repository reads
back agree with what the API reports, for the same rows, end to end.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    ObservationRepository,
    RawArtifactRepository,
    ScanRepository,
    save_scan_result,
)
from apps.api.db.session import get_db
from apps.api.main import app
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.observation import ScanResult

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "observations"
ENGAGEMENT_ID = "eng-lab-baseline"

# Every synthetic + real observation snapshot Layer 1 has produced so far.
# See tests/fixtures/observations/README.md for provenance of each file.
FIXTURE_FILES = [
    "lab_baseline.json",
    "lab_dmz_extended.json",
    "lab_internal.json",
    "lab_data.json",
    "lab_extended_nuclei.json",
]


def _load_scan_result(filename: str) -> ScanResult:
    data = json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))
    return ScanResult.model_validate(data)


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(eng, "connect")
    def set_pragma(dbapi_conn, _):  # type: ignore[no-untyped-def]
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def db_session(engine) -> Session:
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture
def api_client(db_session: Session) -> TestClient:
    def _override_get_db():  # type: ignore[no-untyped-def]
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


def test_all_fixtures_persist_and_are_readable_via_repository(db_session: Session) -> None:
    """Every fixture snapshot round-trips through save_scan_result unchanged."""
    scan_results = [_load_scan_result(f) for f in FIXTURE_FILES]
    total_observations = sum(len(sr.observations) for sr in scan_results)

    for scan_result in scan_results:
        save_scan_result(db_session, scan_result)
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    art_repo = RawArtifactRepository(db_session)

    for scan_result in scan_results:
        assert art_repo.exists(scan_result.artifact.artifact_id)

    stored = obs_repo.get_by_engagement(ENGAGEMENT_ID, limit=None)
    assert len(stored) == total_observations

    by_id = {o.observation_id: o for o in stored}
    for scan_result in scan_results:
        for original in scan_result.observations:
            round_tripped = by_id[original.observation_id]
            # Provenance must survive the DB round trip byte-for-byte: source,
            # confidence, and retrieval timestamp are the only reason a
            # downstream consumer can trust a fact enough to act on it.
            assert round_tripped.provenance == original.provenance
            assert round_tripped.artifact_id == original.artifact_id
            assert round_tripped.kind == original.kind
            assert round_tripped.subject == original.subject


def test_persistence_is_idempotent_across_repeated_ingestion(db_session: Session) -> None:
    """Re-ingesting the same fixtures twice must not duplicate or alter rows.

    Content-addressed observation_id/artifact_id are what makes a re-run scan
    safe; this is the property the whole append-only design leans on.
    """
    scan_results = [_load_scan_result(f) for f in FIXTURE_FILES]
    total_observations = sum(len(sr.observations) for sr in scan_results)

    for scan_result in scan_results:
        save_scan_result(db_session, scan_result)
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    first_pass_count = obs_repo.count_by_engagement(ENGAGEMENT_ID)
    assert first_pass_count == total_observations

    # Re-parse from disk independently (not the same Python objects) and
    # re-ingest, exactly as a re-run scan against an unchanged target would.
    for scan_result in [_load_scan_result(f) for f in FIXTURE_FILES]:
        save_scan_result(db_session, scan_result)
    db_session.commit()

    second_pass_count = obs_repo.count_by_engagement(ENGAGEMENT_ID)
    assert second_pass_count == first_pass_count


def test_observations_endpoint_matches_repository_for_full_fixture_set(
    db_session: Session, api_client: TestClient
) -> None:
    """GET /observations must report exactly what the repository holds."""
    for filename in FIXTURE_FILES:
        save_scan_result(db_session, _load_scan_result(filename))
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    expected_total = obs_repo.count_by_engagement(ENGAGEMENT_ID)
    assert expected_total > 0

    resp = api_client.get("/observations", params={"engagement_id": ENGAGEMENT_ID, "limit": 1000})
    assert resp.status_code == 200
    body = resp.json()

    assert body["total"] == expected_total
    assert len(body["items"]) == expected_total

    expected_ids = {o.observation_id for o in obs_repo.get_by_engagement(ENGAGEMENT_ID, limit=None)}

    api_ids = {item["observation_id"] for item in body["items"]}
    assert api_ids == expected_ids

    # Spot-check provenance survives the repository -> Pydantic -> JSON hop.
    expected_by_id = {
        o.observation_id: o for o in obs_repo.get_by_engagement(ENGAGEMENT_ID, limit=None)
    }
    for item in body["items"]:
        original = expected_by_id[item["observation_id"]]
        assert item["provenance"]["source"] == original.provenance.source.value
        assert item["provenance"]["confidence"] == original.provenance.confidence.value
        assert item["artifact_id"] == original.artifact_id


def test_observations_endpoint_pagination_covers_full_fixture_set_without_gaps_or_overlap(
    db_session: Session, api_client: TestClient
) -> None:
    """Paging with a small limit must return every row exactly once."""
    for filename in FIXTURE_FILES:
        save_scan_result(db_session, _load_scan_result(filename))
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    expected_total = obs_repo.count_by_engagement(ENGAGEMENT_ID)

    page_size = 5
    seen: list[str] = []
    offset = 0
    while True:
        resp = api_client.get(
            "/observations",
            params={"engagement_id": ENGAGEMENT_ID, "limit": page_size, "offset": offset},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == expected_total
        items = body["items"]
        if not items:
            break
        seen.extend(item["observation_id"] for item in items)
        offset += page_size

    assert len(seen) == expected_total
    assert len(set(seen)) == expected_total  # no row repeated across pages


def test_scan_observations_endpoint_matches_repository_for_one_artifact(
    db_session: Session, api_client: TestClient
) -> None:
    """GET /scans/{id}/observations must scope correctly to a single artifact.

    This is the seam a real scan actually exercises: the Celery task persists
    a ScanResult and marks the scan row 'completed' with that artifact_id; the
    API then serves observations for exactly that scan, not the whole
    engagement.
    """
    scan_result = _load_scan_result("lab_dmz_extended.json")
    other_result = _load_scan_result("lab_internal.json")
    save_scan_result(db_session, scan_result)
    save_scan_result(db_session, other_result)

    now = datetime.now(UTC)
    EngagementRepository(db_session).save(
        Engagement(
            engagement_id=ENGAGEMENT_ID,
            name="Lab baseline engagement",
            authorization=Authorization(
                engagement_id=ENGAGEMENT_ID,
                authorized_by="test-operator",
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db_session.commit()

    scan_repo = ScanRepository(db_session)
    scan = scan_repo.create(
        scan_id="scan-integration-test",
        engagement_id=ENGAGEMENT_ID,
        scanner="nmap",
        target="172.20.1.12,172.20.1.13",
    )
    scan_repo.update_status(
        scan_id=scan.scan_id,
        status="completed",
        artifact_id=scan_result.artifact.artifact_id,
        completed_at=datetime.now(UTC),
    )
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    expected = obs_repo.get_by_artifact(scan_result.artifact.artifact_id)
    assert len(expected) == len(scan_result.observations)

    resp = api_client.get(f"/scans/{scan.scan_id}/observations")
    assert resp.status_code == 200
    body = resp.json()

    assert body["total"] == len(expected)
    assert {item["observation_id"] for item in body["items"]} == {
        o.observation_id for o in expected
    }
    # Both fixtures are persisted under the same engagement -- scoping by
    # artifact_id (not engagement_id) must still exclude the other scan's rows.
    other_ids = {o.observation_id for o in other_result.observations}
    assert other_ids.isdisjoint({item["observation_id"] for item in body["items"]})
