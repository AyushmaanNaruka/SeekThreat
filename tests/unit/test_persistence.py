"""Unit tests for database models, repositories, and persistence idempotency."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from apps.api.db.base import Base
from apps.api.db.models import ObservationModel, RawArtifactModel
from apps.api.db.repositories import (
    ObservationRepository,
    RawArtifactRepository,
    save_scan_result,
)
from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
    ScanResult,
)
from packages.schema.models.provenance import Confidence, Provenance, Source

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "observations"


@pytest.fixture
def db_session() -> Session:
    """Provide an isolated, in-memory SQLite session with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
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


def _sample_artifact(artifact_id: str = "sha256:abc123") -> RawArtifact:
    return RawArtifact(
        artifact_id=artifact_id,
        scanner="nmap",
        content="<nmaprun></nmaprun>",
        content_type="application/xml",
        captured_at=datetime(2026, 9, 19, 10, 0, 0, tzinfo=UTC),
    )


def _sample_observation(
    observation_id: str = "obs:sha256:obs001",
    artifact_id: str = "sha256:abc123",
    engagement_id: str = "eng-001",
    kind: ObservationKind = ObservationKind.PORT_OPEN,
) -> Observation:
    return Observation(
        observation_id=observation_id,
        engagement_id=engagement_id,
        scanner="nmap",
        kind=kind,
        subject="192.168.1.1:80/tcp",
        attributes={"port": "80", "protocol": "tcp"},
        artifact_id=artifact_id,
        observed_at=datetime(2026, 9, 19, 10, 0, 0, tzinfo=UTC),
        provenance=Provenance(
            source=Source.SCANNER,
            confidence=Confidence.HIGH,
            retrieved_at=datetime(2026, 9, 19, 10, 0, 0, tzinfo=UTC),
        ),
    )


def test_raw_artifact_model_roundtrip() -> None:
    artifact = _sample_artifact()
    model = RawArtifactModel.from_schema(artifact)
    restored = model.to_schema()

    assert restored.artifact_id == artifact.artifact_id
    assert restored.scanner == artifact.scanner
    assert restored.content == artifact.content
    assert restored.content_type == artifact.content_type
    assert restored.captured_at == artifact.captured_at


def test_observation_model_roundtrip() -> None:
    obs = _sample_observation()
    model = ObservationModel.from_schema(obs)
    restored = model.to_schema()

    assert restored.observation_id == obs.observation_id
    assert restored.engagement_id == obs.engagement_id
    assert restored.scanner == obs.scanner
    assert restored.kind == obs.kind
    assert restored.subject == obs.subject
    assert restored.attributes == obs.attributes
    assert restored.artifact_id == obs.artifact_id
    assert restored.observed_at == obs.observed_at
    assert restored.provenance.source == obs.provenance.source
    assert restored.provenance.confidence == obs.provenance.confidence


def test_raw_artifact_repository_save_and_get(db_session: Session) -> None:
    repo = RawArtifactRepository(db_session)
    artifact = _sample_artifact()

    assert not repo.exists(artifact.artifact_id)
    repo.save(artifact)
    assert repo.exists(artifact.artifact_id)

    fetched = repo.get(artifact.artifact_id)
    assert fetched is not None
    assert fetched.artifact_id == artifact.artifact_id
    assert fetched.content == artifact.content


def test_raw_artifact_repository_idempotent_save(db_session: Session) -> None:
    repo = RawArtifactRepository(db_session)
    artifact = _sample_artifact()

    repo.save(artifact)
    # Saving second time must be a no-op, no integrity error
    repo.save(artifact)
    db_session.commit()

    all_models = db_session.query(RawArtifactModel).all()
    assert len(all_models) == 1


def test_observation_repository_save_and_get(db_session: Session) -> None:
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    obs = _sample_observation(artifact_id=artifact.artifact_id)
    obs_repo.save(obs)

    fetched = obs_repo.get(obs.observation_id)
    assert fetched is not None
    assert fetched.observation_id == obs.observation_id
    assert fetched.subject == obs.subject


def test_observation_repository_idempotent_save_all(db_session: Session) -> None:
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    obs1 = _sample_observation("obs-1", artifact.artifact_id)
    obs2 = _sample_observation("obs-2", artifact.artifact_id)

    obs_repo.save_all([obs1, obs2])
    # Re-running same observations must not fail or duplicate
    obs_repo.save_all([obs1, obs2])
    db_session.commit()

    count = obs_repo.count_by_engagement("eng-001")
    assert count == 2


def test_observation_repository_filtering_and_counts(db_session: Session) -> None:
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    obs_port = _sample_observation("obs-port", artifact.artifact_id, kind=ObservationKind.PORT_OPEN)
    obs_host = _sample_observation("obs-host", artifact.artifact_id, kind=ObservationKind.HOST_UP)
    obs_other_eng = _sample_observation("obs-other", artifact.artifact_id, engagement_id="eng-002")

    obs_repo.save_all([obs_port, obs_host, obs_other_eng])
    db_session.commit()

    # Total in eng-001
    assert obs_repo.count_by_engagement("eng-001") == 2
    # Specific kind in eng-001
    assert obs_repo.count_by_engagement("eng-001", kind=ObservationKind.PORT_OPEN) == 1
    assert obs_repo.count_by_engagement("eng-001", kind=ObservationKind.HOST_UP) == 1
    assert obs_repo.count_by_engagement("eng-001", kind=ObservationKind.SERVICE_VERSION) == 0

    # Retrieve by engagement
    eng1_obs = obs_repo.get_by_engagement("eng-001")
    assert len(eng1_obs) == 2
    assert {o.observation_id for o in eng1_obs} == {"obs-port", "obs-host"}

    # Retrieve by artifact
    art_obs = obs_repo.get_by_artifact(artifact.artifact_id)
    assert len(art_obs) == 3


def test_cascade_delete_removes_observations(db_session: Session) -> None:
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    obs = _sample_observation(artifact_id=artifact.artifact_id)
    obs_repo.save(obs)
    db_session.commit()

    # Delete artifact
    artifact_model = db_session.get(RawArtifactModel, artifact.artifact_id)
    assert artifact_model is not None
    db_session.delete(artifact_model)
    db_session.commit()

    assert obs_repo.get(obs.observation_id) is None


def test_save_scan_result_with_real_fixture(db_session: Session) -> None:
    fixture_path = FIXTURES_DIR / "lab_baseline.json"
    data = json.loads(fixture_path.read_text(encoding="utf-8"))

    scan_result = ScanResult.model_validate(data)
    assert len(scan_result.observations) > 0

    # Initial save
    save_scan_result(db_session, scan_result)
    db_session.commit()

    obs_repo = ObservationRepository(db_session)
    art_repo = RawArtifactRepository(db_session)

    assert art_repo.exists(scan_result.artifact.artifact_id)
    initial_count = obs_repo.count_by_engagement("eng-lab-baseline")
    assert initial_count == len(scan_result.observations)

    # Re-run save (idempotency check)
    save_scan_result(db_session, scan_result)
    db_session.commit()

    re_count = obs_repo.count_by_engagement("eng-lab-baseline")
    assert re_count == initial_count


def test_observation_repository_pagination_and_kind_filter_by_engagement(
    db_session: Session,
) -> None:
    """get_by_engagement/count_by_engagement support limit/offset alongside the kind filter."""
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    observations = [
        _sample_observation(f"obs-{i:02d}", artifact.artifact_id, kind=ObservationKind.PORT_OPEN)
        for i in range(5)
    ]
    obs_repo.save_all(observations)
    db_session.commit()

    assert obs_repo.count_by_engagement("eng-001") == 5

    page_one = obs_repo.get_by_engagement("eng-001", limit=2, offset=0)
    page_two = obs_repo.get_by_engagement("eng-001", limit=2, offset=2)
    page_three = obs_repo.get_by_engagement("eng-001", limit=2, offset=4)

    assert [o.observation_id for o in page_one] == ["obs-00", "obs-01"]
    assert [o.observation_id for o in page_two] == ["obs-02", "obs-03"]
    assert [o.observation_id for o in page_three] == ["obs-04"]

    # No overlap or gaps across pages -- every observation appears exactly once
    all_ids = [o.observation_id for page in (page_one, page_two, page_three) for o in page]
    assert sorted(all_ids) == [f"obs-{i:02d}" for i in range(5)]

    # limit=None (the default) returns everything, matching existing callers
    assert len(obs_repo.get_by_engagement("eng-001")) == 5


def test_observation_repository_pagination_and_kind_filter_by_artifact(
    db_session: Session,
) -> None:
    """get_by_artifact/count_by_artifact mirror the engagement-scoped pagination."""
    art_repo = RawArtifactRepository(db_session)
    obs_repo = ObservationRepository(db_session)

    artifact = _sample_artifact()
    art_repo.save(artifact)

    port_obs = [
        _sample_observation(f"obs-port-{i}", artifact.artifact_id, kind=ObservationKind.PORT_OPEN)
        for i in range(3)
    ]
    host_obs = _sample_observation("obs-host-0", artifact.artifact_id, kind=ObservationKind.HOST_UP)
    obs_repo.save_all([*port_obs, host_obs])
    db_session.commit()

    assert obs_repo.count_by_artifact(artifact.artifact_id) == 4
    assert obs_repo.count_by_artifact(artifact.artifact_id, kind=ObservationKind.PORT_OPEN) == 3
    assert obs_repo.count_by_artifact(artifact.artifact_id, kind=ObservationKind.HOST_UP) == 1

    filtered = obs_repo.get_by_artifact(
        artifact.artifact_id, kind=ObservationKind.PORT_OPEN, limit=2, offset=1
    )
    assert [o.observation_id for o in filtered] == ["obs-port-1", "obs-port-2"]
