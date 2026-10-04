"""Unit tests for the execute_scan Celery task (Task 4).

Tests call the task function *directly* (not via .delay()) to avoid needing a
live Redis broker. This exercises the task body — DB interactions, adapter
dispatch, audit events — in the same isolated SQLite environment used by
test_api.py.

Test coverage:
  - Authorization dict round-trip (model_dump → model_validate)
  - Unsupported scanner → status "failed", audit event "scan.failed"
  - Nmap adapter mocked → status "completed", save_scan_result called,
    audit event "scan.completed"
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db import models as _models  # noqa: F401 – registers all ORM tables
from apps.api.db.base import Base
from apps.api.db.repositories import EngagementRepository, ScanRepository
from apps.api.db.session import get_session_factory
from packages.schema.models.engagement import Authorization, Engagement
from services.scanners.base import ScannerUnavailableError

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _future(hours: int = 24) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)


def _past(hours: int = 1) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _make_auth_dict(**overrides: Any) -> dict[str, Any]:
    """Return a JSON-safe Authorization dict passable through Celery's JSON transport."""
    auth = Authorization(
        engagement_id="eng-celery-test",
        authorized_by="test-operator",
        allowlist=("172.20.0.0/16",),
        granted_at=_past(2),
        expires_at=_future(24),
    )
    d = auth.model_dump(mode="json")
    d.update(overrides)
    return d


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
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


@pytest.fixture(autouse=True)
def reset_audit_log():
    clear_audit_log()
    yield
    clear_audit_log()


@pytest.fixture
def seeded_scan(db_session):
    """Create an engagement + pending scan record; return (scan_id, auth_dict)."""
    # Seed engagement
    eng_repo = EngagementRepository(db_session)
    engagement = Engagement(
        engagement_id="eng-celery-test",
        name="Celery Task Test Engagement",
        authorization=Authorization(
            engagement_id="eng-celery-test",
            authorized_by="test-operator",
            allowlist=("172.20.0.0/16",),
            granted_at=_past(2),
            expires_at=_future(24),
        ),
        created_at=_past(2),
    )
    eng_repo.save(engagement)
    db_session.commit()

    # Create pending scan record
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    scan_repo = ScanRepository(db_session)
    scan_repo.create(
        scan_id=scan_id,
        engagement_id="eng-celery-test",
        scanner="nmap",
        target="172.20.1.50",
        options={},
    )
    db_session.commit()

    return scan_id, _make_auth_dict()


# ---------------------------------------------------------------------------
# Test: Authorization dict round-trip
# ---------------------------------------------------------------------------


def test_authorization_dict_round_trip() -> None:
    """model_dump(mode='json') → Authorization.model_validate() is lossless."""
    original = Authorization(
        engagement_id="eng-rt-001",
        authorized_by="auditor",
        allowlist=("10.0.0.0/8", "*.internal"),
        granted_at=_past(1),
        expires_at=_future(8),
    )

    serialized = original.model_dump(mode="json")

    # Ensure the dict is JSON-safe (no datetime objects, no frozensets)
    import json

    json_str = json.dumps(serialized)  # raises if not serializable
    assert json_str  # non-empty

    # Reconstruct and verify round-trip fidelity
    reconstructed = Authorization.model_validate(serialized)

    assert reconstructed.engagement_id == original.engagement_id
    assert reconstructed.authorized_by == original.authorized_by
    assert reconstructed.allowlist == original.allowlist
    assert reconstructed.granted_at == original.granted_at
    assert reconstructed.expires_at == original.expires_at

    # Functional: permits() still works correctly after round-trip
    assert reconstructed.permits("10.1.2.3")
    assert reconstructed.permits("host.internal")
    assert not reconstructed.permits("8.8.8.8")


# ---------------------------------------------------------------------------
# Test: Unsupported scanner → failed status
# ---------------------------------------------------------------------------


def test_execute_scan_unsupported_scanner(engine, seeded_scan, monkeypatch) -> None:
    """An unsupported scanner name causes the scan to be marked failed."""
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan

    # Patch SessionLocal inside the task module to use our isolated engine
    factory = get_session_factory(engine)

    monkeypatch.setattr(task_module, "SessionLocal", factory)

    # Build a minimal mock Celery task self (bind=True)
    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3

    # An unsupported scanner is permanent (see PERMANENT_ERRORS) so it is never
    # retried, and the task re-raises after marking the scan failed so Celery
    # itself records the task as FAILURE, not SUCCESS.
    with pytest.raises(ValueError):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="unsupported-scanner",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    mock_self.retry.assert_not_called()

    # Check scan marked failed in DB
    db = factory()
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    db.close()

    assert scan is not None
    assert scan.status == "failed"
    assert "ValueError" in (scan.error_message or "")

    # Verify scan.failed audit event
    events = get_audit_log()
    failed_events = [e for e in events if e["event"] == "scan.failed"]
    assert len(failed_events) == 1
    assert failed_events[0]["status"] == "error"
    assert failed_events[0]["scanner"] == "unsupported-scanner"


# ---------------------------------------------------------------------------
# Test: Nmap adapter mocked → happy path completes
# ---------------------------------------------------------------------------


def test_execute_scan_nmap_happy_path(engine, seeded_scan, monkeypatch) -> None:
    """Happy path: mocked NmapAdapter → scan marked completed, save_scan_result called."""
    from apps.api.tasks import scans as task_module
    from packages.schema.models.observation import RawArtifact, ScanResult

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    # Build a minimal ScanResult the task can persist
    fake_artifact = RawArtifact(
        artifact_id="sha256-" + "a" * 58,
        scanner="nmap",
        content=b"<nmaprun/>",
        content_type="application/xml",
        captured_at=datetime.now(UTC),
    )
    fake_result = ScanResult(artifact=fake_artifact, observations=())

    # Mock the NmapAdapter so no live nmap process is spawned
    mock_adapter = MagicMock()
    mock_adapter.scan.return_value = fake_result

    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3
    mock_self.MaxRetriesExceededError = Exception

    with patch("apps.api.tasks.scans.NmapAdapter", return_value=mock_adapter):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="nmap",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    # Scan should be marked completed in DB
    db = factory()
    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    db.close()

    assert scan is not None
    assert scan.status == "completed"
    assert scan.artifact_id == fake_artifact.artifact_id
    assert scan.completed_at is not None

    # Verify audit event
    events = get_audit_log()
    completed_events = [e for e in events if e["event"] == "scan.completed"]
    assert len(completed_events) == 1
    assert completed_events[0]["status"] == "completed"
    assert completed_events[0]["scanner"] == "nmap"


# ---------------------------------------------------------------------------
# Retry classification: permanent failures must not be retried
# ---------------------------------------------------------------------------


def test_unsupported_scanner_is_not_retried(engine, seeded_scan, monkeypatch) -> None:
    """An unsupported scanner name can never succeed, so it must not be retried.

    Every retry is a full rescan. Retrying an error whose outcome cannot change
    burned up to four of them before giving up.
    """
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3

    with pytest.raises(ValueError):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="unsupported-scanner",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    mock_self.retry.assert_not_called()


def test_missing_scanner_binary_is_not_retried(engine, seeded_scan, monkeypatch) -> None:
    """A binary missing at dispatch will still be missing on retry."""
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    unavailable = MagicMock()
    unavailable.is_available.return_value = False
    monkeypatch.setattr(task_module, "NmapAdapter", lambda: unavailable)

    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3

    with pytest.raises(ScannerUnavailableError):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="nmap",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    mock_self.retry.assert_not_called()
    unavailable.scan.assert_not_called()

    db = factory()
    scan = ScanRepository(db).get(scan_id)
    db.close()
    assert scan is not None
    assert scan.status == "failed"
    assert "ScannerUnavailableError" in (scan.error_message or "")


def test_transient_error_is_still_retried(engine, seeded_scan, monkeypatch) -> None:
    """Transient failures keep their retry behaviour — only permanent ones are excluded."""
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    flaky = MagicMock()
    flaky.is_available.return_value = True
    flaky.scan.side_effect = ConnectionError("transient network blip")
    monkeypatch.setattr(task_module, "NmapAdapter", lambda: flaky)

    class _MaxRetriesExceeded(Exception):
        """Stand-in distinct from RuntimeError, so the except clause below
        does not accidentally swallow the simulated reschedule."""

    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3
    mock_self.MaxRetriesExceededError = _MaxRetriesExceeded
    mock_self.retry.side_effect = RuntimeError("celery would reschedule here")

    with pytest.raises(RuntimeError):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="nmap",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    mock_self.retry.assert_called_once()


# ---------------------------------------------------------------------------
# A failed scan must not be reported to Celery as a success
# ---------------------------------------------------------------------------


def test_failed_scan_raises_so_celery_records_failure(engine, seeded_scan, monkeypatch) -> None:
    """The task must not return normally after marking the scan failed.

    Celery derives task state from the return: swallowing the exception left
    the DB row at 'failed' while the task itself was recorded SUCCESS, so
    nothing monitoring Celery could see that anything had gone wrong.
    """
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    mock_self = MagicMock()
    mock_self.request.id = "mock-celery-task-id"
    mock_self.request.retries = 0
    mock_self.max_retries = 3

    with pytest.raises(ValueError):
        task_module.execute_scan.run.__func__(
            mock_self,
            scan_id=scan_id,
            engagement_id="eng-celery-test",
            scanner="nope",
            target="172.20.1.50",
            options={},
            authorization_dict=auth_dict,
        )

    db = factory()
    scan = ScanRepository(db).get(scan_id)
    db.close()
    assert scan is not None
    assert scan.status == "failed"

    events = get_audit_log()
    assert any(e["event"] == "scan.failed" for e in events)


# ---------------------------------------------------------------------------
# Local fallback mode: self is None / background-thread execution
# ---------------------------------------------------------------------------


def test_local_fallback_scanner_exception_marks_failed_without_attribute_error(
    engine, seeded_scan, monkeypatch
) -> None:
    """Local fallback catches scanner exceptions and does NOT crash on NoneType.retry.

    Scenario:
        local fallback (task=None)
            ↓
        execute scan
            ↓
        scanner raises exception
            ↓
        scan becomes FAILED
            ↓
        actual error is stored
            ↓
        NO AttributeError involving self.retry
    """
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    failing_adapter = MagicMock()
    failing_adapter.is_available.return_value = True
    failing_adapter.scan.side_effect = RuntimeError("nmap crash: segmentation fault in scanner")
    monkeypatch.setattr(task_module, "NmapAdapter", lambda: failing_adapter)

    # In local fallback mode, run_scan (or execute_scan with self=None) runs in a background thread
    # and should NOT raise AttributeError: 'NoneType' object has no attribute 'retry'.
    # It catches the exception, updates the record, and exits cleanly.
    task_module.run_scan(
        scan_id=scan_id,
        engagement_id="eng-celery-test",
        scanner="nmap",
        target="172.20.1.50",
        options={},
        authorization_dict=auth_dict,
        task=None,
    )

    db = factory()
    scan = ScanRepository(db).get(scan_id)
    db.close()

    assert scan is not None
    assert scan.status == "failed"
    assert "RuntimeError: nmap crash: segmentation fault in scanner" in (scan.error_message or "")

    events = get_audit_log()
    failed_events = [e for e in events if e["event"] == "scan.failed"]
    assert len(failed_events) == 1
    assert failed_events[0]["status"] == "error"
    assert failed_events[0]["details"]["celery_task_id"] is None


def test_local_fallback_transient_error_marks_failed_without_retry(
    engine, seeded_scan, monkeypatch
) -> None:
    """In local fallback mode (task=None), transient errors skip Celery retry and mark
    scan failed.
    """
    from apps.api.tasks import scans as task_module

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    flaky_adapter = MagicMock()
    flaky_adapter.is_available.return_value = True
    flaky_adapter.scan.side_effect = ConnectionError("Connection refused by target socket")
    monkeypatch.setattr(task_module, "NmapAdapter", lambda: flaky_adapter)

    # Call execute_scan with self=None
    task_module.execute_scan.run.__func__(
        None,
        scan_id=scan_id,
        engagement_id="eng-celery-test",
        scanner="nmap",
        target="172.20.1.50",
        options={},
        authorization_dict=auth_dict,
    )

    db = factory()
    scan = ScanRepository(db).get(scan_id)
    db.close()

    assert scan is not None
    assert scan.status == "failed"
    assert "ConnectionError: Connection refused by target socket" in (scan.error_message or "")


def test_local_fallback_happy_path_completes(engine, seeded_scan, monkeypatch) -> None:
    """Local fallback mode completes successfully when scanner succeeds."""
    from apps.api.tasks import scans as task_module
    from packages.schema.models.observation import RawArtifact, ScanResult

    scan_id, auth_dict = seeded_scan
    factory = get_session_factory(engine)
    monkeypatch.setattr(task_module, "SessionLocal", factory)

    fake_artifact = RawArtifact(
        artifact_id="sha256-" + "b" * 58,
        scanner="nmap",
        content=b"<nmaprun/>",
        content_type="application/xml",
        captured_at=datetime.now(UTC),
    )
    fake_result = ScanResult(artifact=fake_artifact, observations=())

    mock_adapter = MagicMock()
    mock_adapter.is_available.return_value = True
    mock_adapter.scan.return_value = fake_result
    monkeypatch.setattr(task_module, "NmapAdapter", lambda: mock_adapter)

    task_module.run_scan(
        scan_id=scan_id,
        engagement_id="eng-celery-test",
        scanner="nmap",
        target="172.20.1.50",
        options={},
        authorization_dict=auth_dict,
        task=None,
    )

    db = factory()
    scan = ScanRepository(db).get(scan_id)
    db.close()

    assert scan is not None
    assert scan.status == "completed"
    assert scan.artifact_id == fake_artifact.artifact_id
    assert scan.completed_at is not None

    events = get_audit_log()
    completed_events = [e for e in events if e["event"] == "scan.completed"]
    assert len(completed_events) == 1
    assert completed_events[0]["status"] == "completed"
    assert completed_events[0]["details"]["celery_task_id"] is None
