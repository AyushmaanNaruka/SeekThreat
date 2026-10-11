"""Unit tests for the post-scan targeted feed sync & re-enrichment pipeline.

Test coverage (Task 6):
  1. _cve_ids_from_artifact — extracts CVE IDs from VULN_CANDIDATE observations
  2. _missing_cve_ids — correctly identifies CVEs absent from local mirrors
  3. run_post_scan_enrichment — full pipeline: no CVEs, all known, missing CVEs
  4. run_post_scan_enrichment — DB read error marks ok=False, does not raise
  5. run_post_scan_enrichment — sync failure marks ok=False, re-enrichment still runs
  6. _dispatch_post_scan_enrichment (via scans module) — enqueue failure is swallowed
  7. Celery task wrapper — unhandled exceptions are caught, audit event emitted
  8. Celery task wrapper — success path emits completed audit event
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import apps.api.db.models as _models  # noqa: F401 — registers ORM tables
from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db.base import Base
from apps.api.db.repositories import (
    ObservationRepository,
    RawArtifactRepository,
)
from apps.api.db.session import get_session_factory
from apps.api.tasks.post_scan_enrichment import (
    _cve_ids_from_artifact,
    _missing_cve_ids,
    run_post_scan_enrichment,
)
from packages.schema.models.finding import Finding
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _future(hours: int = 24) -> datetime:
    return _now() + timedelta(hours=hours)


def _past(hours: int = 1) -> datetime:
    return _now() - timedelta(hours=hours)


def _make_artifact(artifact_id: str | None = None) -> RawArtifact:
    return RawArtifact(
        artifact_id=artifact_id or f"art-{uuid.uuid4().hex[:12]}",
        scanner="nuclei",
        content="{}",
        content_type="application/json",
        captured_at=_now(),
    )


def _make_provenance() -> Provenance:
    return Provenance(
        source=Source.NVD,
        confidence=Confidence.HIGH,
        retrieved_at=datetime.now(UTC),
    )


def _make_vuln_observation(
    artifact_id: str,
    cve_ids: list[str],
    engagement_id: str = "eng-test",
) -> Observation:
    return Observation(
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        engagement_id=engagement_id,
        scanner="nuclei",
        kind=ObservationKind.VULN_CANDIDATE,
        subject="172.20.1.10:443/tcp",
        attributes={"cve_ids": ",".join(cve_ids), "severity": "high"},
        artifact_id=artifact_id,
        observed_at=_now(),
        provenance=_make_provenance(),
    )


def _make_non_vuln_observation(artifact_id: str, engagement_id: str = "eng-test") -> Observation:
    return Observation(
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        engagement_id=engagement_id,
        scanner="nmap",
        kind=ObservationKind.PORT_OPEN,
        subject="172.20.1.10",
        attributes={"port": "443", "protocol": "tcp"},
        artifact_id=artifact_id,
        observed_at=_now(),
        provenance=_make_provenance(),
    )


def _make_finding(cve_ids: list[str], engagement_id: str = "eng-test") -> Finding:
    return Finding(
        finding_id=f"f-{uuid.uuid4().hex[:12]}",
        engagement_id=engagement_id,
        asset_id="host:172.20.1.10",
        cve_ids=cve_ids,
        observation_ids=[f"obs-{uuid.uuid4().hex[:12]}"],
    )


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
def session_factory(engine):
    """A session factory wired to the in-memory test engine."""
    return get_session_factory(engine)


# ---------------------------------------------------------------------------
# 1. _cve_ids_from_artifact
# ---------------------------------------------------------------------------


class TestCveIdsFromArtifact:
    def test_returns_cves_from_vuln_candidates(self, db_session):
        """VULN_CANDIDATE observations have their CVE IDs extracted and normalized."""
        artifact = _make_artifact()
        RawArtifactRepository(db_session).save(artifact)
        obs = _make_vuln_observation(
            artifact_id=artifact.artifact_id,
            cve_ids=["CVE-2021-44228", "CVE-2024-3400"],
        )
        ObservationRepository(db_session).save(obs)
        db_session.commit()

        result = _cve_ids_from_artifact(db_session, artifact.artifact_id)

        assert result == ["CVE-2021-44228", "CVE-2024-3400"]

    def test_ignores_non_vuln_candidate_observations(self, db_session):
        """PORT_OPEN observations are not included."""
        artifact = _make_artifact()
        RawArtifactRepository(db_session).save(artifact)
        obs = _make_non_vuln_observation(artifact.artifact_id)
        ObservationRepository(db_session).save(obs)
        db_session.commit()

        result = _cve_ids_from_artifact(db_session, artifact.artifact_id)

        assert result == []

    def test_deduplicates_cve_ids_across_observations(self, db_session):
        """The same CVE ID reported by two observations is deduplicated."""
        artifact = _make_artifact()
        RawArtifactRepository(db_session).save(artifact)
        obs1 = _make_vuln_observation(artifact.artifact_id, ["CVE-2021-44228"])
        obs2 = _make_vuln_observation(artifact.artifact_id, ["CVE-2021-44228", "CVE-2024-3400"])
        ObservationRepository(db_session).save_all([obs1, obs2])
        db_session.commit()

        result = _cve_ids_from_artifact(db_session, artifact.artifact_id)

        assert result == ["CVE-2021-44228", "CVE-2024-3400"]

    def test_returns_empty_for_unknown_artifact(self, db_session):
        """An artifact with no observations returns an empty list."""
        result = _cve_ids_from_artifact(db_session, "art-does-not-exist")
        assert result == []

    def test_observation_without_cve_ids_attribute(self, db_session):
        """Observations missing the cve_ids attribute are silently skipped."""
        artifact = _make_artifact()
        RawArtifactRepository(db_session).save(artifact)
        obs = Observation(
            observation_id=f"obs-{uuid.uuid4().hex[:12]}",
            engagement_id="eng-test",
            scanner="nuclei",
            kind=ObservationKind.VULN_CANDIDATE,
            subject="172.20.1.10:80/tcp",
            attributes={"severity": "medium"},  # no cve_ids key
            artifact_id=artifact.artifact_id,
            observed_at=_now(),
            provenance=_make_provenance(),
        )
        ObservationRepository(db_session).save(obs)
        db_session.commit()

        result = _cve_ids_from_artifact(db_session, artifact.artifact_id)
        assert result == []


# ---------------------------------------------------------------------------
# 2. _missing_cve_ids
# ---------------------------------------------------------------------------


class TestMissingCveIds:
    def test_all_missing_when_no_mirrors(self, tmp_path):
        """All CVE IDs are missing when mirror files do not exist."""
        cves = ["CVE-2021-44228", "CVE-2024-3400"]
        result = _missing_cve_ids(cves, tmp_path)
        assert result == cves

    def test_known_cves_excluded(self, tmp_path):
        """CVEs already in a mirror file are excluded from the missing set."""
        from packages.schema.models.provenance import Source
        from services.enrichment.sources.sync import MIRROR_FILENAMES

        mirror = tmp_path / MIRROR_FILENAMES[Source.NVD]
        mirror.write_text(
            json.dumps({"CVE-2021-44228": {"id": "CVE-2021-44228"}}),
            encoding="utf-8",
        )

        result = _missing_cve_ids(["CVE-2021-44228", "CVE-2024-3400"], tmp_path)

        assert result == ["CVE-2024-3400"]

    def test_corrupt_mirror_treated_as_empty(self, tmp_path):
        """A corrupt mirror file falls back to treating all CVEs as missing."""
        from packages.schema.models.provenance import Source
        from services.enrichment.sources.sync import MIRROR_FILENAMES

        mirror = tmp_path / MIRROR_FILENAMES[Source.CVE_ORG]
        mirror.write_text("not valid json", encoding="utf-8")

        result = _missing_cve_ids(["CVE-2024-3400"], tmp_path)

        assert result == ["CVE-2024-3400"]

    def test_cve_known_in_any_source_is_excluded(self, tmp_path):
        """A CVE present in any mirror is excluded, even if absent from others."""
        from packages.schema.models.provenance import Source
        from services.enrichment.sources.sync import MIRROR_FILENAMES

        # Write it to EUVD only; not in NVD, CVE.org, or Vulnrichment
        euvd_mirror = tmp_path / MIRROR_FILENAMES[Source.EUVD]
        euvd_mirror.write_text(json.dumps({"CVE-2021-44228": {}}), encoding="utf-8")

        result = _missing_cve_ids(["CVE-2021-44228", "CVE-2024-3400"], tmp_path)

        assert "CVE-2021-44228" not in result
        assert "CVE-2024-3400" in result


# ---------------------------------------------------------------------------
# 3. run_post_scan_enrichment — no CVE observations
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentNoCves:
    def test_no_vuln_candidate_observations_returns_early(self, engine, session_factory, tmp_path):
        """A scan with no VULN_CANDIDATE observations skips sync and enrichment."""
        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            obs = _make_non_vuln_observation(artifact.artifact_id)
            ObservationRepository(s).save(obs)
            s.commit()

        with patch("apps.api.tasks.post_scan_enrichment.SessionLocal", session_factory):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-001",
                cache_dir=tmp_path,
            )

        assert summary["ok"] is True
        assert summary["cves_found"] == 0
        assert summary["cves_missing"] == 0
        assert summary["cves_synced"] == 0


# ---------------------------------------------------------------------------
# 4. run_post_scan_enrichment — all CVEs already known
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentAllKnown:
    def test_skips_sync_when_all_cves_known(self, engine, session_factory, tmp_path):
        """When all CVEs are in the mirror, sync is skipped, re-enrichment runs."""
        from packages.schema.models.provenance import Source
        from services.enrichment.sources.sync import MIRROR_FILENAMES

        # Write both CVEs into an existing NVD mirror.
        nvd_mirror = tmp_path / MIRROR_FILENAMES[Source.NVD]
        nvd_mirror.write_text(
            json.dumps(
                {
                    "CVE-2021-44228": {"id": "CVE-2021-44228"},
                    "CVE-2024-3400": {"id": "CVE-2024-3400"},
                }
            ),
            encoding="utf-8",
        )

        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            obs = _make_vuln_observation(artifact.artifact_id, ["CVE-2021-44228", "CVE-2024-3400"])
            ObservationRepository(s).save(obs)
            s.commit()

        # No findings stored — re-enrichment finds nothing but must not fail.
        with (
            patch("apps.api.tasks.post_scan_enrichment.SessionLocal", session_factory),
            patch("apps.api.tasks.post_scan_enrichment.FeedSyncer") as mock_syncer,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-002",
                cache_dir=tmp_path,
            )

        # sync_cve_records must NOT be called — everything was already known.
        mock_syncer.assert_not_called()
        assert summary["ok"] is True
        assert summary["cves_found"] == 2
        assert summary["cves_missing"] == 0


# ---------------------------------------------------------------------------
# 5. run_post_scan_enrichment — missing CVEs trigger sync and re-enrichment
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentMissingCves:
    def test_missing_cves_trigger_targeted_sync(self, engine, session_factory, tmp_path):
        """CVEs absent from mirrors trigger sync_cve_records."""
        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            obs = _make_vuln_observation(artifact.artifact_id, ["CVE-2021-44228"])
            ObservationRepository(s).save(obs)
            s.commit()

        # Mock FeedSyncer so no network I/O occurs.
        mock_result = MagicMock()
        mock_result.records_synced = 1
        mock_result.success = True
        mock_result.key = "nvd"

        mock_syncer_instance = MagicMock()
        mock_syncer_instance.sync_cve_records.return_value = [mock_result]

        with (
            patch("apps.api.tasks.post_scan_enrichment.SessionLocal", session_factory),
            patch(
                "apps.api.tasks.post_scan_enrichment.FeedSyncer",
                return_value=mock_syncer_instance,
            ),
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-003",
                cache_dir=tmp_path,
            )

        mock_syncer_instance.sync_cve_records.assert_called_once_with(["CVE-2021-44228"])
        assert summary["cves_synced"] == 1
        assert summary["ok"] is True

    def test_sync_partial_failure_marks_ok_false_but_reenrichment_continues(
        self, engine, session_factory, tmp_path
    ):
        """A partial sync failure marks ok=False but re-enrichment still runs."""
        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            obs = _make_vuln_observation(artifact.artifact_id, ["CVE-2024-3400"])
            ObservationRepository(s).save(obs)
            s.commit()

        failed_result = MagicMock()
        failed_result.records_synced = 0
        failed_result.success = False
        failed_result.key = "nvd"

        mock_syncer_instance = MagicMock()
        mock_syncer_instance.sync_cve_records.return_value = [failed_result]

        reenriched_calls: list[int] = []

        def _patched_reenrich(**kwargs: Any) -> None:
            reenriched_calls.append(1)

        with (
            patch("apps.api.tasks.post_scan_enrichment.SessionLocal", session_factory),
            patch(
                "apps.api.tasks.post_scan_enrichment.FeedSyncer",
                return_value=mock_syncer_instance,
            ),
            patch(
                "apps.api.tasks.post_scan_enrichment._reenrich_findings",
                side_effect=_patched_reenrich,
            ),
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-004",
                cache_dir=tmp_path,
            )

        # Re-enrichment was called despite sync failure.
        assert len(reenriched_calls) == 1
        assert summary["ok"] is False  # partial failure propagated

    def test_sync_exception_marks_ok_false_reenrichment_still_called(
        self, engine, session_factory, tmp_path
    ):
        """An exception inside FeedSyncer is caught and re-enrichment still runs."""
        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            obs = _make_vuln_observation(artifact.artifact_id, ["CVE-2024-3400"])
            ObservationRepository(s).save(obs)
            s.commit()

        reenriched_calls: list[int] = []

        def _patched_reenrich(**kwargs: Any) -> None:
            reenriched_calls.append(1)

        with (
            patch("apps.api.tasks.post_scan_enrichment.SessionLocal", session_factory),
            patch(
                "apps.api.tasks.post_scan_enrichment.FeedSyncer",
                side_effect=RuntimeError("upstream timeout"),
            ),
            patch(
                "apps.api.tasks.post_scan_enrichment._reenrich_findings",
                side_effect=_patched_reenrich,
            ),
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-005",
                cache_dir=tmp_path,
            )

        assert len(reenriched_calls) == 1
        assert summary["ok"] is False


# ---------------------------------------------------------------------------
# 6. DB error during CVE extraction
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentDbError:
    def test_db_error_marks_ok_false_and_returns_immediately(self, tmp_path):
        """SQLAlchemyError during observation read marks ok=False and returns early."""
        from sqlalchemy.exc import OperationalError

        def _failing_session():
            raise OperationalError("SELECT", {}, Exception("db down"))

        # Simulate SessionLocal context manager raising
        cm = MagicMock()
        cm.__enter__ = MagicMock(side_effect=OperationalError("", {}, Exception("down")))
        cm.__exit__ = MagicMock(return_value=False)
        mock_session_local = MagicMock(return_value=cm)

        with patch("apps.api.tasks.post_scan_enrichment.SessionLocal", mock_session_local):
            summary = run_post_scan_enrichment(
                artifact_id="art-xyz",
                engagement_id="eng-test",
                scan_id="scan-006",
                cache_dir=tmp_path,
            )

        assert summary["ok"] is False
        assert summary["cves_found"] == 0


# ---------------------------------------------------------------------------
# 7. _dispatch_post_scan_enrichment — enqueue failure is swallowed
# ---------------------------------------------------------------------------


class TestDispatchPostScanEnrichment:
    def test_enqueue_failure_does_not_raise(self):
        """apply_async failure is caught so the scan is never affected."""
        from apps.api.tasks import scans as scan_module

        with patch("apps.api.tasks.post_scan_enrichment.sync_new_findings_cves") as mock_task:
            mock_task.apply_async.side_effect = RuntimeError("Redis unavailable")
            # Must NOT raise.
            scan_module._dispatch_post_scan_enrichment(
                artifact_id="art-001",
                engagement_id="eng-test",
                scan_id="scan-007",
            )


# ---------------------------------------------------------------------------
# 8. Celery task wrapper — audit events
# ---------------------------------------------------------------------------


class TestSyncNewFindingsCvesTask:
    def test_completed_audit_event_on_success(self, tmp_path):
        """A successful pipeline emits post_scan_enrichment.completed."""
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

        mock_summary = {
            "artifact_id": "art-001",
            "scan_id": "scan-008",
            "cves_found": 2,
            "cves_missing": 1,
            "cves_synced": 1,
            "findings_reenriched": 1,
            "ok": True,
        }

        mock_self = MagicMock()

        with patch(
            "apps.api.tasks.post_scan_enrichment.run_post_scan_enrichment",
            return_value=mock_summary,
        ):
            sync_new_findings_cves.run.__func__(
                mock_self,
                "art-001",
                "eng-test",
                "scan-008",
            )

        events = get_audit_log()
        assert any(e["event"] == "post_scan_enrichment.completed" for e in events)

    def test_partial_audit_event_on_ok_false(self, tmp_path):
        """ok=False emits post_scan_enrichment.partial instead of .completed."""
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

        mock_summary = {
            "artifact_id": "art-002",
            "scan_id": "scan-009",
            "cves_found": 1,
            "cves_missing": 1,
            "cves_synced": 0,
            "findings_reenriched": 0,
            "ok": False,
        }

        mock_self = MagicMock()

        with patch(
            "apps.api.tasks.post_scan_enrichment.run_post_scan_enrichment",
            return_value=mock_summary,
        ):
            sync_new_findings_cves.run.__func__(
                mock_self,
                "art-002",
                "eng-test",
                "scan-009",
            )

        events = get_audit_log()
        assert any(e["event"] == "post_scan_enrichment.partial" for e in events)

    def test_unhandled_exception_emits_error_audit_event(self):
        """An unhandled exception inside the pipeline emits .error and does not re-raise."""
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

        mock_self = MagicMock()

        with patch(
            "apps.api.tasks.post_scan_enrichment.run_post_scan_enrichment",
            side_effect=RuntimeError("catastrophic"),
        ):
            # Must NOT raise — fire-and-forget guarantee.
            sync_new_findings_cves.run.__func__(
                mock_self,
                "art-003",
                "eng-test",
                "scan-010",
            )

        events = get_audit_log()
        assert any(e["event"] == "post_scan_enrichment.error" for e in events)
