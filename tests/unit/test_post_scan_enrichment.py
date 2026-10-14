"""Unit tests for the post-scan targeted feed sync & re-enrichment pipeline.

Test coverage (Task 6, PR #19 review):
  1. _cve_ids_from_artifact — extracts CVE IDs from VULN_CANDIDATE observations
  2. _missing_cve_ids — gaps computed per source, not "known to any mirror"
  3. run_post_scan_enrichment — no CVEs / all known / missing CVEs / per-run cap
  4. re-enrichment only for CVEs that actually got new data
  5. _reenrich_findings against stored findings: scoped to the scan's engagement,
     paged in chunks, persisted
  6. DB read error marks ok=False, does not raise
  7. Celery task wrapper — audit actor/target/details, time limits, error isolation
  8. scans._dispatch_post_scan_enrichment — retry=False, enqueue failure audited
  9. beat coverage — CVE IDs from VULN_CANDIDATE observations are retried
"""

from __future__ import annotations

import json
import shutil
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import apps.api.db.models as _models  # noqa: F401 — registers ORM tables
from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db.base import Base
from apps.api.db.models import EnrichedFindingModel
from apps.api.db.repositories import (
    EngagementRepository,
    ObservationRepository,
    RawArtifactRepository,
)
from apps.api.db.session import get_session_factory
from apps.api.tasks import post_scan_enrichment as pse
from apps.api.tasks.post_scan_enrichment import (
    _cve_ids_from_artifact,
    _findings_for_cves,
    _missing_cve_ids,
    _reenrich_findings,
    run_post_scan_enrichment,
)
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.enrichment.sources.sync import (
    MIRROR_FILENAMES,
    TARGETED_SOURCES,
    SyncResult,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "enrichment"
OLD = datetime(2000, 1, 1, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


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


def _make_finding(finding_id: str, engagement_id: str, cve_ids: list[str]) -> Finding:
    return Finding(
        finding_id=finding_id,
        engagement_id=engagement_id,
        asset_id="host:172.20.1.10",
        scanner="nuclei",
        cve_ids=cve_ids,
        observation_ids=[f"obs-{finding_id}"],
        detected_at=datetime(2026, 9, 20, tzinfo=UTC),
    )


def _seed_engagement(session: Any, engagement_id: str) -> None:
    EngagementRepository(session).save(
        Engagement(
            engagement_id=engagement_id,
            name=engagement_id,
            authorization=Authorization(
                engagement_id=engagement_id,
                authorized_by="operator",
                allowlist=("172.20.0.0/16",),
                granted_at=_now() - timedelta(hours=1),
                expires_at=_now() + timedelta(days=1),
            ),
            created_at=_now() - timedelta(hours=1),
        )
    )


def _seed_stored_finding(session: Any, finding: Finding) -> None:
    """A previously persisted, never-really-enriched row: no fields, old timestamp."""
    session.add(
        EnrichedFindingModel.from_schema(
            EnrichedFinding(finding=finding, fields={}), enriched_at=OLD
        )
    )


def _write_all_mirrors(cache_dir: Path, cve_ids: list[str]) -> None:
    for name in TARGETED_SOURCES:
        source = next(s for s, n in pse.SOURCE_NAMES.items() if n == name)
        (cache_dir / MIRROR_FILENAMES[source]).write_text(
            json.dumps({cve: {} for cve in cve_ids}), encoding="utf-8"
        )


def _result(key: str, synced: tuple[str, ...] = (), success: bool = True) -> SyncResult:
    source = next(s for s, n in pse.SOURCE_NAMES.items() if n == key)
    return SyncResult(
        source=source,
        success=success,
        records_synced=len(synced),
        target_path=Path(f"{key}.json"),
        error=None if success else "boom",
        cve_ids_synced=synced,
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


def _seed_scan_cves(session_factory: Any, cve_ids: list[str]) -> RawArtifact:
    artifact = _make_artifact()
    with session_factory() as s:
        RawArtifactRepository(s).save(artifact)
        ObservationRepository(s).save(_make_vuln_observation(artifact.artifact_id, cve_ids))
        s.commit()
    return artifact


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
# 2. _missing_cve_ids — per source
# ---------------------------------------------------------------------------


class TestMissingCveIds:
    def test_all_missing_everywhere_when_no_mirrors(self, tmp_path):
        cves = ["CVE-2021-44228", "CVE-2024-3400"]
        result = _missing_cve_ids(cves, tmp_path)
        assert result == {name: cves for name in TARGETED_SOURCES}

    def test_known_cve_excluded_only_for_that_source(self, tmp_path):
        (tmp_path / MIRROR_FILENAMES[Source.NVD]).write_text(
            json.dumps({"CVE-2021-44228": {"id": "CVE-2021-44228"}}), encoding="utf-8"
        )
        result = _missing_cve_ids(["CVE-2021-44228", "CVE-2024-3400"], tmp_path)
        assert result["nvd"] == ["CVE-2024-3400"]
        assert result["cve_org"] == ["CVE-2021-44228", "CVE-2024-3400"]

    def test_corrupt_mirror_treated_as_empty(self, tmp_path):
        (tmp_path / MIRROR_FILENAMES[Source.CVE_ORG]).write_text("not valid json", "utf-8")
        assert _missing_cve_ids(["CVE-2024-3400"], tmp_path)["cve_org"] == ["CVE-2024-3400"]

    def test_cve_org_record_does_not_hide_nvd_vulnrichment_euvd_gaps(self, tmp_path):
        """Regression: 'known in ANY mirror' meant NVD etc. were never fetched."""
        (tmp_path / MIRROR_FILENAMES[Source.CVE_ORG]).write_text(
            json.dumps({"CVE-2021-44228": {}}), encoding="utf-8"
        )
        result = _missing_cve_ids(["CVE-2021-44228"], tmp_path)
        assert result["cve_org"] == []
        for name in ("vulnrichment", "euvd", "nvd"):
            assert result[name] == ["CVE-2021-44228"]


# ---------------------------------------------------------------------------
# 3. run_post_scan_enrichment
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentNoCves:
    def test_no_vuln_candidate_observations_returns_early(self, engine, session_factory, tmp_path):
        """A scan with no VULN_CANDIDATE observations skips sync and enrichment."""
        artifact = _make_artifact()
        with session_factory() as s:
            RawArtifactRepository(s).save(artifact)
            ObservationRepository(s).save(_make_non_vuln_observation(artifact.artifact_id))
            s.commit()

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer") as syncer_cls,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-001",
                cache_dir=tmp_path,
            )

        syncer_cls.assert_not_called()
        assert summary["ok"] is True
        assert summary["cves_found"] == 0
        assert summary["cves_missing"] == 0
        assert summary["cves_synced"] == 0


class TestRunPostScanEnrichmentAllKnown:
    def test_no_sync_and_no_reenrichment_when_every_source_has_every_cve(
        self, engine, session_factory, tmp_path
    ):
        """Nothing new was fetched, so nothing is re-enriched (docstring contract)."""
        cves = ["CVE-2021-44228", "CVE-2024-3400"]
        _write_all_mirrors(tmp_path, cves)
        artifact = _seed_scan_cves(session_factory, cves)

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer") as syncer_cls,
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-002",
                cache_dir=tmp_path,
            )

        syncer_cls.assert_not_called()
        reenrich.assert_not_called()
        assert summary["ok"] is True
        assert summary["cves_found"] == 2
        assert summary["cves_missing"] == 0

    def test_known_to_cve_org_only_still_syncs_the_other_sources(
        self, engine, session_factory, tmp_path
    ):
        (tmp_path / MIRROR_FILENAMES[Source.CVE_ORG]).write_text(
            json.dumps({"CVE-2021-44228": {}}), encoding="utf-8"
        )
        artifact = _seed_scan_cves(session_factory, ["CVE-2021-44228"])
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = []

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
        ):
            run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-002b",
                cache_dir=tmp_path,
            )

        (missing,), _ = syncer.sync_missing_cve_records.call_args
        assert missing == {
            "cve_org": [],
            "vulnrichment": ["CVE-2021-44228"],
            "euvd": ["CVE-2021-44228"],
            "nvd": ["CVE-2021-44228"],
        }


class TestRunPostScanEnrichmentMissingCves:
    def test_missing_cves_trigger_per_source_sync(self, engine, session_factory, tmp_path):
        artifact = _seed_scan_cves(session_factory, ["CVE-2021-44228"])
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = [
            _result("cve_org", ("CVE-2021-44228",)),
            _result("nvd"),
        ]

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-003",
                cache_dir=tmp_path,
            )

        (missing,), _ = syncer.sync_missing_cve_records.call_args
        assert missing == {name: ["CVE-2021-44228"] for name in TARGETED_SOURCES}
        assert summary["cves_synced"] == 1
        assert summary["cves_sent_upstream"] == ["CVE-2021-44228"]
        assert summary["cves_with_new_data"] == ["CVE-2021-44228"]
        assert set(summary["sources"]) == {"cve_org", "nvd"}
        assert summary["ok"] is True
        assert reenrich.call_args.kwargs["cve_ids"] == {"CVE-2021-44228"}
        assert reenrich.call_args.kwargs["engagement_id"] == "eng-test"

    def test_reenrichment_limited_to_cves_with_new_data(self, engine, session_factory, tmp_path):
        artifact = _seed_scan_cves(session_factory, ["CVE-2021-44228", "CVE-2099-0001"])
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = [_result("nvd", ("CVE-2021-44228",))]

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-003b",
                cache_dir=tmp_path,
            )

        assert reenrich.call_args.kwargs["cve_ids"] == {"CVE-2021-44228"}

    def test_nothing_new_fetched_means_no_reenrichment(self, engine, session_factory, tmp_path):
        artifact = _seed_scan_cves(session_factory, ["CVE-2099-0001"])
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = [_result("nvd")]

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-003c",
                cache_dir=tmp_path,
            )

        reenrich.assert_not_called()

    def test_partial_failure_marks_ok_false_but_new_data_is_still_used(
        self, engine, session_factory, tmp_path
    ):
        artifact = _seed_scan_cves(session_factory, ["CVE-2024-3400"])
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = [
            _result("cve_org", ("CVE-2024-3400",)),
            _result("nvd", success=False),
        ]

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-004",
                cache_dir=tmp_path,
            )

        assert reenrich.call_count == 1
        assert summary["ok"] is False
        assert summary["failed_sources"] == ["nvd"]

    def test_sync_exception_marks_ok_false_without_reenrichment(
        self, engine, session_factory, tmp_path
    ):
        artifact = _seed_scan_cves(session_factory, ["CVE-2024-3400"])

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", side_effect=RuntimeError("upstream timeout")),
            patch.object(pse, "_reenrich_findings") as reenrich,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-005",
                cache_dir=tmp_path,
            )

        reenrich.assert_not_called()
        assert summary["ok"] is False
        assert "upstream timeout" in summary["error"]

    def test_per_run_cve_cap_defers_the_rest_to_beat(self, engine, session_factory, tmp_path):
        cves = [f"CVE-2021-{n:05d}" for n in range(1, 8)]
        artifact = _seed_scan_cves(session_factory, cves)
        syncer = MagicMock()
        syncer.sync_missing_cve_records.return_value = []

        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", return_value=syncer),
            patch.object(pse.settings, "post_scan_max_cves", 3),
            patch.object(pse.logger, "warning") as warn,
        ):
            summary = run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-cap",
                cache_dir=tmp_path,
            )

        (missing,), _ = syncer.sync_missing_cve_records.call_args
        assert all(ids == cves[:3] for ids in missing.values())
        assert summary["cves_sent_upstream"] == cves[:3]
        assert summary["cves_deferred"] == 4
        # Patched rather than caplog: other suites reconfigure logging propagation.
        assert any("cap" in str(c.args[0]).lower() for c in warn.call_args_list)

    def test_syncer_gets_a_time_budget_inside_the_soft_limit(
        self, engine, session_factory, tmp_path
    ):
        artifact = _seed_scan_cves(session_factory, ["CVE-2024-3400"])
        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer") as syncer_cls,
        ):
            syncer_cls.return_value.sync_missing_cve_records.return_value = []
            run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-budget",
                cache_dir=tmp_path,
            )
        budget = syncer_cls.call_args.kwargs["time_budget_seconds"]
        assert 0 < budget < pse.settings.post_scan_soft_time_limit_seconds


# ---------------------------------------------------------------------------
# 5. _reenrich_findings / _findings_for_cves against stored findings
# ---------------------------------------------------------------------------


@pytest.fixture
def mirror_dir(tmp_path: Path) -> Path:
    cache = tmp_path / "cache"
    cache.mkdir()
    shutil.copy(FIXTURES_DIR / "cve_org_sample.json", cache / MIRROR_FILENAMES[Source.CVE_ORG])
    return cache


class TestReenrichAgainstStoredFindings:
    def _seed(self, session_factory: Any) -> None:
        with session_factory() as s:
            _seed_engagement(s, "eng-A")
            _seed_engagement(s, "eng-B")
            s.flush()
            _seed_stored_finding(s, _make_finding("f-1", "eng-A", ["CVE-2021-44228"]))
            _seed_stored_finding(s, _make_finding("f-2", "eng-A", ["CVE-2021-41773"]))
            # Same finding_id and same CVE, different engagement: must be untouched.
            _seed_stored_finding(s, _make_finding("f-1", "eng-B", ["CVE-2021-44228"]))
            _seed_stored_finding(s, _make_finding("f-3", "eng-B", ["CVE-2021-44228"]))
            s.commit()

    def _rows(self, session_factory: Any) -> dict[tuple[str, str], EnrichedFindingModel]:
        with session_factory() as s:
            return {
                (r.engagement_id, r.finding_id): r
                for r in s.scalars(select(EnrichedFindingModel)).all()
            }

    def test_other_engagements_rows_are_untouched(self, engine, session_factory, mirror_dir):
        """B1: a scan in engagement A must not rewrite engagement B's findings."""
        self._seed(session_factory)
        summary: dict[str, Any] = {"ok": True, "findings_reenriched": 0}

        with patch.object(pse, "SessionLocal", session_factory):
            _reenrich_findings(
                cve_ids={"CVE-2021-44228"},
                engagement_id="eng-A",
                cache_dir=mirror_dir,
                summary=summary,
            )

        rows = self._rows(session_factory)
        assert summary["ok"] is True
        assert summary["findings_reenriched"] == 1
        # Engagement A, matching CVE: re-enriched and persisted.
        a1 = rows[("eng-A", "f-1")]
        assert a1.enriched_at.replace(tzinfo=UTC) > OLD
        assert any(v["provenance"]["source"] == Source.CVE_ORG.value for v in a1.fields.values()), (
            "fused CVE.org fields were not persisted"
        )
        # Engagement A, other CVE: not touched.
        assert rows[("eng-A", "f-2")].enriched_at.replace(tzinfo=UTC) == OLD
        # Engagement B, same CVE (and even the same finding_id): not touched.
        for key in (("eng-B", "f-1"), ("eng-B", "f-3")):
            assert rows[key].enriched_at.replace(tzinfo=UTC) == OLD
            assert rows[key].fields == {}

    def test_findings_for_cves_is_scoped_and_paged(self, engine, session_factory):
        with session_factory() as s:
            _seed_engagement(s, "eng-A")
            _seed_engagement(s, "eng-B")
            s.flush()
            for i in range(5):
                _seed_stored_finding(s, _make_finding(f"a-{i}", "eng-A", ["CVE-2021-44228"]))
            _seed_stored_finding(s, _make_finding("a-x", "eng-A", ["CVE-2014-0160"]))
            _seed_stored_finding(s, _make_finding("b-0", "eng-B", ["CVE-2021-44228"]))
            s.commit()

        with session_factory() as s:
            chunks = list(_findings_for_cves(s, "eng-A", {"CVE-2021-44228"}, chunk_size=2))

        found = [f.finding_id for chunk in chunks for f in chunk]
        assert sorted(found) == [f"a-{i}" for i in range(5)]
        assert all(len(chunk) <= 2 for chunk in chunks)
        assert all(f.engagement_id == "eng-A" for chunk in chunks for f in chunk)

    def test_chunked_reenrichment_persists_every_match(
        self, engine, session_factory, mirror_dir, monkeypatch
    ):
        with session_factory() as s:
            _seed_engagement(s, "eng-A")
            s.flush()
            for i in range(5):
                _seed_stored_finding(s, _make_finding(f"a-{i}", "eng-A", ["CVE-2021-44228"]))
            s.commit()
        monkeypatch.setattr(pse, "REENRICH_CHUNK_SIZE", 2)
        summary: dict[str, Any] = {"ok": True, "findings_reenriched": 0}

        with patch.object(pse, "SessionLocal", session_factory):
            _reenrich_findings(
                cve_ids={"CVE-2021-44228"},
                engagement_id="eng-A",
                cache_dir=mirror_dir,
                summary=summary,
            )

        assert summary["findings_reenriched"] == 5
        rows = self._rows(session_factory)
        assert all(r.enriched_at.replace(tzinfo=UTC) > OLD for r in rows.values())


# ---------------------------------------------------------------------------
# 6. DB error during CVE extraction
# ---------------------------------------------------------------------------


class TestRunPostScanEnrichmentDbError:
    def test_db_error_marks_ok_false_and_returns_immediately(self, tmp_path):
        """SQLAlchemyError during observation read marks ok=False and returns early."""
        from sqlalchemy.exc import OperationalError

        cm = MagicMock()
        cm.__enter__ = MagicMock(side_effect=OperationalError("", {}, Exception("down")))
        cm.__exit__ = MagicMock(return_value=False)
        mock_session_local = MagicMock(return_value=cm)

        with patch.object(pse, "SessionLocal", mock_session_local):
            summary = run_post_scan_enrichment(
                artifact_id="art-xyz",
                engagement_id="eng-test",
                scan_id="scan-006",
                cache_dir=tmp_path,
            )

        assert summary["ok"] is False
        assert summary["cves_found"] == 0


# ---------------------------------------------------------------------------
# 7. Celery task wrapper — audit events, time limits
# ---------------------------------------------------------------------------


def _summary(ok: bool) -> dict[str, Any]:
    return {
        "artifact_id": "art-001",
        "scan_id": "scan-008",
        "cves_found": 2,
        "cves_missing": 1,
        "cves_sent_upstream": ["CVE-2021-44228"],
        "cves_deferred": 0,
        "cves_synced": 1,
        "cves_with_new_data": ["CVE-2021-44228"],
        "sources": {"cve_org": {"success": True, "records": 1}},
        "failed_sources": [] if ok else ["nvd"],
        "findings_reenriched": 1,
        "ok": ok,
    }


class TestSyncNewFindingsCvesTask:
    def _run(self, *args: Any, **kwargs: Any) -> None:
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

        sync_new_findings_cves.run.__func__(MagicMock(), *args, **kwargs)

    def test_completed_audit_event_names_authorizer_target_and_upstream_cves(self):
        with patch.object(pse, "run_post_scan_enrichment", return_value=_summary(True)):
            self._run("art-001", "eng-test", "scan-008", actor="alice@lab")

        (event,) = [e for e in get_audit_log() if e["event"] == "post_scan_enrichment.completed"]
        assert event["actor"] == "alice@lab"
        assert event["engagement_id"] == "eng-test"
        assert "eng-test" in event["target"] and "scan-008" in event["target"]
        assert event["details"]["cves_sent_upstream"] == ["CVE-2021-44228"]
        assert event["details"]["sources"] == {"cve_org": {"success": True, "records": 1}}
        assert event["details"]["artifact_id"] == "art-001"

    def test_actor_falls_back_to_system(self):
        with patch.object(pse, "run_post_scan_enrichment", return_value=_summary(True)):
            self._run("art-001", "eng-test", "scan-008")
        (event,) = get_audit_log()
        assert event["actor"] == pse.SYSTEM_ACTOR

    def test_partial_audit_event_on_ok_false(self):
        with patch.object(pse, "run_post_scan_enrichment", return_value=_summary(False)):
            self._run("art-002", "eng-test", "scan-009", actor="alice@lab")
        assert any(e["event"] == "post_scan_enrichment.partial" for e in get_audit_log())

    def test_unhandled_exception_emits_error_audit_event(self):
        """An unhandled exception inside the pipeline emits .error and does not re-raise."""
        with patch.object(pse, "run_post_scan_enrichment", side_effect=RuntimeError("bad")):
            self._run("art-003", "eng-test", "scan-010", actor="alice@lab")
        (event,) = [e for e in get_audit_log() if e["event"] == "post_scan_enrichment.error"]
        assert event["actor"] == "alice@lab"

    def test_soft_time_limit_is_audited_not_raised(self):
        from celery.exceptions import SoftTimeLimitExceeded

        with patch.object(pse, "run_post_scan_enrichment", side_effect=SoftTimeLimitExceeded()):
            self._run("art-004", "eng-test", "scan-011")
        (event,) = [e for e in get_audit_log() if e["event"] == "post_scan_enrichment.error"]
        assert "SoftTimeLimitExceeded" in event["details"]["error"]

    def test_task_has_time_limits(self):
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

        soft = sync_new_findings_cves.soft_time_limit
        hard = sync_new_findings_cves.time_limit
        assert soft == pse.settings.post_scan_soft_time_limit_seconds
        assert hard is not None and hard > soft

    def test_soft_time_limit_is_not_swallowed_by_the_sync_step(
        self, engine, session_factory, tmp_path
    ):
        from celery.exceptions import SoftTimeLimitExceeded

        artifact = _seed_scan_cves(session_factory, ["CVE-2024-3400"])
        with (
            patch.object(pse, "SessionLocal", session_factory),
            patch.object(pse, "FeedSyncer", side_effect=SoftTimeLimitExceeded()),
            pytest.raises(SoftTimeLimitExceeded),
        ):
            run_post_scan_enrichment(
                artifact_id=artifact.artifact_id,
                engagement_id="eng-test",
                scan_id="scan-012",
                cache_dir=tmp_path,
            )


# ---------------------------------------------------------------------------
# 8. _dispatch_post_scan_enrichment
# ---------------------------------------------------------------------------


class TestDispatchPostScanEnrichment:
    def test_dispatch_does_not_retry_publishing_and_passes_actor(self):
        from apps.api.tasks import scans as scan_module

        with patch("apps.api.tasks.post_scan_enrichment.sync_new_findings_cves") as task:
            scan_module._dispatch_post_scan_enrichment(
                artifact_id="art-001",
                engagement_id="eng-test",
                scan_id="scan-007",
                actor="alice@lab",
            )
        kwargs = task.apply_async.call_args.kwargs
        assert kwargs["retry"] is False
        assert kwargs["kwargs"]["actor"] == "alice@lab"
        assert kwargs["kwargs"]["engagement_id"] == "eng-test"

    def test_enqueue_failure_does_not_raise_and_is_audited(self):
        from apps.api.tasks import scans as scan_module

        with patch("apps.api.tasks.post_scan_enrichment.sync_new_findings_cves") as task:
            task.apply_async.side_effect = RuntimeError("Redis unavailable")
            scan_module._dispatch_post_scan_enrichment(
                artifact_id="art-001",
                engagement_id="eng-test",
                scan_id="scan-007",
                actor="alice@lab",
            )

        (event,) = [
            e for e in get_audit_log() if e["event"] == "post_scan_enrichment.enqueue_failed"
        ]
        assert event["actor"] == "alice@lab"
        assert event["engagement_id"] == "eng-test"
        assert event["status"] == "error"
        assert "Redis unavailable" in event["details"]["error"]


# ---------------------------------------------------------------------------
# 9. Beat coverage: scan-only CVE IDs are retried by the daily sync
# ---------------------------------------------------------------------------


class TestBeatCoverage:
    def test_known_cve_ids_include_vuln_candidate_observations(self, engine, session_factory):
        from apps.api.tasks.sync_feeds import _known_cve_ids

        artifact = _make_artifact()
        with session_factory() as s:
            _seed_engagement(s, "eng-A")
            s.flush()
            _seed_stored_finding(s, _make_finding("f-1", "eng-A", ["CVE-2021-44228"]))
            RawArtifactRepository(s).save(artifact)
            ObservationRepository(s).save_all(
                [
                    _make_vuln_observation(
                        artifact.artifact_id, ["cve-2024-3400", "CVE-2021-44228"], "eng-A"
                    ),
                    _make_non_vuln_observation(artifact.artifact_id, "eng-A"),
                ]
            )
            s.commit()

        with session_factory() as s:
            assert _known_cve_ids(s) == ["CVE-2021-44228", "CVE-2024-3400"]
