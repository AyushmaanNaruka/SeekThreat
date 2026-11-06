"""Tests for B-4: Beat-sync re-enrichment in apps.api.tasks.sync_feeds.

Invariants tested:
- _engagement_ids_for_cves returns the correct engagement IDs that reference a CVE.
- _beat_reenrich triggers re-enrichment only for affected engagements.
- Audit events are logged per-engagement with correct actor and target.
- Engagements whose findings do NOT overlap the synced CVEs are skipped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from apps.api.core.audit import clear_audit_log, get_audit_log

# ---------------------------------------------------------------------------
# Helpers: mock DB session returning enriched-finding-like rows
# ---------------------------------------------------------------------------


def _mock_session_with_findings(findings_by_engagement: dict[str, list[dict[str, Any]]]):
    """Return a mock SessionLocal context-manager that yields a fake session.

    ``findings_by_engagement`` maps engagement_id -> list of finding_data dicts.
    """

    class FakeSession:
        def __init__(self):
            self._committed = False

        def execute(self, stmt):
            """Return rows as a mock result set."""
            return FakeResult(findings_by_engagement)

        def commit(self):
            self._committed = True

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeResult:
        def __init__(self, data):
            self._data = data

        def scalars(self):
            return self

        def all(self):
            rows = []
            for eid, findings in self._data.items():
                for f in findings:
                    rows.append((eid, f))
            return rows

        def __iter__(self):
            for eid, findings in self._data.items():
                for f in findings:
                    yield (eid, f)

    return FakeSession


class TestEngagementIdsForCves:
    """Tests for _engagement_ids_for_cves helper."""

    def test_returns_matching_engagement(self):
        """An engagement whose finding references a synced CVE is returned."""
        from apps.api.tasks.sync_feeds import _engagement_ids_for_cves

        findings = {
            "eng-1": [
                {"cve_ids": ["CVE-2023-1111", "CVE-2023-2222"], "title": "f1"},
            ],
            "eng-2": [
                {"cve_ids": ["CVE-2023-9999"], "title": "f2"},
            ],
        }
        session = _mock_session_with_findings(findings)()
        result = _engagement_ids_for_cves(session, {"CVE-2023-1111"})
        assert "eng-1" in result
        assert "eng-2" not in result

    def test_returns_empty_for_no_overlap(self):
        from apps.api.tasks.sync_feeds import _engagement_ids_for_cves

        findings = {
            "eng-1": [{"cve_ids": ["CVE-2023-9999"], "title": "f1"}],
        }
        session = _mock_session_with_findings(findings)()
        result = _engagement_ids_for_cves(session, {"CVE-2023-0001"})
        assert result == []

    def test_case_insensitive_cve_matching(self):
        from apps.api.tasks.sync_feeds import _engagement_ids_for_cves

        findings = {
            "eng-1": [{"cve_ids": ["cve-2023-1111"], "title": "f1"}],
        }
        session = _mock_session_with_findings(findings)()
        result = _engagement_ids_for_cves(session, {"CVE-2023-1111"})
        assert "eng-1" in result


class TestBeatReenrich:
    """Tests for _beat_reenrich function (integration-style with mocks)."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        clear_audit_log()

    def test_audit_event_per_engagement(self):
        """Each affected engagement gets its own audit event."""
        from apps.api.tasks.sync_feeds import _beat_reenrich

        # Mock _engagement_ids_for_cves to return ["eng-1"]
        # Mock SessionLocal, EnrichedFindingRepository, EnrichmentService
        with (
            patch("apps.api.tasks.sync_feeds._engagement_ids_for_cves", return_value=["eng-1"]),
            patch("apps.api.tasks.sync_feeds.SessionLocal") as mock_session_cls,
            patch("apps.api.tasks.sync_feeds.settings") as mock_settings,
        ):
            mock_settings.enrichment_cache_dir = Path("/fake/cache")

            # Mock the session context that returns no matching rows (empty re-enrichment)
            mock_session = MagicMock()
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.execute.return_value.all.return_value = []
            mock_session_cls.return_value = mock_session

            # Mock the imports inside the function
            with (
                patch("apps.api.tasks.sync_feeds.EnrichedFindingRepository", create=True),
                patch("apps.api.tasks.sync_feeds.EnrichmentService", create=True),
            ):
                result = _beat_reenrich({"CVE-2023-1111"}, "system:celery_beat")

            assert "eng-1" in result["engagements"]
            # Check audit event
            events = get_audit_log()
            beat_events = [e for e in events if e["event"] == "beat_sync.reenrichment"]
            assert len(beat_events) == 1
            assert beat_events[0]["target"] == "engagement:eng-1/beat_sync"
            assert beat_events[0]["actor"] == "system:celery_beat"
            assert beat_events[0]["engagement_id"] == "eng-1"

    def test_no_engagements_returns_empty(self):
        """When no engagements reference the synced CVEs, no re-enrichment happens."""
        from apps.api.tasks.sync_feeds import _beat_reenrich

        with (
            patch("apps.api.tasks.sync_feeds._engagement_ids_for_cves", return_value=[]),
            patch("apps.api.tasks.sync_feeds.SessionLocal"),
        ):
            result = _beat_reenrich({"CVE-2023-9999"}, "system:celery_beat")

        assert result["engagements"] == {}
        beat_events = [e for e in get_audit_log() if e["event"] == "beat_sync.reenrichment"]
        assert len(beat_events) == 0

    def test_summary_includes_synced_cves(self):
        """Summary includes the CVEs that triggered re-enrichment."""
        from apps.api.tasks.sync_feeds import _beat_reenrich

        with (
            patch("apps.api.tasks.sync_feeds._engagement_ids_for_cves", return_value=[]),
            patch("apps.api.tasks.sync_feeds.SessionLocal"),
        ):
            result = _beat_reenrich({"CVE-2023-1111", "CVE-2023-2222"}, "system:celery_beat")

        assert sorted(result["cves_synced"]) == ["CVE-2023-1111", "CVE-2023-2222"]

    def test_engagement_isolation(self):
        """Only the engagement that overlaps is re-enriched; others are not touched."""
        from apps.api.tasks.sync_feeds import _beat_reenrich

        # Only eng-2 references CVE-2023-1111
        with (
            patch("apps.api.tasks.sync_feeds._engagement_ids_for_cves", return_value=["eng-2"]),
            patch("apps.api.tasks.sync_feeds.SessionLocal") as mock_session_cls,
            patch("apps.api.tasks.sync_feeds.settings") as mock_settings,
        ):
            mock_settings.enrichment_cache_dir = Path("/fake/cache")
            mock_session = MagicMock()
            mock_session.__enter__ = MagicMock(return_value=mock_session)
            mock_session.__exit__ = MagicMock(return_value=False)
            mock_session.execute.return_value.all.return_value = []
            mock_session_cls.return_value = mock_session

            with (
                patch("apps.api.tasks.sync_feeds.EnrichedFindingRepository", create=True),
                patch("apps.api.tasks.sync_feeds.EnrichmentService", create=True),
            ):
                result = _beat_reenrich({"CVE-2023-1111"}, "system:celery_beat")

        assert "eng-2" in result["engagements"]
        assert "eng-1" not in result["engagements"]
