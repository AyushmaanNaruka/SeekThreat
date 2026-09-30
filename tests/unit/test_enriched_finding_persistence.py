"""Unit tests for EnrichedFinding persistence and idempotent upsert invariants.

Task 5 guard: verifying that repeat enrichment runs on the same finding_id
produce exactly one row with byte-identical content, and that the full
EnrichedFinding domain model survives a round-trip through the ORM.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from apps.api.db.base import Base
from apps.api.db.models import EnrichedFindingModel
from apps.api.db.repositories import EnrichedFindingRepository
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 9, 30, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def db_session() -> Session:
    """Isolated, in-memory SQLite session with foreign keys enabled."""
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


def _prov(source: Source = Source.CVE_ORG) -> Provenance:
    return Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW)


def _finding(finding_id: str = "fnd-001", engagement_id: str = "eng-001") -> Finding:
    return Finding(
        finding_id=finding_id,
        engagement_id=engagement_id,
        asset_id="ast-001",
        scanner="nmap",
        cve_ids=["CVE-2021-41773"],
        title="Apache path traversal",
        description="Apache 2.4.49 path traversal and RCE",
        observation_ids=["obs-001"],
        detected_at=NOW,
    )


def _ers() -> ExposureRiskScore:
    cvss_component = ScoreComponent(
        name="cvss_base",
        value=9.8,
        weight=0.40,
        explanation="CVSS base score 9.8 normalized to 9.8 on 0–10 scale",
        provenance=_prov(Source.CVE_ORG),
    )
    epss_component = ScoreComponent(
        name="epss",
        value=8.5,
        weight=0.35,
        explanation="EPSS probability 0.85 scaled to 8.5 on 0–10 scale",
        provenance=_prov(Source.EPSS),
    )
    kev_component = ScoreComponent(
        name="kev",
        value=2.5,
        weight=0.25,
        explanation="Listed in CISA KEV — active exploitation confirmed (+2.5 additive boost)",
        provenance=_prov(Source.KEV),
    )
    value = (
        cvss_component.value * cvss_component.weight
        + epss_component.value * epss_component.weight
        + kev_component.value * kev_component.weight
    )
    return ExposureRiskScore(
        value=round(value, 6),
        components=(cvss_component, epss_component, kev_component),
    )


def _enriched_finding(
    finding_id: str = "fnd-001",
    engagement_id: str = "eng-001",
    with_ers: bool = True,
) -> EnrichedFinding:
    fields: dict[str, Attributed[EnrichmentValue]] = {
        "cvss_base": Attributed[EnrichmentValue](value=9.8, provenance=_prov()),
        "description": Attributed[EnrichmentValue](
            value="Apache 2.4.49 path traversal and RCE",
            provenance=_prov(Source.VULNRICHMENT),
        ),
        "kev_listed": Attributed[EnrichmentValue](value=True, provenance=_prov(Source.KEV)),
    }
    return EnrichedFinding(
        finding=_finding(finding_id=finding_id, engagement_id=engagement_id),
        fields=fields,
        ers=_ers() if with_ers else None,
    )


# ---------------------------------------------------------------------------
# ORM model round-trip tests
# ---------------------------------------------------------------------------


class TestEnrichedFindingModelRoundTrip:
    """Verify from_schema / to_schema preserve the complete domain object."""

    def test_from_schema_populates_all_columns(self) -> None:
        enriched = _enriched_finding()
        model = EnrichedFindingModel.from_schema(enriched, enriched_at=NOW)

        assert model.finding_id == "fnd-001"
        assert model.engagement_id == "eng-001"
        assert isinstance(model.finding_data, dict)
        assert model.finding_data["finding_id"] == "fnd-001"
        assert isinstance(model.fields, dict)
        assert "cvss_base" in model.fields
        assert model.ers_value is not None
        assert model.ers_components is not None
        assert len(model.ers_components) == 3
        assert model.enriched_at == NOW

    def test_to_schema_reconstructs_finding(self, db_session: Session) -> None:
        enriched = _enriched_finding()
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()

        result = repo.get("fnd-001")
        assert result is not None
        assert result.finding.finding_id == "fnd-001"
        assert result.finding.engagement_id == "eng-001"
        assert result.finding.cve_ids == ["CVE-2021-41773"]

    def test_to_schema_reconstructs_attributed_fields(self, db_session: Session) -> None:
        enriched = _enriched_finding()
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()

        result = repo.get("fnd-001")
        assert result is not None
        assert "cvss_base" in result.fields
        assert result.fields["cvss_base"].value == 9.8
        assert result.fields["cvss_base"].provenance.source == Source.CVE_ORG
        assert result.fields["kev_listed"].value is True
        assert result.fields["kev_listed"].provenance.source == Source.KEV

    def test_to_schema_reconstructs_ers(self, db_session: Session) -> None:
        enriched = _enriched_finding(with_ers=True)
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()

        result = repo.get("fnd-001")
        assert result is not None
        assert result.ers is not None
        assert len(result.ers.components) == 3
        expected_value = sum(c.value * c.weight for c in enriched.ers.components)  # type: ignore[union-attr]
        assert abs(result.ers.value - expected_value) < 1e-6

    def test_to_schema_without_ers_produces_none(self, db_session: Session) -> None:
        enriched = _enriched_finding(with_ers=False)
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()

        result = repo.get("fnd-001")
        assert result is not None
        assert result.ers is None


# ---------------------------------------------------------------------------
# Idempotency tests — the core Task 5 invariant
# ---------------------------------------------------------------------------


class TestEnrichedFindingIdempotentUpsert:
    """Verify upsert is idempotent: identical state, exactly one row, always."""

    def test_double_upsert_produces_exactly_one_row(self, db_session: Session) -> None:
        """Core idempotency invariant: N upserts → 1 row, not N rows."""
        enriched = _enriched_finding()
        repo = EnrichedFindingRepository(db_session)

        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()
        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()

        count_stmt = select(func.count()).select_from(EnrichedFindingModel)
        row_count = db_session.scalar(count_stmt)
        assert row_count == 1, f"expected 1 row after 2 upserts; got {row_count}"

    def test_upserted_twice_with_same_data_yields_identical_content(
        self, db_session: Session
    ) -> None:
        """Content idempotency: two identical upserts produce byte-identical rows."""
        enriched = _enriched_finding()
        repo = EnrichedFindingRepository(db_session)

        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()
        result_1 = repo.get("fnd-001")

        repo.upsert(enriched, enriched_at=NOW)
        db_session.commit()
        result_2 = repo.get("fnd-001")

        assert result_1 is not None
        assert result_2 is not None
        assert result_1.model_dump(mode="json") == result_2.model_dump(mode="json")

    def test_upsert_overwrites_stale_fields_on_re_enrichment(
        self, db_session: Session
    ) -> None:
        """Re-enrichment with updated fields replaces old data in place."""
        enriched_v1 = _enriched_finding()
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(enriched_v1, enriched_at=NOW)
        db_session.commit()

        # Simulate a re-enrichment with a different cvss value
        updated_fields = {
            "cvss_base": Attributed[EnrichmentValue](
                value=6.5,  # updated score
                provenance=_prov(Source.NVD),
            ),
        }
        enriched_v2 = EnrichedFinding(
            finding=_finding(),
            fields=updated_fields,
            ers=None,
        )
        later = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
        repo.upsert(enriched_v2, enriched_at=later)
        db_session.commit()

        # Still exactly one row
        count_stmt = select(func.count()).select_from(EnrichedFindingModel)
        assert db_session.scalar(count_stmt) == 1

        result = repo.get("fnd-001")
        assert result is not None
        assert result.fields["cvss_base"].value == 6.5
        assert result.fields["cvss_base"].provenance.source == Source.NVD
        # ERS is gone (re-enrichment produced None)
        assert result.ers is None

    def test_batch_upsert_all_produces_correct_row_count(
        self, db_session: Session
    ) -> None:
        """upsert_all on N distinct findings creates exactly N rows."""
        findings = [
            _enriched_finding(finding_id=f"fnd-{i:03d}", engagement_id="eng-001")
            for i in range(1, 6)
        ]
        repo = EnrichedFindingRepository(db_session)
        repo.upsert_all(findings, enriched_at=NOW)
        db_session.commit()

        count = db_session.scalar(
            select(func.count()).select_from(EnrichedFindingModel)
        )
        assert count == 5

    def test_batch_upsert_all_twice_stays_idempotent(
        self, db_session: Session
    ) -> None:
        """Running upsert_all twice on the same batch keeps row count stable."""
        findings = [
            _enriched_finding(finding_id=f"fnd-{i:03d}", engagement_id="eng-001")
            for i in range(1, 4)
        ]
        repo = EnrichedFindingRepository(db_session)
        repo.upsert_all(findings, enriched_at=NOW)
        db_session.commit()
        repo.upsert_all(findings, enriched_at=NOW)
        db_session.commit()

        count = db_session.scalar(
            select(func.count()).select_from(EnrichedFindingModel)
        )
        assert count == 3


# ---------------------------------------------------------------------------
# Query method tests
# ---------------------------------------------------------------------------


class TestEnrichedFindingRepositoryQueries:
    """Verify get, get_by_engagement, and count_by_engagement."""

    def test_get_returns_none_for_missing_id(self, db_session: Session) -> None:
        repo = EnrichedFindingRepository(db_session)
        assert repo.get("nonexistent") is None

    def test_get_by_engagement_returns_findings_for_that_engagement(
        self, db_session: Session
    ) -> None:
        repo = EnrichedFindingRepository(db_session)
        for i in range(1, 4):
            repo.upsert(
                _enriched_finding(finding_id=f"fnd-{i:03d}", engagement_id="eng-A"),
                enriched_at=NOW,
            )
        repo.upsert(
            _enriched_finding(finding_id="fnd-999", engagement_id="eng-B"),
            enriched_at=NOW,
        )
        db_session.commit()

        results = repo.get_by_engagement("eng-A")
        assert len(results) == 3
        assert all(r.finding.engagement_id == "eng-A" for r in results)

    def test_get_by_engagement_does_not_return_other_engagements(
        self, db_session: Session
    ) -> None:
        repo = EnrichedFindingRepository(db_session)
        repo.upsert(
            _enriched_finding(finding_id="fnd-001", engagement_id="eng-X"),
            enriched_at=NOW,
        )
        db_session.commit()

        results = repo.get_by_engagement("eng-Y")
        assert results == []

    def test_count_by_engagement_returns_correct_count(
        self, db_session: Session
    ) -> None:
        repo = EnrichedFindingRepository(db_session)
        for i in range(1, 6):
            repo.upsert(
                _enriched_finding(finding_id=f"fnd-{i:03d}", engagement_id="eng-001"),
                enriched_at=NOW,
            )
        db_session.commit()

        assert repo.count_by_engagement("eng-001") == 5
        assert repo.count_by_engagement("eng-999") == 0

    def test_get_by_engagement_respects_limit_and_offset(
        self, db_session: Session
    ) -> None:
        repo = EnrichedFindingRepository(db_session)
        for i in range(1, 11):
            repo.upsert(
                _enriched_finding(finding_id=f"fnd-{i:03d}", engagement_id="eng-001"),
                enriched_at=NOW,
            )
        db_session.commit()

        page_1 = repo.get_by_engagement("eng-001", limit=4, offset=0)
        page_2 = repo.get_by_engagement("eng-001", limit=4, offset=4)
        assert len(page_1) == 4
        assert len(page_2) == 4
        # Pages must not overlap
        ids_1 = {r.finding.finding_id for r in page_1}
        ids_2 = {r.finding.finding_id for r in page_2}
        assert ids_1.isdisjoint(ids_2)
