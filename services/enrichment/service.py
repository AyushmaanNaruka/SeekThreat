"""Enrichment pipeline coordinator service.

Orchestrates multi-source intelligence fusion, additive Exposure Risk Score
(ERS) computation, and idempotent persistence for finding records.

Load-bearing architectural constraints:
1. Purely local offline execution: no outbound network calls occur during
   enrichment. All sources query local mirrors.
2. Provenance preservation: every enriched field carries source attribution
   and confidence.
3. Strict upsert idempotency: repeated enrichment runs never duplicate or
   corrupt existing database rows.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from apps.api.db.repositories import EnrichedFindingRepository
from packages.schema.models.finding import EnrichedFinding, Finding
from services.enrichment.fusion import FusionEngine


class EnrichmentService:
    """Coordinates finding enrichment across intelligence sources, ERS, and persistence."""

    def __init__(
        self,
        fusion_engine: FusionEngine | None = None,
        repository: EnrichedFindingRepository | None = None,
    ) -> None:
        self.fusion_engine = fusion_engine or FusionEngine()
        self.repository = repository

    def _resolve_repository(
        self, session: Session | None = None
    ) -> EnrichedFindingRepository:
        """Resolve repository from explicit session or existing instance."""
        if session is not None:
            return EnrichedFindingRepository(session)
        if self.repository is not None:
            return self.repository
        raise ValueError(
            "Database operation requested, but neither an active Session nor "
            "an EnrichedFindingRepository was provided to EnrichmentService."
        )

    def enrich_finding(
        self,
        finding: Finding,
        persist: bool = False,
        session: Session | None = None,
        compute_ers: bool = True,
        enriched_at: datetime | None = None,
    ) -> EnrichedFinding:
        """Enrich a single finding through multi-source fusion and ERS scoring.

        Args:
            finding: Raw finding reported by scanner.
            persist: Whether to store/upsert the enriched finding in the database.
            session: Optional active SQLAlchemy session.
            compute_ers: Whether to evaluate the additive Exposure Risk Score.
            enriched_at: Optional timestamp override for enrichment execution.

        Returns:
            Fully populated EnrichedFinding domain model.
        """
        enriched = self.fusion_engine.fuse_to_enriched_finding(
            finding, compute_ers=compute_ers
        )
        if persist:
            repo = self._resolve_repository(session)
            repo.upsert(enriched, enriched_at=enriched_at or datetime.now(UTC))
        return enriched

    def enrich_batch(
        self,
        findings: Sequence[Finding],
        persist: bool = False,
        session: Session | None = None,
        compute_ers: bool = True,
        enriched_at: datetime | None = None,
    ) -> list[EnrichedFinding]:
        """Enrich a collection of findings through multi-source fusion and ERS scoring.

        Args:
            findings: Sequence of findings to enrich.
            persist: Whether to batch upsert the results in the database.
            session: Optional active SQLAlchemy session.
            compute_ers: Whether to evaluate additive Exposure Risk Scores.
            enriched_at: Optional timestamp override for enrichment execution.

        Returns:
            List of EnrichedFinding domain models.
        """
        results: list[EnrichedFinding] = [
            self.fusion_engine.fuse_to_enriched_finding(f, compute_ers=compute_ers)
            for f in findings
        ]
        if persist and results:
            repo = self._resolve_repository(session)
            repo.upsert_all(results, enriched_at=enriched_at or datetime.now(UTC))
        return results

    def get_enriched_finding(
        self, finding_id: str, session: Session | None = None
    ) -> EnrichedFinding | None:
        """Retrieve a persisted EnrichedFinding by its primary key finding_id."""
        repo = self._resolve_repository(session)
        return repo.get(finding_id)

    def get_by_engagement(
        self,
        engagement_id: str,
        limit: int | None = None,
        offset: int = 0,
        session: Session | None = None,
    ) -> list[EnrichedFinding]:
        """Retrieve paginated enriched findings belonging to an engagement."""
        repo = self._resolve_repository(session)
        return repo.get_by_engagement(engagement_id, limit=limit, offset=offset)

    def count_by_engagement(
        self, engagement_id: str, session: Session | None = None
    ) -> int:
        """Count enriched findings belonging to an engagement."""
        repo = self._resolve_repository(session)
        return repo.count_by_engagement(engagement_id)
