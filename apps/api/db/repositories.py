"""Repository layer with idempotent persistence for RawArtifact and Observation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import Insert as PGInsert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import Insert as SQLiteInsert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from apps.api.db.models import (
    EngagementModel,
    ObservationModel,
    RawArtifactModel,
    ScanModel,
)
from packages.schema.models.engagement import Engagement
from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
    ScanResult,
)


class RawArtifactRepository:
    """Repository handling persistence and lookup of RawArtifact records."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, artifact: RawArtifact) -> RawArtifact:
        """Idempotently persist a RawArtifact record.

        Because artifact_id is a deterministic content-addressed sha256, re-running
        a scan with identical output produces an identical ID and is safely ignored.
        """
        dialect = self.session.bind.dialect.name if self.session.bind else ""
        record = {
            "artifact_id": artifact.artifact_id,
            "scanner": artifact.scanner,
            "content": artifact.content,
            "content_type": artifact.content_type,
            "captured_at": artifact.captured_at,
        }

        stmt: PGInsert | SQLiteInsert
        if dialect == "postgresql":
            stmt = (
                pg_insert(RawArtifactModel)
                .values(**record)
                .on_conflict_do_nothing(index_elements=["artifact_id"])
            )
            self.session.execute(stmt)
        elif dialect == "sqlite":
            stmt = (
                sqlite_insert(RawArtifactModel)
                .values(**record)
                .on_conflict_do_nothing(index_elements=["artifact_id"])
            )
            self.session.execute(stmt)
        else:
            if not self.session.get(RawArtifactModel, artifact.artifact_id):
                self.session.add(RawArtifactModel.from_schema(artifact))

        self.session.flush()
        return artifact

    def get(self, artifact_id: str) -> RawArtifact | None:
        """Retrieve a RawArtifact by its unique ID."""
        model = self.session.get(RawArtifactModel, artifact_id)
        return model.to_schema() if model is not None else None

    def exists(self, artifact_id: str) -> bool:
        """Check if an artifact with this ID has already been persisted."""
        stmt = (
            select(func.count())
            .select_from(RawArtifactModel)
            .where(RawArtifactModel.artifact_id == artifact_id)
        )
        return bool(self.session.scalar(stmt))


class ObservationRepository:
    """Repository handling persistence, querying, and counting of Observation facts."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, observation: Observation) -> Observation:
        """Idempotently persist a single Observation record."""
        self.save_all([observation])
        return observation

    def save_all(self, observations: Sequence[Observation]) -> tuple[Observation, ...]:
        """Idempotently persist a batch of Observation records in one operation.

        Re-running a scan produces deterministic observation IDs; duplicate rows
        are skipped without raising integrity conflicts.
        """
        if not observations:
            return ()

        records: list[dict[str, Any]] = [
            {
                "observation_id": obs.observation_id,
                "engagement_id": obs.engagement_id,
                "scanner": obs.scanner,
                "kind": obs.kind.value,
                "subject": obs.subject,
                "attributes": dict(obs.attributes),
                "artifact_id": obs.artifact_id,
                "observed_at": obs.observed_at,
                "provenance": obs.provenance.model_dump(mode="json"),
            }
            for obs in observations
        ]

        dialect = self.session.bind.dialect.name if self.session.bind else ""

        stmt: PGInsert | SQLiteInsert
        if dialect == "postgresql":
            stmt = (
                pg_insert(ObservationModel)
                .values(records)
                .on_conflict_do_nothing(index_elements=["observation_id"])
            )
            self.session.execute(stmt)
        elif dialect == "sqlite":
            stmt = (
                sqlite_insert(ObservationModel)
                .values(records)
                .on_conflict_do_nothing(index_elements=["observation_id"])
            )
            self.session.execute(stmt)
        else:
            for obs in observations:
                if not self.session.get(ObservationModel, obs.observation_id):
                    self.session.add(ObservationModel.from_schema(obs))

        self.session.flush()
        return tuple(observations)

    def get(self, observation_id: str) -> Observation | None:
        """Retrieve a single observation by its primary key ID."""
        model = self.session.get(ObservationModel, observation_id)
        return model.to_schema() if model is not None else None

    def get_by_engagement(
        self,
        engagement_id: str,
        kind: ObservationKind | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Observation]:
        """Retrieve observations associated with an engagement, optionally filtered by kind.

        ``limit=None`` (the default) returns everything, matching prior behavior for
        existing callers. Ordering is stable (observed_at, then observation_id) so
        paging through with a fixed limit never skips or repeats a row.
        """
        stmt = select(ObservationModel).where(ObservationModel.engagement_id == engagement_id)
        if kind is not None:
            stmt = stmt.where(ObservationModel.kind == kind.value)
        stmt = stmt.order_by(
            ObservationModel.observed_at.asc(), ObservationModel.observation_id.asc()
        )
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        results = self.session.scalars(stmt).all()
        return [m.to_schema() for m in results]

    def get_by_artifact(
        self,
        artifact_id: str,
        kind: ObservationKind | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[Observation]:
        """Retrieve observations derived from a given raw artifact, optionally filtered by kind."""
        stmt = select(ObservationModel).where(ObservationModel.artifact_id == artifact_id)
        if kind is not None:
            stmt = stmt.where(ObservationModel.kind == kind.value)
        stmt = stmt.order_by(
            ObservationModel.observed_at.asc(), ObservationModel.observation_id.asc()
        )
        if offset:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        results = self.session.scalars(stmt).all()
        return [m.to_schema() for m in results]

    def count_by_engagement(
        self,
        engagement_id: str,
        kind: ObservationKind | None = None,
    ) -> int:
        """Count observations associated with an engagement, optionally filtered by kind."""
        stmt = (
            select(func.count())
            .select_from(ObservationModel)
            .where(ObservationModel.engagement_id == engagement_id)
        )
        if kind is not None:
            stmt = stmt.where(ObservationModel.kind == kind.value)
        count = self.session.scalar(stmt)
        return int(count) if count is not None else 0

    def count_by_artifact(
        self,
        artifact_id: str,
        kind: ObservationKind | None = None,
    ) -> int:
        """Count observations derived from a given raw artifact, optionally filtered by kind."""
        stmt = (
            select(func.count())
            .select_from(ObservationModel)
            .where(ObservationModel.artifact_id == artifact_id)
        )
        if kind is not None:
            stmt = stmt.where(ObservationModel.kind == kind.value)
        count = self.session.scalar(stmt)
        return int(count) if count is not None else 0


def save_scan_result(session: Session, scan_result: ScanResult) -> None:
    """Atomically persist an entire ScanResult (RawArtifact + Observations) idempotently."""
    artifact_repo = RawArtifactRepository(session)
    observation_repo = ObservationRepository(session)

    artifact_repo.save(scan_result.artifact)
    observation_repo.save_all(scan_result.observations)
    session.flush()


class EngagementRepository:
    """Repository handling persistence and lookup of Engagement records."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def save(self, engagement: Engagement) -> Engagement:
        """Create or update an Engagement record."""
        existing = self.session.get(EngagementModel, engagement.engagement_id)
        if existing is not None:
            existing.name = engagement.name
            existing.authorized_by = engagement.authorization.authorized_by
            existing.allowlist = list(engagement.authorization.allowlist)
            existing.granted_at = engagement.authorization.granted_at
            existing.expires_at = engagement.authorization.expires_at
            existing.created_at = engagement.created_at
        else:
            self.session.add(EngagementModel.from_schema(engagement))
        self.session.flush()
        return engagement

    def get(self, engagement_id: str) -> Engagement | None:
        """Retrieve an Engagement domain model by ID."""
        model = self.session.get(EngagementModel, engagement_id)
        return model.to_schema() if model is not None else None

    def list_all(self) -> list[Engagement]:
        """List all registered engagements, newest first."""
        stmt = select(EngagementModel).order_by(EngagementModel.created_at.desc())
        return [m.to_schema() for m in self.session.scalars(stmt).all()]


class ScanRepository:
    """Repository handling persistence and state transitions of Scan jobs."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        scan_id: str,
        engagement_id: str,
        scanner: str,
        target: str,
        options: dict[str, Any] | None = None,
    ) -> ScanModel:
        """Create a new pending scan job."""
        scan = ScanModel(
            scan_id=scan_id,
            engagement_id=engagement_id,
            scanner=scanner,
            target=target,
            status="pending",
            options=options or {},
            created_at=datetime.now(UTC),
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def get(self, scan_id: str) -> ScanModel | None:
        """Retrieve a scan record by scan_id."""
        return self.session.get(ScanModel, scan_id)

    def update_status(
        self,
        scan_id: str,
        status: str,
        artifact_id: str | None = None,
        error_message: str | None = None,
        completed_at: datetime | None = None,
    ) -> ScanModel | None:
        """Update the status and completion details of a scan job."""
        scan = self.session.get(ScanModel, scan_id)
        if scan is None:
            return None
        scan.status = status
        if artifact_id is not None:
            scan.artifact_id = artifact_id
        if error_message is not None:
            scan.error_message = error_message
        if completed_at is not None:
            scan.completed_at = completed_at
        elif status in ("completed", "failed") and scan.completed_at is None:
            scan.completed_at = datetime.now(UTC)
        self.session.flush()
        return scan

    def list_by_engagement(self, engagement_id: str) -> list[ScanModel]:
        """List all scans belonging to an engagement."""
        stmt = (
            select(ScanModel)
            .where(ScanModel.engagement_id == engagement_id)
            .order_by(ScanModel.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())
