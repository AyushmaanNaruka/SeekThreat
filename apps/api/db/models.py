"""SQLAlchemy ORM models for Layer 1 Collection persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.db.base import Base
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Provenance

# JSONB on PostgreSQL, standard JSON fallback on SQLite
JSON_TYPE = JSONB().with_variant(JSON(), "sqlite")


class RawArtifactModel(Base):
    """Verbatim tool output, stored once and referenced by observations."""

    __tablename__ = "raw_artifacts"

    artifact_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    observations: Mapped[list[ObservationModel]] = relationship(
        "ObservationModel",
        back_populates="artifact",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @classmethod
    def from_schema(cls, artifact: RawArtifact) -> RawArtifactModel:
        """Create an ORM model instance from a Pydantic RawArtifact domain model."""
        return cls(
            artifact_id=artifact.artifact_id,
            scanner=artifact.scanner,
            content=artifact.content,
            content_type=artifact.content_type,
            captured_at=artifact.captured_at,
        )

    def to_schema(self) -> RawArtifact:
        """Convert ORM model to immutable Pydantic RawArtifact domain model."""
        captured_at = self.captured_at
        if captured_at.tzinfo is None:
            captured_at = captured_at.replace(tzinfo=UTC)
        return RawArtifact(
            artifact_id=self.artifact_id,
            scanner=self.scanner,
            content=self.content,
            content_type=self.content_type,
            captured_at=captured_at,
        )


class ObservationModel(Base):
    """One immutable fact reported by a scanner, persisted with attribution."""

    __tablename__ = "observations"

    observation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    artifact_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("raw_artifacts.artifact_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)

    artifact: Mapped[RawArtifactModel] = relationship(
        "RawArtifactModel",
        back_populates="observations",
    )

    __table_args__ = (
        Index("ix_observations_engagement_kind", "engagement_id", "kind"),
    )

    @classmethod
    def from_schema(cls, observation: Observation) -> ObservationModel:
        """Create an ORM model instance from a Pydantic Observation domain model."""
        return cls(
            observation_id=observation.observation_id,
            engagement_id=observation.engagement_id,
            scanner=observation.scanner,
            kind=observation.kind.value,
            subject=observation.subject,
            attributes=dict(observation.attributes),
            artifact_id=observation.artifact_id,
            observed_at=observation.observed_at,
            provenance=observation.provenance.model_dump(mode="json"),
        )

    def to_schema(self) -> Observation:
        """Convert ORM model to immutable Pydantic Observation domain model."""
        observed_at = self.observed_at
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=UTC)

        # Deserialize provenance dictionary into Pydantic model
        prov = Provenance.model_validate(self.provenance)

        return Observation(
            observation_id=self.observation_id,
            engagement_id=self.engagement_id,
            scanner=self.scanner,
            kind=ObservationKind(self.kind),
            subject=self.subject,
            attributes={k: str(v) for k, v in self.attributes.items()},
            artifact_id=self.artifact_id,
            observed_at=observed_at,
            provenance=prov,
        )


class EngagementModel(Base):
    """Scoped piece of authorized scan work."""

    __tablename__ = "engagements"

    engagement_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    authorized_by: Mapped[str] = mapped_column(String(128), nullable=False)
    allowlist: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scans: Mapped[list[ScanModel]] = relationship(
        "ScanModel",
        back_populates="engagement",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    @classmethod
    def from_schema(cls, engagement: Engagement) -> EngagementModel:
        """Create an ORM model instance from a Pydantic Engagement domain model."""
        return cls(
            engagement_id=engagement.engagement_id,
            name=engagement.name,
            authorized_by=engagement.authorization.authorized_by,
            allowlist=list(engagement.authorization.allowlist),
            granted_at=engagement.authorization.granted_at,
            expires_at=engagement.authorization.expires_at,
            created_at=engagement.created_at,
        )

    def to_schema(self) -> Engagement:
        """Convert ORM model to immutable Pydantic Engagement domain model."""
        granted_at = self.granted_at if self.granted_at.tzinfo is not None else self.granted_at.replace(tzinfo=UTC)
        expires_at = self.expires_at if self.expires_at.tzinfo is not None else self.expires_at.replace(tzinfo=UTC)
        created_at = self.created_at if self.created_at.tzinfo is not None else self.created_at.replace(tzinfo=UTC)

        auth = Authorization(
            engagement_id=self.engagement_id,
            authorized_by=self.authorized_by,
            allowlist=tuple(self.allowlist),
            granted_at=granted_at,
            expires_at=expires_at,
        )
        return Engagement(
            engagement_id=self.engagement_id,
            name=self.name,
            authorization=auth,
            created_at=created_at,
        )


class ScanModel(Base):
    """Record of a requested scan execution and its status."""

    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("engagements.engagement_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scanner: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    options: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False, default=dict)
    artifact_id: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("raw_artifacts.artifact_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    engagement: Mapped[EngagementModel] = relationship("EngagementModel", back_populates="scans")
    artifact: Mapped[RawArtifactModel | None] = relationship("RawArtifactModel")

