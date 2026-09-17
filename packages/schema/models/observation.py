"""Immutable scan facts.

Observations are append-only and never mutated. Everything downstream — findings,
enrichment, the graph, paths, scores — is a view derived from them, which is what
makes the pipeline reproducible and every derived value traceable.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.schema.models._time import require_aware
from packages.schema.models.provenance import Provenance


class RawArtifact(BaseModel):
    """Verbatim tool output, stored once and referenced by observations."""

    model_config = ConfigDict(frozen=True)

    artifact_id: str
    scanner: str
    content: str
    content_type: str
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)


class ObservationKind(str, Enum):
    HOST_UP = "host_up"
    PORT_OPEN = "port_open"
    SERVICE_VERSION = "service_version"
    VULN_CANDIDATE = "vuln_candidate"
    REACHABILITY = "reachability"


class Observation(BaseModel):
    """One fact a scanner reported, at a point in time. Immutable."""

    model_config = ConfigDict(frozen=True)

    observation_id: str
    engagement_id: str
    scanner: str
    kind: ObservationKind
    subject: str
    # NOTE: dict values remain mutable in-place even though Observation is frozen;
    # Pydantic has no frozen-dict type. Accepted limitation — see final review, Phase 0.
    attributes: dict[str, str] = Field(default_factory=dict)
    artifact_id: str
    observed_at: datetime
    provenance: Provenance

    @field_validator("observed_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)


class ScanResult(BaseModel):
    """Everything one authorized scan produced: the artifact and the facts derived from it.

    Every observation must reference this result's own artifact — a scan never mixes
    facts derived from one tool run with an artifact from another.
    """

    model_config = ConfigDict(frozen=True)

    artifact: RawArtifact
    observations: tuple[Observation, ...] = ()

    @model_validator(mode="after")
    def _observations_reference_this_artifact(self) -> ScanResult:
        stray = sorted({o.artifact_id for o in self.observations} - {self.artifact.artifact_id})
        if stray:
            raise ValueError(
                f"observations reference artifact ids other than {self.artifact.artifact_id!r}: "
                f"{stray}"
            )
        return self
