"""Immutable scan facts.

Observations are append-only and never mutated. Everything downstream — findings,
enrichment, the graph, paths, scores — is a view derived from them, which is what
makes the pipeline reproducible and every derived value traceable.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
