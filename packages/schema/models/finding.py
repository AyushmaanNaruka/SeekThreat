"""Findings, before and after enrichment.

`Finding` is what a scanner reported. `EnrichedFinding` is what multi-source
fusion made of it — and every fused field carries its own provenance, because
`Attributed` cannot be constructed without one.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from packages.schema.models._time import require_aware
from packages.schema.models.provenance import Attributed
from packages.schema.models.scoring import ExposureRiskScore

# What an enrichment source can supply for a single field.
EnrichmentValue = str | float | int | bool | list[str] | None

# Standard canonical CVE identifier format: CVE-YYYY-NNNN+. ASCII digits only:
# `\d` would also accept other Unicode decimal digits (e.g. Arabic-Indic, fullwidth),
# which then miss every mirror lookup and reach upstream URLs. Use with fullmatch.
CVE_ID_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}", re.ASCII)


class Finding(BaseModel):
    """One vulnerability on one asset, as reported by one scanner."""

    finding_id: str
    engagement_id: str
    asset_id: str
    scanner: str
    cve_ids: list[str] = Field(default_factory=list)
    title: str = ""
    description: str = ""
    observation_ids: list[str]
    detected_at: datetime

    @field_validator("cve_ids")
    @classmethod
    def _validate_cve_ids(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in value:
            norm = raw.strip().upper()
            if not CVE_ID_PATTERN.fullmatch(norm):
                raise ValueError(
                    f"invalid CVE ID {raw!r}; cve_ids must match standard 'CVE-YYYY-NNNN+' format"
                )
            if norm not in seen:
                seen.add(norm)
                cleaned.append(norm)
        return cleaned

    @field_validator("observation_ids")
    @classmethod
    def _must_trace_to_observations(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("a finding must reference at least one observation")
        return value

    @field_validator("detected_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)


class EnrichedFinding(BaseModel):
    """A finding plus fused, attributed intelligence about it."""

    finding: Finding
    fields: dict[str, Attributed[EnrichmentValue]] = Field(default_factory=dict)
    ers: ExposureRiskScore | None = None
