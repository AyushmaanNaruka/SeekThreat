"""Provenance primitives.

Every enriched value in this system carries where it came from and how confident
we are. `Attributed[T]` pairs a value with its provenance so that an unattributed
value cannot be constructed.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, field_validator

from packages.schema.models._time import require_aware


class Source(str, Enum):
    """Where a piece of data came from. Required on enriched fields."""

    CVE_ORG = "cve.org"
    VULNRICHMENT = "cisa.vulnrichment"
    KEV = "cisa.kev"
    EPSS = "first.epss"
    NVD = "nvd"
    EUVD = "enisa.euvd"
    OSV = "osv.dev"
    GHSA = "github.advisories"
    EXPLOITDB = "exploitdb"
    METASPLOIT = "metasploit"
    BRON = "bron"
    DERIVED = "derived"
    SCANNER = "scanner"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Provenance(BaseModel):
    """Attached to every enriched value. Non-optional by design."""

    model_config = ConfigDict(frozen=True)

    source: Source
    confidence: Confidence
    retrieved_at: datetime
    note: str | None = None

    @field_validator("retrieved_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)


T = TypeVar("T")


class Attributed(BaseModel, Generic[T]):
    """A value and the provenance that justifies it, inseparably."""

    model_config = ConfigDict(frozen=True)

    value: T
    provenance: Provenance
