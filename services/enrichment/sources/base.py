"""Base interface and domain models for enrichment intelligence sources.

Non-negotiable invariants:
1. Intelligence sources are mirrored locally. No live API calls happen during request-time enrichment.
2. Every piece of intelligence produced carries explicit Source and Confidence attribution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

RecordT = TypeVar("RecordT", bound=BaseModel)


class BaseSourceRecord(BaseModel):
    """Common fields for an intelligence record tied to a CVE."""

    model_config = ConfigDict(frozen=True)

    cve_id: str
    source: Source
    confidence: Confidence = Confidence.HIGH
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_payload: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def to_attributed(
        self,
        value: EnrichmentValue,
        source: Source | None = None,
        confidence: Confidence | None = None,
        note: str | None = None,
    ) -> Attributed[EnrichmentValue]:
        """Wrap an extracted value into an immutable Attributed container."""
        prov = Provenance(
            source=source or self.source,
            confidence=confidence or self.confidence,
            retrieved_at=self.retrieved_at,
            note=note,
        )
        return Attributed[EnrichmentValue](value=value, provenance=prov)


class BaseEnrichmentSource(ABC, Generic[RecordT]):
    """Abstract contract for offline-mirrored enrichment intelligence sources.

    Subclasses load data from local files/mirrors and perform fast in-memory
    lookups without making request-time network calls.
    """

    source: Source
    priority: int  # 1 is highest priority (CVE.org) per services/enrichment/README.md

    def __init__(self, cache_file: Path | str | None = None) -> None:
        self.cache_file = Path(cache_file) if cache_file else None
        self._cache: dict[str, RecordT] = {}
        self._loaded: bool = False
        if self.cache_file and self.cache_file.exists():
            self.load()

    @abstractmethod
    def load(self) -> None:
        """Load data from local cache storage into memory."""
        ...

    def is_cached(self, cve_id: str) -> bool:
        """Check if intelligence for a CVE is present in local cache."""
        if not self._loaded and self.cache_file and self.cache_file.exists():
            self.load()
        return cve_id.strip().upper() in self._cache

    def lookup(self, cve_id: str) -> RecordT | None:
        """Look up intelligence for a CVE from local mirror.

        CRITICAL: Never initiates network calls. Returns None or negative
        record if the CVE is not in the local mirror.
        """
        if not self._loaded and self.cache_file and self.cache_file.exists():
            self.load()
        return self._cache.get(cve_id.strip().upper())

    def count(self) -> int:
        """Return the number of records indexed in local cache."""
        if not self._loaded and self.cache_file and self.cache_file.exists():
            self.load()
        return len(self._cache)

    def clear(self) -> None:
        """Clear the in-memory index."""
        self._cache.clear()
        self._loaded = False
