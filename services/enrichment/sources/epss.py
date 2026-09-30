"""FIRST EPSS v4 intelligence source client (Exploitation Probability).

Priority 4 source per services/enrichment/README.md:
"FIRST EPSS v4: Exploitation probability; scores CVEs with no CVSS"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.sources.base import BaseEnrichmentSource, BaseSourceRecord


class FirstEPSSRecord(BaseSourceRecord):
    """FIRST Exploit Prediction Scoring System (EPSS v4) probability metrics."""

    source: Source = Source.EPSS
    confidence: Confidence = Confidence.HIGH
    epss: float
    percentile: float
    date: str | None = None

    def get_attributed_epss(self) -> Attributed[EnrichmentValue]:
        """Return Attributed EPSS probability score."""
        return self.to_attributed(
            value=self.epss,
            note=f"FIRST EPSS v4 probability score ({self.epss * 100:.2f}%)",
        )

    def get_attributed_percentile(self) -> Attributed[EnrichmentValue]:
        """Return Attributed EPSS percentile ranking."""
        return self.to_attributed(
            value=self.percentile,
            note=f"FIRST EPSS v4 percentile ranking ({self.percentile * 100:.1f}th percentile)",
        )


class FirstEPSSSource(BaseEnrichmentSource[FirstEPSSRecord]):
    """Local-mirror client for FIRST EPSS v4 scoring feed."""

    source = Source.EPSS
    priority = 4

    def load(self) -> None:
        """Load and index FIRST EPSS v4 JSON feed."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        with open(self.cache_file, encoding="utf-8") as f:
            data = json.load(f)

        records: dict[str, FirstEPSSRecord] = {}
        items = data.get("data", []) if isinstance(data, dict) else data

        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                cve_id = item.get("cve") or item.get("cve_id")
                if not cve_id:
                    continue
                cve_id = cve_id.strip().upper()

                try:
                    epss_val = float(item["epss"])
                    percentile_val = float(item["percentile"])
                except (KeyError, ValueError, TypeError):
                    continue

                records[cve_id] = FirstEPSSRecord(
                    cve_id=cve_id,
                    epss=epss_val,
                    percentile=percentile_val,
                    date=item.get("date"),
                    raw_payload=item,
                )

        self._cache = records
        self._loaded = True
