"""CISA Known Exploited Vulnerabilities (KEV) intelligence source client.

Priority 3 source per services/enrichment/README.md:
"CISA KEV: Confirmed active exploitation — first-tier signal"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.sources.base import BaseEnrichmentSource, BaseSourceRecord


class CISAKevRecord(BaseSourceRecord):
    """CISA KEV catalog record confirming whether a CVE is actively exploited in the wild."""

    source: Source = Source.KEV
    confidence: Confidence = Confidence.HIGH
    is_in_kev: bool = False
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str | None = None
    short_description: str = ""
    required_action: str = ""
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    notes: str = ""

    def get_attributed_is_in_kev(self) -> Attributed[EnrichmentValue]:
        """Return Attributed boolean indicating confirmed active exploitation."""
        note = (
            f"Confirmed active exploitation in the wild (added {self.date_added})"
            if self.is_in_kev
            else "Not listed in CISA Known Exploited Vulnerabilities catalog"
        )
        return self.to_attributed(value=self.is_in_kev, note=note)

    def get_attributed_date_added(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed date added to KEV if present."""
        if not self.is_in_kev or not self.date_added:
            return None
        return self.to_attributed(value=self.date_added, note="Date added to CISA KEV catalog")

    def get_attributed_ransomware_use(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed ransomware campaign use status if present."""
        if not self.is_in_kev or not self.known_ransomware_campaign_use:
            return None
        return self.to_attributed(
            value=self.known_ransomware_campaign_use,
            note="Known ransomware campaign association per CISA",
        )


class CISAKevSource(BaseEnrichmentSource[CISAKevRecord]):
    """Local-mirror client for CISA KEV catalog."""

    source = Source.KEV
    priority = 3

    def load(self) -> None:
        """Load and index CISA KEV catalog JSON data."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        with open(self.cache_file, encoding="utf-8") as f:
            data = json.load(f)

        records: dict[str, CISAKevRecord] = {}
        vuln_list = data.get("vulnerabilities", []) if isinstance(data, dict) else data

        if isinstance(vuln_list, list):
            for v in vuln_list:
                if not isinstance(v, dict):
                    continue
                cve_id = v.get("cveID") or v.get("cve_id")
                if not cve_id:
                    continue
                cve_id = cve_id.strip().upper()
                records[cve_id] = CISAKevRecord(
                    cve_id=cve_id,
                    is_in_kev=True,
                    vendor_project=v.get("vendorProject", ""),
                    product=v.get("product", ""),
                    vulnerability_name=v.get("vulnerabilityName", ""),
                    date_added=v.get("dateAdded"),
                    short_description=v.get("shortDescription", ""),
                    required_action=v.get("requiredAction", ""),
                    due_date=v.get("dueDate"),
                    known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse"),
                    notes=v.get("notes", ""),
                    raw_payload=v,
                )

        self._cache = records
        self._loaded = True

    def lookup(self, cve_id: str) -> CISAKevRecord:
        """Lookup a CVE in the KEV catalog.

        If present in KEV, returns record with is_in_kev=True.
        If absent from KEV, returns record with is_in_kev=False and Confidence.HIGH.
        """
        normalized_id = cve_id.strip().upper()
        if not self._loaded and self.cache_file and self.cache_file.exists():
            self.load()

        if normalized_id in self._cache:
            return self._cache[normalized_id]

        # Affirmative negative record: absent from catalog
        return CISAKevRecord(
            cve_id=normalized_id,
            is_in_kev=False,
            source=self.source,
            confidence=Confidence.HIGH,
        )
