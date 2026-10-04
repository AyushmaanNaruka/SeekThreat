"""CVE.org intelligence source client (canonical CVE Services 5.1 records).

Priority 1 source per services/enrichment/README.md:
"CVE.org: Canonical record, CNA-supplied CVSS/CWE — now primary"
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.sources.base import (
    BaseEnrichmentSource,
    BaseSourceRecord,
    parse_feed_date,
)


class CVEOrgRecord(BaseSourceRecord):
    """Canonical vulnerability metadata supplied by the CVE Numbering Authority (CNA)."""

    source: Source = Source.CVE_ORG
    confidence: Confidence = Confidence.HIGH
    title: str = ""
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    base_severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)

    def get_attributed_cvss(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed CVSS base score if present."""
        if self.cvss_score is None:
            return None
        return self.to_attributed(
            value=self.cvss_score,
            note=f"CNA CVSS {self.cvss_version or 'v3.1'} score ({self.base_severity or 'N/A'})",
        )

    def get_attributed_vector(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed CVSS vector string if present."""
        if not self.cvss_vector:
            return None
        return self.to_attributed(value=self.cvss_vector, note="CNA CVSS vector string")

    def get_attributed_cwe(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed list of CWE identifiers if present."""
        if not self.cwe_ids:
            return None
        return self.to_attributed(value=list(self.cwe_ids), note="CNA documented CWE taxonomy")

    def get_attributed_description(self) -> Attributed[EnrichmentValue] | None:
        """Return Attributed description text if present."""
        if not self.description:
            return None
        return self.to_attributed(value=self.description, note="CVE canonical description")


class CVEOrgSource(BaseEnrichmentSource[CVEOrgRecord]):
    """Local-mirror client for CVE.org v5.1 records."""

    source = Source.CVE_ORG
    priority = 1

    def load(self) -> None:
        """Load and index local CVE.org mirror JSON data."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        with open(self.cache_file, encoding="utf-8") as f:
            data = json.load(f)

        records: dict[str, CVEOrgRecord] = {}

        if isinstance(data, dict):
            # Either {"CVE-XXXX": {...}} or a single CVE_RECORD
            if "dataType" in data and data.get("dataType") == "CVE_RECORD":
                record = self._parse_cve_v5_record(data)
                if record:
                    records[record.cve_id] = record
            else:
                for cve_id, raw_record in data.items():
                    if isinstance(raw_record, dict):
                        record = self._parse_cve_v5_record(raw_record, fallback_id=cve_id)
                        if record:
                            records[record.cve_id] = record
        elif isinstance(data, list):
            for raw_record in data:
                if isinstance(raw_record, dict):
                    record = self._parse_cve_v5_record(raw_record)
                    if record:
                        records[record.cve_id] = record

        self._cache = records
        self._loaded = True

    def _parse_cve_v5_record(
        self, record_dict: dict[str, Any], fallback_id: str | None = None
    ) -> CVEOrgRecord | None:
        """Parse an official CVE Services 5.1 JSON structure."""
        metadata = record_dict.get("cveMetadata", {})
        cve_id = metadata.get("cveId") or fallback_id
        if not cve_id:
            return None
        cve_id = cve_id.strip().upper()

        containers = record_dict.get("containers", {})
        cna = containers.get("cna", {})

        title = cna.get("title", "")
        descriptions = cna.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en" and d.get("value"):
                desc_text = d["value"]
                break
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value", "")

        # Extract CVSS metrics (checking v4.0, v3.1, v3.0, v2.0)
        cvss_score: float | None = None
        cvss_vector: str | None = None
        cvss_version: str | None = None
        base_severity: str | None = None

        for metric in cna.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if key in metric and isinstance(metric[key], dict):
                    cvss_data = metric[key]
                    cvss_score = float(cvss_data["baseScore"]) if "baseScore" in cvss_data else None
                    cvss_vector = cvss_data.get("vectorString")
                    cvss_version = cvss_data.get(
                        "version", key.replace("cvssV", "").replace("_", ".")
                    )
                    base_severity = cvss_data.get("baseSeverity")
                    break
            if cvss_score is not None:
                break

        # Extract problemTypes (CWE IDs)
        cwe_ids: list[str] = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id and cwe_id not in cwe_ids:
                    cwe_ids.append(cwe_id.strip().upper())

        # cveMetadata.dateUpdated is the record's last modification; it is the best
        # available "as of" date for this data. Fall back to fusion time if absent.
        updated = parse_feed_date(metadata.get("dateUpdated"))

        return CVEOrgRecord(
            cve_id=cve_id,
            title=title,
            description=desc_text,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            base_severity=base_severity,
            cwe_ids=cwe_ids,
            raw_payload=record_dict,
            retrieved_at=updated or datetime.now(UTC),
        )
