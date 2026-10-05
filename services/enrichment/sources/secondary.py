"""Secondary intelligence sources, prioritized per services/enrichment/README.md.

Roadmap priority:
1. CVE.org (MVP) - primary CNA records
2. CISA Vulnrichment (Priority 2) - SSVC decision points, CWE, CVSS on higher-risk CVEs
3. CISA KEV (MVP) - confirmed active exploitation in the wild
4. FIRST EPSS v4 (MVP) - 30-day exploitation probability
5. NVD 2.0 (Priority 5) - CVSS/CPE where still enriched
6. ENISA EUVD (Priority 6) - European fallback (beta, incomplete)
7. OSV.dev (Priority 7) - Package/ecosystem vulns NVD misses
8. GitHub Advisories (Priority 8) - Open-source package coverage
9. ExploitDB (Priority 9) - Public exploit existence (IDs only, Hard Rule 4)
10. Metasploit (Priority 10) - Exploit maturity signal (module names only, Hard Rule 4)
"""

from __future__ import annotations

import csv
import json
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.base import (
    BaseEnrichmentSource,
    BaseSourceRecord,
    parse_feed_date,
)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _safe_float(val: object) -> float | None:
    if val is None:
        return None
    try:
        return float(val)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


class VulnrichmentRecord(BaseSourceRecord):
    """CISA Vulnrichment data (SSVC decision points, CWE, CVSS)."""

    source: Source = Source.VULNRICHMENT
    confidence: Confidence = Confidence.MEDIUM
    ssvc_decision: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    base_severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


class VulnrichmentSource(BaseEnrichmentSource[VulnrichmentRecord]):
    """CISA Vulnrichment local-mirror client (Priority 2)."""

    source = Source.VULNRICHMENT
    priority = 2

    def load(self) -> None:
        """Load and index local CISA Vulnrichment mirror data."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        records: dict[str, VulnrichmentRecord] = {}

        if isinstance(data, dict):
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, dict):
                    rec = self._parse_record(val, fallback_id=key)
                    if rec:
                        records[rec.cve_id] = rec
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._parse_record(item)
                    if rec:
                        records[rec.cve_id] = rec

        self._cache = records
        self._loaded = True

    def _parse_record(
        self, raw: dict[str, Any], fallback_id: str | None = None
    ) -> VulnrichmentRecord | None:
        """Parse either a flat record or CVE v5 container with ADP enrichment."""
        metadata = raw.get("cveMetadata", {})
        cve_id = metadata.get("cveId") or raw.get("cveId") or raw.get("cve_id") or fallback_id
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.strip().upper()

        # Check for CVE v5 containers.adp structure
        containers = raw.get("containers", {})
        adps = containers.get("adp", []) if isinstance(containers, dict) else []

        ssvc_decision: str | None = raw.get("ssvc_decision") or raw.get("ssvc")
        cvss_score = _safe_float(raw.get("cvss_score"))
        cvss_vector = raw.get("cvss_vector")
        cvss_version = raw.get("cvss_version")
        base_severity = raw.get("base_severity")
        cwe_ids: list[str] = []
        if isinstance(raw.get("cwe_ids"), list):
            cwe_ids = [str(c).strip().upper() for c in raw["cwe_ids"] if c]
        description = raw.get("description", "")

        for adp in adps:
            if not isinstance(adp, dict):
                continue
            # Metrics
            for metric in adp.get("metrics", []):
                if not isinstance(metric, dict):
                    continue
                for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if key in metric and isinstance(metric[key], dict):
                        mdata = metric[key]
                        if cvss_score is None and "baseScore" in mdata:
                            cvss_score = _safe_float(mdata["baseScore"])
                        if not cvss_vector and "vectorString" in mdata:
                            cvss_vector = mdata["vectorString"]
                        if not cvss_version:
                            cvss_version = mdata.get(
                                "version", key.replace("cvssV", "").replace("_", ".")
                            )
                        if not base_severity:
                            base_severity = mdata.get("baseSeverity")
                # SSVC in other metric
                if not ssvc_decision and "other" in metric and isinstance(metric["other"], dict):
                    other = metric["other"]
                    content = other.get("content", {})
                    if isinstance(content, dict) and "decision" in content:
                        ssvc_decision = content["decision"]
                    elif "decision" in other:
                        ssvc_decision = other["decision"]

            # Problem types (CWEs)
            for pt in adp.get("problemTypes", []):
                if isinstance(pt, dict):
                    for desc in pt.get("descriptions", []):
                        if isinstance(desc, dict):
                            cid = desc.get("cweId")
                            if cid and cid.strip().upper() not in cwe_ids:
                                cwe_ids.append(cid.strip().upper())

        date_val = metadata.get("dateUpdated") or raw.get("updated_at") or raw.get("dateUpdated")
        retrieved_at = parse_feed_date(date_val) or datetime.now(UTC)

        return VulnrichmentRecord(
            cve_id=cve_id,
            source=Source.VULNRICHMENT,
            confidence=Confidence.MEDIUM,
            ssvc_decision=str(ssvc_decision) if ssvc_decision else None,
            cvss_score=cvss_score,
            cvss_vector=str(cvss_vector) if cvss_vector else None,
            cvss_version=str(cvss_version) if cvss_version else None,
            base_severity=str(base_severity) if base_severity else None,
            cwe_ids=cwe_ids,
            description=str(description) if description else "",
            retrieved_at=retrieved_at,
            raw_payload=raw,
        )


class NVDRecord(BaseSourceRecord):
    """NVD 2.0 vulnerability record."""

    source: Source = Source.NVD
    confidence: Confidence = Confidence.HIGH
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    base_severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


class NVDSource(BaseEnrichmentSource[NVDRecord]):
    """NVD 2.0 local-mirror client (Priority 5)."""

    source = Source.NVD
    priority = 5

    def load(self) -> None:
        """Load and index local NVD mirror JSON data."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        records: dict[str, NVDRecord] = {}

        if isinstance(data, dict):
            # Check if it has 'vulnerabilities' array (standard NVD 2.0 API mirror)
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                for item in data["vulnerabilities"]:
                    if isinstance(item, dict):
                        rec = self._parse_nvd_item(item)
                        if rec:
                            records[rec.cve_id] = rec
            else:
                for key, val in data.items():
                    if key.startswith("_"):
                        continue
                    if isinstance(val, dict):
                        rec = self._parse_record(val, fallback_id=key)
                        if rec:
                            records[rec.cve_id] = rec
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._parse_record(item)
                    if rec:
                        records[rec.cve_id] = rec

        self._cache = records
        self._loaded = True

    def _parse_nvd_item(self, item: dict[str, Any]) -> NVDRecord | None:
        """Parse NVD 2.0 API 'vulnerabilities' item format."""
        cve_obj = item.get("cve", {}) if isinstance(item.get("cve"), dict) else item
        cve_id = cve_obj.get("id") or cve_obj.get("cveId")
        return self._parse_record(cve_obj, fallback_id=cve_id)

    def _parse_record(
        self, raw: dict[str, Any], fallback_id: str | None = None
    ) -> NVDRecord | None:
        """Parse NVD record (flat or nested NVD 2.0 structure)."""
        cve_id = raw.get("id") or raw.get("cveId") or raw.get("cve_id") or fallback_id
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.strip().upper()

        cvss_score = _safe_float(raw.get("cvss_score"))
        cvss_vector = raw.get("cvss_vector")
        cvss_version = raw.get("cvss_version")
        base_severity = raw.get("base_severity")
        cwe_ids: list[str] = []
        description = raw.get("description", "")

        # Nested metrics block (NVD 2.0 API style)
        metrics = raw.get("metrics", {})
        if isinstance(metrics, dict):
            for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                mlist = metrics.get(mkey, [])
                if isinstance(mlist, list) and mlist:
                    primary = mlist[0]
                    if isinstance(primary, dict):
                        cdata = primary.get("cvssData", {})
                        if isinstance(cdata, dict):
                            if cvss_score is None and "baseScore" in cdata:
                                cvss_score = _safe_float(cdata["baseScore"])
                            if not cvss_vector and "vectorString" in cdata:
                                cvss_vector = cdata["vectorString"]
                            if not cvss_version and "version" in cdata:
                                cvss_version = cdata["version"]
                            if not base_severity:
                                base_severity = cdata.get("baseSeverity") or primary.get(
                                    "baseSeverity"
                                )
                            break

        # Nested weaknesses block (NVD 2.0 API style)
        weaknesses = raw.get("weaknesses", [])
        if isinstance(weaknesses, list):
            for w in weaknesses:
                if isinstance(w, dict):
                    for d in w.get("description", []):
                        if isinstance(d, dict) and "value" in d:
                            val = str(d["value"]).strip().upper()
                            if val and val != "NVD-CWE-OTHER" and val not in cwe_ids:
                                cwe_ids.append(val)

        # Flat CWEs if given
        if not cwe_ids and isinstance(raw.get("cwe_ids"), list):
            cwe_ids = [str(c).strip().upper() for c in raw["cwe_ids"] if c]

        # Nested descriptions block (NVD 2.0 API style)
        descriptions = raw.get("descriptions", [])
        if not description and isinstance(descriptions, list):
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en" and "value" in d:
                    description = d["value"]
                    break

        date_val = raw.get("lastModified") or raw.get("published") or raw.get("updated_at")
        retrieved_at = parse_feed_date(date_val) or datetime.now(UTC)

        return NVDRecord(
            cve_id=cve_id,
            source=Source.NVD,
            confidence=Confidence.HIGH,
            cvss_score=cvss_score,
            cvss_vector=str(cvss_vector) if cvss_vector else None,
            cvss_version=str(cvss_version) if cvss_version else None,
            base_severity=str(base_severity) if base_severity else None,
            cwe_ids=cwe_ids,
            description=str(description) if description else "",
            retrieved_at=retrieved_at,
            raw_payload=raw,
        )


class EUVDRecord(BaseSourceRecord):
    """ENISA European Vulnerability Database record."""

    source: Source = Source.EUVD
    confidence: Confidence = Confidence.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    base_severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


class EUVDSource(BaseEnrichmentSource[EUVDRecord]):
    """ENISA European Vulnerability Database client (Priority 6)."""

    source = Source.EUVD
    priority = 6

    def load(self) -> None:
        """Load and index local EUVD mirror JSON data."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        records: dict[str, EUVDRecord] = {}

        if isinstance(data, dict):
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, dict):
                    rec = self._parse_record(val, fallback_id=key)
                    if rec:
                        records[rec.cve_id] = rec
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._parse_record(item)
                    if rec:
                        records[rec.cve_id] = rec

        self._cache = records
        self._loaded = True

    def _parse_record(
        self, raw: dict[str, Any], fallback_id: str | None = None
    ) -> EUVDRecord | None:
        cve_id = raw.get("cve_id") or raw.get("cveId") or fallback_id
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.strip().upper()

        cvss_score = _safe_float(raw.get("cvss_score") or raw.get("cvssBaseScore"))
        cvss_vector = raw.get("cvss_vector") or raw.get("cvssVector")
        cvss_version = raw.get("cvss_version") or raw.get("cvssVersion")
        base_severity = raw.get("base_severity") or raw.get("severity")
        cwe_ids: list[str] = []
        if isinstance(raw.get("cwe_ids"), list):
            cwe_ids = [str(c).strip().upper() for c in raw["cwe_ids"] if c]
        description = raw.get("description") or raw.get("summary") or ""

        date_val = raw.get("updated_at") or raw.get("dateUpdated") or raw.get("published_at")
        retrieved_at = parse_feed_date(date_val) or datetime.now(UTC)

        return EUVDRecord(
            cve_id=cve_id,
            source=Source.EUVD,
            confidence=Confidence.MEDIUM,
            cvss_score=cvss_score,
            cvss_vector=str(cvss_vector) if cvss_vector else None,
            cvss_version=str(cvss_version) if cvss_version else None,
            base_severity=str(base_severity) if base_severity else None,
            cwe_ids=cwe_ids,
            description=str(description) if description else "",
            retrieved_at=retrieved_at,
            raw_payload=raw,
        )


class OSVSource(BaseEnrichmentSource[BaseSourceRecord]):
    """OSV.dev package/ecosystem vulnerability client (Priority 7)."""

    source = Source.OSV
    priority = 7

    def load(self) -> None:
        self._loaded = True


class GHSASource(BaseEnrichmentSource[BaseSourceRecord]):
    """GitHub Security Advisories client (Priority 8)."""

    source = Source.GHSA
    priority = 8

    def load(self) -> None:
        self._loaded = True


class ExploitDBRecord(BaseSourceRecord):
    """ExploitDB public exploit metadata (IDs only, never exploit code).

    Hard Rule 4: Report and reference exploit metadata only. Never weaponize,
    chain, or execute exploits.
    """

    source: Source = Source.EXPLOITDB
    confidence: Confidence = Confidence.HIGH
    exploit_ids: list[str] = Field(default_factory=list)
    has_public_exploit: bool = True


class ExploitDBSource(BaseEnrichmentSource[ExploitDBRecord]):
    """ExploitDB exploit existence client (Priority 9)."""

    source = Source.EXPLOITDB
    priority = 9

    def load(self) -> None:
        """Load ExploitDB mappings from mirror file (supports JSON or CSV)."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        suffix = self.cache_file.suffix.lower()
        if suffix == ".csv":
            self._load_csv()
        else:
            self._load_json()

    def _load_json(self) -> None:
        try:
            with open(self.cache_file, encoding="utf-8") as f:  # type: ignore[arg-type]
                data = json.load(f)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        records: dict[str, ExploitDBRecord] = {}
        if isinstance(data, dict):
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, dict):
                    cve_id = val.get("cve_id") or key
                    if not isinstance(cve_id, str):
                        continue
                    cve_id = cve_id.strip().upper()
                    raw_ids = val.get("exploit_ids", [])
                    exploit_ids = [str(i).strip() for i in raw_ids if i]
                    has_exploit = bool(val.get("has_public_exploit", bool(exploit_ids)))
                    retrieved = parse_feed_date(val.get("updated_at")) or datetime.now(UTC)
                    records[cve_id] = ExploitDBRecord(
                        cve_id=cve_id,
                        exploit_ids=exploit_ids,
                        has_public_exploit=has_exploit,
                        retrieved_at=retrieved,
                    )
        self._cache = records
        self._loaded = True

    def _load_csv(self) -> None:
        """Parse ExploitDB files_exploits.csv and map CVE codes to EDB-IDs."""
        records: dict[str, list[str]] = {}
        try:
            with open(self.cache_file, encoding="utf-8", errors="replace") as f:  # type: ignore[arg-type]
                reader = csv.DictReader(f)
                for row in reader:
                    edb_id = row.get("id", "").strip()
                    if not edb_id:
                        continue
                    formatted_id = f"EDB-{edb_id}"
                    codes = row.get("codes", "")
                    for match in CVE_PATTERN.finditer(codes):
                        cve = match.group(0).upper()
                        if cve not in records:
                            records[cve] = []
                        if formatted_id not in records[cve]:
                            records[cve].append(formatted_id)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        self._cache = {
            cve: ExploitDBRecord(
                cve_id=cve,
                exploit_ids=ids,
                has_public_exploit=True,
            )
            for cve, ids in records.items()
        }
        self._loaded = True


class MetasploitRecord(BaseSourceRecord):
    """Metasploit exploit module metadata (module names only, never exploit code).

    Hard Rule 4: Metasploit module names are maturity signals. Never include
    Ruby module source code or execution harnesses.
    """

    source: Source = Source.METASPLOIT
    confidence: Confidence = Confidence.HIGH
    module_names: list[str] = Field(default_factory=list)
    has_metasploit_module: bool = True


class MetasploitSource(BaseEnrichmentSource[MetasploitRecord]):
    """Metasploit exploit maturity client (Priority 10)."""

    source = Source.METASPLOIT
    priority = 10

    def load(self) -> None:
        """Load Metasploit module mappings from mirror JSON."""
        if not self.cache_file or not self.cache_file.exists():
            self._cache.clear()
            self._loaded = True
            return

        try:
            with open(self.cache_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._cache.clear()
            self._loaded = True
            return

        records: dict[str, MetasploitRecord] = {}

        if isinstance(data, dict):
            # Check if this is Rapid7's modules_metadata_base.json format
            # { "exploit/multi/...": { "references": ["CVE-2021-44228", ...], ... } }
            first_key = next((k for k in data if not k.startswith("_")), "")
            first_val = data.get(first_key)
            if isinstance(first_val, dict) and "references" in first_val:
                cve_map: dict[str, list[str]] = {}
                for mod_name, mod_info in data.items():
                    if mod_name.startswith("_") or not isinstance(mod_info, dict):
                        continue
                    refs = mod_info.get("references", [])
                    if isinstance(refs, list):
                        for ref in refs:
                            if isinstance(ref, str):
                                for match in CVE_PATTERN.finditer(ref):
                                    cve = match.group(0).upper()
                                    if cve not in cve_map:
                                        cve_map[cve] = []
                                    if mod_name not in cve_map[cve]:
                                        cve_map[cve].append(mod_name)
                for cve, mods in cve_map.items():
                    records[cve] = MetasploitRecord(
                        cve_id=cve,
                        module_names=mods,
                        has_metasploit_module=True,
                    )
            else:
                # Pre-keyed {cve_id: {"module_names": [...], ...}} format
                for key, val in data.items():
                    if key.startswith("_"):
                        continue
                    if isinstance(val, dict):
                        cve_id = val.get("cve_id") or key
                        if not isinstance(cve_id, str):
                            continue
                        cve_id = cve_id.strip().upper()
                        raw_mods = val.get("module_names", [])
                        module_names = [str(m).strip() for m in raw_mods if m]
                        has_mod = bool(val.get("has_metasploit_module", bool(module_names)))
                        retrieved = parse_feed_date(val.get("updated_at")) or datetime.now(UTC)
                        records[cve_id] = MetasploitRecord(
                            cve_id=cve_id,
                            module_names=module_names,
                            has_metasploit_module=has_mod,
                            retrieved_at=retrieved,
                        )

        self._cache = records
        self._loaded = True
