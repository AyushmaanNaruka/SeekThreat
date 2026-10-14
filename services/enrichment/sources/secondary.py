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

The CVSS/CWE/description fallback chain uses the priority order of the sources
that carry those fields: CVE.org (1) -> Vulnrichment (2) -> NVD (5) -> EUVD (6).

Each reader accepts the upstream record shape that ``FeedSyncer`` mirrors (see
``tests/fixtures/enrichment/upstream/README.md`` for captured examples) and the
flat snake_case shape used by the synthetic fixtures.
"""

from __future__ import annotations

import csv
import json
import logging
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.base import (
    BaseEnrichmentSource,
    BaseSourceRecord,
    parse_feed_date,
)

logger = logging.getLogger(__name__)

#: A whole reference/alias that IS a CVE ID (not a URL that merely mentions one).
CVE_ID_EXACT = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}", re.IGNORECASE | re.ASCII)

#: NVD's "no CWE" placeholders. They are not weaknesses and must not reach fusion.
NVD_CWE_PLACEHOLDERS = frozenset({"NVD-CWE-NOINFO", "NVD-CWE-OTHER"})
NVD_SOURCE_ID = "nvd@nist.gov"
#: Version preference for NVD metrics: v3.1 first (what ERS is calibrated on), then
#: v3.0, v4.0, v2. Within a version an NVD-authored Primary metric wins.
NVD_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")

#: EUVD timestamps, e.g. "Oct 21, 2025, 11:05:21 PM". They match the UTC
#: ``dateUpdated`` CVE.org publishes for the same record, so they are read as UTC.
_EUVD_DATE_FORMAT = "%b %d, %Y, %I:%M:%S %p"


def _safe_float(val: object) -> float | None:
    if val is None:
        return None
    try:
        return float(val)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None


def _load_mirror_json(path: Path, source: Source) -> Any | None:
    """Read a mirror file; log and return None when it is unreadable or corrupt."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning(
            "enrichment mirror %s for %s is unreadable; treating as not loaded: %s",
            path,
            source.value,
            exc,
        )
        return None


def _split_ids(value: object) -> list[str]:
    """EUVD lists aliases as one newline-separated string; accept lists too."""
    if isinstance(value, str):
        parts: Iterable[object] = value.splitlines()
    elif isinstance(value, list):
        parts = value
    else:
        return []
    return [str(p).strip() for p in parts if str(p).strip()]


def _parse_euvd_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), _EUVD_DATE_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return parse_feed_date(value)


class VulnrichmentRecord(BaseSourceRecord):
    """CISA Vulnrichment data (SSVC decision points, CWE, CVSS)."""

    source: Source = Source.VULNRICHMENT
    confidence: Confidence = Confidence.MEDIUM
    #: An SSVC *decision* (Track/Attend/Act) where one is supplied. CISA's ADP
    #: container publishes decision points, not a decision, so real records leave
    #: this None and populate ``ssvc_options`` instead.
    ssvc_decision: str | None = None
    #: SSVC decision points as published by CISA-ADP, e.g. {"Exploitation": "active"}.
    ssvc_options: dict[str, str] = Field(default_factory=dict)
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
        self._load_cached(self._index)

    def _index(self, path: Path) -> dict[str, Any]:
        data = _load_mirror_json(path, self.source)
        fallback = self.default_retrieved_at()
        records: dict[str, VulnrichmentRecord] = {}

        if isinstance(data, dict):
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, dict):
                    rec = self._parse_record(val, fallback, fallback_id=key)
                    if rec:
                        records[rec.cve_id] = rec
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._parse_record(item, fallback)
                    if rec:
                        records[rec.cve_id] = rec

        return records

    def _parse_record(
        self, raw: dict[str, Any], fallback: datetime, fallback_id: str | None = None
    ) -> VulnrichmentRecord | None:
        """Parse either a flat record or a CVE v5 record with CISA-ADP containers."""
        metadata = raw.get("cveMetadata", {})
        cve_id = metadata.get("cveId") or raw.get("cveId") or raw.get("cve_id") or fallback_id
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.strip().upper()

        containers = raw.get("containers", {})
        adps = containers.get("adp", []) if isinstance(containers, dict) else []

        ssvc_decision: str | None = raw.get("ssvc_decision") or raw.get("ssvc")
        ssvc_options: dict[str, str] = {}
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
                other = metric.get("other")
                if isinstance(other, dict) and other.get("type", "ssvc") == "ssvc":
                    content = other.get("content", {})
                    if isinstance(content, dict):
                        if not ssvc_decision and "decision" in content:
                            ssvc_decision = content["decision"]
                        for option in content.get("options", []) or []:
                            if isinstance(option, dict):
                                for point, value in option.items():
                                    ssvc_options.setdefault(str(point), str(value))
                    if not ssvc_decision and "decision" in other:
                        ssvc_decision = other["decision"]

            for pt in adp.get("problemTypes", []):
                if isinstance(pt, dict):
                    for desc in pt.get("descriptions", []):
                        if isinstance(desc, dict):
                            cid = desc.get("cweId")
                            if cid and cid.strip().upper() not in cwe_ids:
                                cwe_ids.append(cid.strip().upper())

        date_val = metadata.get("dateUpdated") or raw.get("updated_at") or raw.get("dateUpdated")
        retrieved_at = parse_feed_date(date_val) or fallback

        return VulnrichmentRecord(
            cve_id=cve_id,
            source=Source.VULNRICHMENT,
            confidence=Confidence.MEDIUM,
            ssvc_decision=str(ssvc_decision) if ssvc_decision else None,
            ssvc_options=ssvc_options,
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
    #: Who authored the selected metric: ``nvd@nist.gov`` for NVD's own Primary
    #: assessment, otherwise the CNA's identifier as NVD lists it.
    cvss_source: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


def _select_nvd_metric(
    metrics: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], bool] | None:
    """Pick the metric to use: (entry, cvssData, nvd_authored).

    NVD-authored Primary metrics win over CNA Secondary ones at any version; within
    each pass the version order is ``NVD_METRIC_KEYS``.
    """
    candidates: list[tuple[dict[str, Any], dict[str, Any], bool]] = []
    for mkey in NVD_METRIC_KEYS:
        mlist = metrics.get(mkey, [])
        if not isinstance(mlist, list):
            continue
        for entry in mlist:
            if not isinstance(entry, dict) or not isinstance(entry.get("cvssData"), dict):
                continue
            nvd_authored = entry.get("type") == "Primary" or entry.get("source") == NVD_SOURCE_ID
            candidates.append((entry, entry["cvssData"], nvd_authored))
    for candidate in candidates:
        if candidate[2]:
            return candidate
    return candidates[0] if candidates else None


class NVDSource(BaseEnrichmentSource[NVDRecord]):
    """NVD 2.0 local-mirror client (Priority 5; third in the CVSS/CWE chain)."""

    source = Source.NVD
    priority = 5

    def load(self) -> None:
        """Load and index local NVD mirror JSON data."""
        self._load_cached(self._index)

    def _index(self, path: Path) -> dict[str, Any]:
        data = _load_mirror_json(path, self.source)
        fallback = self.default_retrieved_at()
        records: dict[str, NVDRecord] = {}

        if isinstance(data, dict):
            # Standard NVD 2.0 API response: {"vulnerabilities": [{"cve": {...}}]}
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                for item in data["vulnerabilities"]:
                    if isinstance(item, dict):
                        rec = self._parse_nvd_item(item, fallback)
                        if rec:
                            records[rec.cve_id] = rec
            else:
                # FeedSyncer mirror: {cve_id: <NVD "cve" object>}; or flat synthetic.
                for key, val in data.items():
                    if key.startswith("_"):
                        continue
                    if isinstance(val, dict):
                        rec = self._parse_record(val, fallback, fallback_id=key)
                        if rec:
                            records[rec.cve_id] = rec
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._parse_record(item, fallback)
                    if rec:
                        records[rec.cve_id] = rec

        return records

    def _parse_nvd_item(self, item: dict[str, Any], fallback: datetime) -> NVDRecord | None:
        """Parse NVD 2.0 API 'vulnerabilities' item format."""
        cve_obj = item.get("cve", {}) if isinstance(item.get("cve"), dict) else item
        cve_id = cve_obj.get("id") or cve_obj.get("cveId")
        return self._parse_record(cve_obj, fallback, fallback_id=cve_id)

    def _parse_record(
        self, raw: dict[str, Any], fallback: datetime, fallback_id: str | None = None
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
        cvss_source: str | None = None
        confidence = Confidence.HIGH
        cwe_ids: list[str] = []
        description = raw.get("description", "")

        metrics = raw.get("metrics", {})
        if cvss_score is None and isinstance(metrics, dict):
            selected = _select_nvd_metric(metrics)
            if selected is not None:
                entry, cdata, nvd_authored = selected
                cvss_score = _safe_float(cdata.get("baseScore"))
                cvss_vector = cdata.get("vectorString") or cvss_vector
                cvss_version = cdata.get("version") or cvss_version
                base_severity = cdata.get("baseSeverity") or entry.get("baseSeverity")
                cvss_source = entry.get("source")
                if not nvd_authored:
                    # A CNA metric relayed by NVD: NVD has not assessed it itself.
                    confidence = Confidence.MEDIUM

        weaknesses = raw.get("weaknesses", [])
        if isinstance(weaknesses, list):
            for w in weaknesses:
                if isinstance(w, dict):
                    for d in w.get("description", []):
                        if isinstance(d, dict) and "value" in d:
                            val = str(d["value"]).strip().upper()
                            if val and val not in NVD_CWE_PLACEHOLDERS and val not in cwe_ids:
                                cwe_ids.append(val)

        if not cwe_ids and isinstance(raw.get("cwe_ids"), list):
            for c in raw["cwe_ids"]:
                val = str(c).strip().upper() if c else ""
                if val and val not in NVD_CWE_PLACEHOLDERS and val not in cwe_ids:
                    cwe_ids.append(val)

        descriptions = raw.get("descriptions", [])
        if not description and isinstance(descriptions, list):
            for d in descriptions:
                if isinstance(d, dict) and d.get("lang") == "en" and "value" in d:
                    description = d["value"]
                    break

        date_val = raw.get("lastModified") or raw.get("published") or raw.get("updated_at")
        retrieved_at = parse_feed_date(date_val) or fallback

        return NVDRecord(
            cve_id=cve_id,
            source=Source.NVD,
            confidence=confidence,
            cvss_score=cvss_score,
            cvss_vector=str(cvss_vector) if cvss_vector else None,
            cvss_version=str(cvss_version) if cvss_version else None,
            base_severity=str(base_severity) if base_severity else None,
            cvss_source=str(cvss_source) if cvss_source else None,
            cwe_ids=cwe_ids,
            description=str(description) if description else "",
            retrieved_at=retrieved_at,
            raw_payload=raw,
        )


class EUVDRecord(BaseSourceRecord):
    """ENISA European Vulnerability Database record."""

    source: Source = Source.EUVD
    confidence: Confidence = Confidence.MEDIUM
    euvd_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    base_severity: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    description: str = ""


class EUVDSource(BaseEnrichmentSource[EUVDRecord]):
    """ENISA European Vulnerability Database client (Priority 6; last in the chain)."""

    source = Source.EUVD
    priority = 6

    def load(self) -> None:
        """Load and index local EUVD mirror JSON data."""
        self._load_cached(self._index)

    def _index(self, path: Path) -> dict[str, Any]:
        data = _load_mirror_json(path, self.source)
        fallback = self.default_retrieved_at()
        records: dict[str, EUVDRecord] = {}

        if isinstance(data, dict):
            # FeedSyncer mirror: {cve_id: <EUVD record>}
            for key, val in data.items():
                if key.startswith("_"):
                    continue
                if isinstance(val, dict):
                    rec = self._parse_record(val, fallback, fallback_id=key)
                    if rec:
                        records[rec.cve_id] = rec
        elif isinstance(data, list):
            # Raw EUVD items: index each one under every CVE alias it carries.
            for item in data:
                if not isinstance(item, dict):
                    continue
                cves = [
                    a.upper() for a in _split_ids(item.get("aliases")) if CVE_ID_EXACT.fullmatch(a)
                ]
                if not cves and isinstance(item.get("cve_id"), str):
                    cves = [item["cve_id"]]
                for cve in cves:
                    rec = self._parse_record(item, fallback, fallback_id=cve)
                    if rec:
                        records[rec.cve_id] = rec

        return records

    def _parse_record(
        self, raw: dict[str, Any], fallback: datetime, fallback_id: str | None = None
    ) -> EUVDRecord | None:
        """Parse a real EUVD record (``id``, ``aliases``, ``baseScore*``) or a flat one."""
        aliases = _split_ids(raw.get("aliases"))
        cve_id = raw.get("cve_id") or fallback_id
        if not cve_id:
            cve_id = next((a for a in aliases if CVE_ID_EXACT.fullmatch(a)), None)
        if not cve_id or not isinstance(cve_id, str):
            return None
        cve_id = cve_id.strip().upper()

        vector = raw.get("baseScoreVector") or raw.get("cvss_vector")
        if "baseScore" in raw:
            cvss_score = _safe_float(raw.get("baseScore"))
            # EUVD reports 0.0 with no vector when nobody scored the record.
            if cvss_score == 0.0 and not vector:
                cvss_score = None
        else:
            cvss_score = _safe_float(raw.get("cvss_score"))
        cvss_version = raw.get("baseScoreVersion") or raw.get("cvss_version")
        base_severity = raw.get("base_severity")
        cwe_ids: list[str] = []
        if isinstance(raw.get("cwe_ids"), list):
            cwe_ids = [str(c).strip().upper() for c in raw["cwe_ids"] if c]
        description = raw.get("description") or ""

        euvd_id = raw.get("id") if isinstance(raw.get("id"), str) else None
        date_val = raw.get("dateUpdated") or raw.get("datePublished")
        retrieved_at = (
            _parse_euvd_date(date_val)
            or parse_feed_date(raw.get("updated_at") or raw.get("published_at"))
            or fallback
        )

        return EUVDRecord(
            cve_id=cve_id,
            source=Source.EUVD,
            confidence=Confidence.MEDIUM,
            euvd_id=euvd_id,
            aliases=aliases,
            cvss_score=cvss_score,
            cvss_vector=str(vector) if vector else None,
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


def exploitdb_cve_map(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    """Map CVE -> EDB-IDs from ``files_exploits.csv`` rows (``id`` and ``codes`` only).

    Hard Rule 4: only identifiers are read; exploit files are never fetched.
    """
    cve_map: dict[str, list[str]] = {}
    for row in rows:
        edb_id = str(row.get("id") or "").strip()
        if not edb_id:
            continue
        formatted_id = f"EDB-{edb_id}"
        for code in str(row.get("codes") or "").split(";"):
            code = code.strip()
            if CVE_ID_EXACT.fullmatch(code):
                ids = cve_map.setdefault(code.upper(), [])
                if formatted_id not in ids:
                    ids.append(formatted_id)
    return cve_map


def _metasploit_module_type(key: str, info: Mapping[str, Any]) -> str:
    declared = info.get("type")
    if isinstance(declared, str) and declared:
        return declared
    name = info.get("fullname") if isinstance(info.get("fullname"), str) else key
    return re.split(r"[/_]", str(name), maxsplit=1)[0]


def metasploit_cve_map(data: Mapping[str, Any]) -> dict[str, list[str]]:
    """Map CVE -> exploit module names from Rapid7 ``modules_metadata_base.json``.

    Only modules whose ``type`` is ``exploit`` count (auxiliary scanners, payloads
    and post modules are not exploits). The module is named by its ``fullname``
    (``exploit/multi/http/...``). Only whole ``CVE-YYYY-NNNN`` references count, so
    a URL reference that merely mentions a CVE is ignored. Hard Rule 4: names only.
    """
    cve_map: dict[str, list[str]] = {}
    for key, info in data.items():
        if key.startswith("_") or not isinstance(info, Mapping):
            continue
        if _metasploit_module_type(key, info) != "exploit":
            continue
        fullname = info.get("fullname")
        name = fullname if isinstance(fullname, str) and fullname else key
        refs = info.get("references", [])
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, str) and CVE_ID_EXACT.fullmatch(ref.strip()):
                mods = cve_map.setdefault(ref.strip().upper(), [])
                if name not in mods:
                    mods.append(name)
    return cve_map


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
        self._load_cached(self._index)

    def _index(self, path: Path) -> dict[str, Any]:
        if path.suffix.lower() == ".csv":
            return dict(self._parse_csv(path))
        return dict(self._parse_json(path))

    def _parse_json(self, path: Path) -> dict[str, ExploitDBRecord]:
        data = _load_mirror_json(path, self.source)
        fallback = self.default_retrieved_at()
        records: dict[str, ExploitDBRecord] = {}
        if isinstance(data, dict):
            for k, val in data.items():
                if k.startswith("_"):
                    continue
                if isinstance(val, dict):
                    cve_id = val.get("cve_id") or k
                    if not isinstance(cve_id, str):
                        continue
                    cve_id = cve_id.strip().upper()
                    raw_ids = val.get("exploit_ids", [])
                    exploit_ids = [str(i).strip() for i in raw_ids if i]
                    has_exploit = bool(val.get("has_public_exploit", bool(exploit_ids)))
                    retrieved = parse_feed_date(val.get("updated_at")) or fallback
                    records[cve_id] = ExploitDBRecord(
                        cve_id=cve_id,
                        exploit_ids=exploit_ids,
                        has_public_exploit=has_exploit,
                        retrieved_at=retrieved,
                    )
        return records

    def _parse_csv(self, path: Path) -> dict[str, ExploitDBRecord]:
        """Parse ExploitDB files_exploits.csv and map CVE codes to EDB-IDs."""
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as f:
                cve_map = exploitdb_cve_map(csv.DictReader(f))
        except (OSError, csv.Error) as exc:
            logger.warning("ExploitDB CSV mirror %s is unreadable: %s", path, exc)
            return {}

        fallback = self.default_retrieved_at()
        return {
            cve: ExploitDBRecord(
                cve_id=cve, exploit_ids=ids, has_public_exploit=True, retrieved_at=fallback
            )
            for cve, ids in cve_map.items()
        }


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
        self._load_cached(self._index)

    def _index(self, path: Path) -> dict[str, Any]:
        data = _load_mirror_json(path, self.source)
        fallback = self.default_retrieved_at()
        records: dict[str, MetasploitRecord] = {}

        if isinstance(data, dict):
            first_k = next((k for k in data if not k.startswith("_")), "")
            first_v = data.get(first_k)
            if isinstance(first_v, dict) and "references" in first_v:
                for cve, mods in metasploit_cve_map(data).items():
                    records[cve] = MetasploitRecord(
                        cve_id=cve,
                        module_names=mods,
                        has_metasploit_module=True,
                        retrieved_at=fallback,
                    )
            else:
                for k, v in data.items():
                    if k.startswith("_"):
                        continue
                    if isinstance(v, dict):
                        cve_id = v.get("cve_id") or k
                        if not isinstance(cve_id, str):
                            continue
                        cve_id = cve_id.strip().upper()
                        raw_mods = v.get("module_names", [])
                        module_names = [str(m).strip() for m in raw_mods if m]
                        has_mod = bool(v.get("has_metasploit_module", bool(module_names)))
                        retrieved = parse_feed_date(v.get("updated_at")) or fallback
                        records[cve_id] = MetasploitRecord(
                            cve_id=cve_id,
                            module_names=module_names,
                            has_metasploit_module=has_mod,
                            retrieved_at=retrieved,
                        )

        return records
