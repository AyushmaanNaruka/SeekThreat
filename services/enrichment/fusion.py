"""Multi-source intelligence fusion engine and fallback chain.

Load-bearing rules from services/enrichment/README.md:
1. Every field gets a Provenance. No unattributed data.
   Every field is wrapped in Attributed[EnrichmentValue] — an unattributed value
   must be unrepresentable, not just discouraged.
2. Fallback chain: CVE.org -> Vulnrichment -> EUVD -> derived. Label derived values.
   The chain runs PER FIELD (CVSS, CWE, description independently), so each field's
   provenance names the source it actually came from.
5. Mirror sources locally. Don't hit APIs on the request path.

An unloaded or empty mirror is never turned into a confident negative: missing KEV
data yields ``in_kev`` = None attributed DERIVED/LOW ("KEV status unknown").
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from services.enrichment.sources.base import BaseSourceRecord
from services.enrichment.sources.cisa_kev import CISAKevRecord, CISAKevSource
from services.enrichment.sources.cve_org import CVEOrgSource
from services.enrichment.sources.epss import FirstEPSSSource
from services.enrichment.sources.secondary import (
    EUVDSource,
    ExploitDBRecord,
    ExploitDBSource,
    MetasploitRecord,
    MetasploitSource,
    NVDSource,
    VulnrichmentSource,
)
from services.enrichment.sources.sync import mirror_path

# Derived placeholders used when no source has data. They are NOT measurements:
# they are attributed Source.DERIVED / Confidence.LOW and ERS explains them as
# placeholders (services/enrichment/ers.py). Values unchanged from the original
# implementation; they have no documented rationale yet.
PLACEHOLDER_CVSS: float = 5.0
PLACEHOLDER_EPSS: float = 0.001
PLACEHOLDER_EPSS_PERCENTILE: float = 0.05
PLACEHOLDER_CVSS_NON_CVE: float = 4.0
PLACEHOLDER_EPSS_NON_CVE: float = 0.0001
PLACEHOLDER_EPSS_PERCENTILE_NON_CVE: float = 0.01

KEV_UNKNOWN_NOTE = "KEV mirror not loaded; KEV status unknown"

_CHAIN_ORDER = (Source.CVE_ORG, Source.VULNRICHMENT, Source.NVD, Source.EUVD)
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _record_cvss(record: BaseSourceRecord) -> float | None:
    value = getattr(record, "cvss_score", None)
    return float(value) if value is not None else None


def _record_cwes(record: BaseSourceRecord) -> list[str]:
    return list(getattr(record, "cwe_ids", None) or [])


def _record_description(record: BaseSourceRecord) -> str | None:
    description = getattr(record, "description", "") or getattr(record, "title", "")
    return description or None


def _chain_rank(source: Source) -> int:
    return _CHAIN_ORDER.index(source) if source in _CHAIN_ORDER else len(_CHAIN_ORDER)


class FusionEngine:
    """Fuses multi-source intelligence for findings, executing fallback chains with provenance."""

    def __init__(
        self,
        cve_org: CVEOrgSource | None = None,
        cisa_kev: CISAKevSource | None = None,
        first_epss: FirstEPSSSource | None = None,
        vulnrichment: VulnrichmentSource | None = None,
        nvd: NVDSource | None = None,
        euvd: EUVDSource | None = None,
        exploitdb: ExploitDBSource | None = None,
        metasploit: MetasploitSource | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        """Build the engine from explicit sources and/or a local mirror directory.

        Args:
            cve_org, cisa_kev, first_epss, vulnrichment, euvd, exploitdb, metasploit:
                Explicit source instances. An explicit source always wins over ``cache_dir``.
            cache_dir: Directory of local mirror files, laid out exactly as
                ``SourceSynchronizer`` writes it (``sources.sync.MIRROR_FILENAMES``):

                - ``cve_org.json``      -> CVEOrgSource
                - ``cisa_kev.json``     -> CISAKevSource
                - ``epss_v4.json``      -> FirstEPSSSource
                - ``vulnrichment.json`` -> VulnrichmentSource
                - ``euvd.json``         -> EUVDSource
                - ``exploitdb.json``    -> ExploitDBSource
                - ``metasploit.json``   -> MetasploitSource

                A missing or empty file leaves that source unloaded. When
                ``cache_dir`` is None, any source not passed explicitly is created
                unloaded, and secondary sources are left out of the chain.
        """

        def _path(source: Source) -> Path | None:
            return mirror_path(cache_dir, source) if cache_dir is not None else None

        self.cve_org = cve_org or CVEOrgSource(cache_file=_path(Source.CVE_ORG))
        self.cisa_kev = cisa_kev or CISAKevSource(cache_file=_path(Source.KEV))
        self.first_epss = first_epss or FirstEPSSSource(cache_file=_path(Source.EPSS))
        self.vulnrichment = vulnrichment or (
            VulnrichmentSource(cache_file=_path(Source.VULNRICHMENT))
            if cache_dir is not None
            else None
        )
        self.nvd = nvd or (
            NVDSource(cache_file=_path(Source.NVD)) if cache_dir is not None else None
        )
        self.euvd = euvd or (
            EUVDSource(cache_file=_path(Source.EUVD)) if cache_dir is not None else None
        )
        self.exploitdb = exploitdb or (
            ExploitDBSource(cache_file=_path(Source.EXPLOITDB))
            if cache_dir is not None
            else None
        )
        self.metasploit = metasploit or (
            MetasploitSource(cache_file=_path(Source.METASPLOIT))
            if cache_dir is not None
            else None
        )

    def fuse(self, finding: Finding) -> dict[str, Attributed[EnrichmentValue]]:
        """Fuse intelligence across sources into an attributed field dictionary."""
        now = datetime.now(UTC)

        if not finding.cve_ids:
            return self._fuse_non_cve_finding(finding, now)

        cve_ids = [c.strip().upper() for c in finding.cve_ids]
        fields: dict[str, Attributed[EnrichmentValue]] = {}

        # 1. Per-field fallback chain (CVE.org -> Vulnrichment -> EUVD -> derived).
        best_cvss: tuple[float, str, BaseSourceRecord] | None = None
        cwe_values: list[str] = []
        cwe_contributors: list[tuple[str, BaseSourceRecord]] = []
        summary: tuple[str, str, BaseSourceRecord] | None = None

        for cve_id in cve_ids:
            chain = self._chain_records(cve_id)

            for rec in chain:
                score = _record_cvss(rec)
                if score is not None:
                    if best_cvss is None or score > best_cvss[0]:
                        best_cvss = (score, cve_id, rec)
                    break

            for rec in chain:
                cwes = _record_cwes(rec)
                if cwes:
                    cwe_contributors.append((cve_id, rec))
                    cwe_values.extend(c for c in cwes if c not in cwe_values)
                    break

            if summary is None:
                for rec in chain:
                    text = _record_description(rec)
                    if text:
                        summary = (text, cve_id, rec)
                        break

        # CVSS
        if best_cvss is not None:
            score, cvss_cve, rec = best_cvss
            fields["cvss_score"] = Attributed[EnrichmentValue](
                value=score,
                provenance=Provenance(
                    source=rec.source,
                    confidence=rec.confidence,
                    retrieved_at=rec.retrieved_at,
                    note=f"{self._cvss_note(rec)} (selected from {cvss_cve})",
                ),
            )
            vector = getattr(rec, "cvss_vector", None)
            if vector:
                fields["cvss_vector"] = Attributed[EnrichmentValue](
                    value=vector,
                    provenance=Provenance(
                        source=rec.source,
                        confidence=rec.confidence,
                        retrieved_at=rec.retrieved_at,
                        note=f"Vector for {cvss_cve} from {rec.source.value}",
                    ),
                )
        else:
            fields["cvss_score"] = Attributed[EnrichmentValue](
                value=PLACEHOLDER_CVSS,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note=(
                        "Derived placeholder CVSS; no CVSS in CVE.org, Vulnrichment or "
                        "EUVD mirrors. Not a measurement."
                    ),
                ),
            )

        # CWE
        if cwe_contributors:
            fields["cwe_ids"] = self._attributed_cwes(cwe_values, cwe_contributors)
        else:
            fields["cwe_ids"] = Attributed[EnrichmentValue](
                value=["CWE-Other"],
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived fallback CWE classification; no source supplied a CWE",
                ),
            )

        # 2. CISA KEV
        fields.update(self._kev_fields(cve_ids, now))

        # 3. FIRST EPSS v4 (max probability selection)
        best_epss: tuple[float, float, str, BaseSourceRecord] | None = None
        for cve_id in cve_ids:
            rec_epss = self.first_epss.lookup(cve_id)
            if rec_epss is not None and (best_epss is None or rec_epss.epss > best_epss[0]):
                best_epss = (rec_epss.epss, rec_epss.percentile, cve_id, rec_epss)

        if best_epss is not None:
            epss_score, epss_percentile, epss_cve, epss_rec = best_epss
            fields["epss_score"] = Attributed[EnrichmentValue](
                value=epss_score,
                provenance=Provenance(
                    source=Source.EPSS,
                    confidence=Confidence.HIGH,
                    retrieved_at=epss_rec.retrieved_at,
                    note=f"FIRST EPSS v4 probability score for {epss_cve}",
                ),
            )
            fields["epss_percentile"] = Attributed[EnrichmentValue](
                value=epss_percentile,
                provenance=Provenance(
                    source=Source.EPSS,
                    confidence=Confidence.HIGH,
                    retrieved_at=epss_rec.retrieved_at,
                    note=f"FIRST EPSS v4 percentile ranking for {epss_cve}",
                ),
            )
        else:
            fields["epss_score"] = Attributed[EnrichmentValue](
                value=PLACEHOLDER_EPSS,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived placeholder EPSS; no EPSS score in mirror. Not a measurement.",
                ),
            )
            fields["epss_percentile"] = Attributed[EnrichmentValue](
                value=PLACEHOLDER_EPSS_PERCENTILE,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived placeholder EPSS percentile. Not a measurement.",
                ),
            )

        # Summary
        if summary is not None:
            text, summary_cve, desc_rec = summary
            fields["summary"] = Attributed[EnrichmentValue](
                value=text,
                provenance=Provenance(
                    source=desc_rec.source,
                    confidence=desc_rec.confidence,
                    retrieved_at=desc_rec.retrieved_at,
                    note=f"Vulnerability description for {summary_cve} "
                    f"from {desc_rec.source.value}",
                ),
            )

        # 4. Exploit availability signals (ExploitDB & Metasploit)
        fields.update(self._exploit_fields(cve_ids, now))

        return fields

    def _chain_records(self, cve_id: str) -> list[BaseSourceRecord]:
        """Records for a CVE in fallback-chain order: CVE.org -> Vulnrichment -> NVD -> EUVD."""
        records: list[BaseSourceRecord] = []
        cve_record = self.cve_org.lookup(cve_id)
        if cve_record is not None:
            records.append(cve_record)
        if self.vulnrichment is not None:
            vuln_record = self.vulnrichment.lookup(cve_id)
            if vuln_record is not None:
                records.append(vuln_record)
        if self.nvd is not None:
            nvd_record = self.nvd.lookup(cve_id)
            if nvd_record is not None:
                records.append(nvd_record)
        if self.euvd is not None:
            euvd_record = self.euvd.lookup(cve_id)
            if euvd_record is not None:
                records.append(euvd_record)
        return records

    @staticmethod
    def _cvss_note(record: BaseSourceRecord) -> str:
        if record.source == Source.CVE_ORG:
            version = getattr(record, "cvss_version", None)
            return f"Canonical CVE.org CNA CVSS{f' v{version}' if version else ''}"
        if record.source == Source.VULNRICHMENT:
            return "CISA Vulnrichment fallback CVSS (CVE.org lacked metrics)"
        if record.source == Source.NVD:
            return "NVD 2.0 fallback CVSS"
        if record.source == Source.EUVD:
            return "ENISA EUVD fallback CVSS (CVE.org and Vulnrichment lacked metrics)"
        return f"CVSS from {record.source.value}"

    @staticmethod
    def _attributed_cwes(
        cwe_values: list[str], contributors: list[tuple[str, BaseSourceRecord]]
    ) -> Attributed[EnrichmentValue]:
        """Attribute a CWE union across a finding's CVEs.

        Provenance holds a single source, so when CVEs got their CWEs from different
        sources it names the most authoritative one in chain order, takes the LOWEST
        contributing confidence, and lists every per-CVE source in the note.
        """
        primary = min((rec.source for _, rec in contributors), key=_chain_rank)
        confidence = min(
            (rec.confidence for _, rec in contributors), key=lambda c: _CONFIDENCE_RANK[c]
        )
        per_cve = "; ".join(f"{cve} from {rec.source.value}" for cve, rec in contributors)
        return Attributed[EnrichmentValue](
            value=sorted(cwe_values),
            provenance=Provenance(
                source=primary,
                confidence=confidence,
                retrieved_at=min(rec.retrieved_at for _, rec in contributors),
                note=f"CWE taxonomy: {per_cve}",
            ),
        )

    def _kev_fields(
        self, cve_ids: list[str], now: datetime
    ) -> dict[str, Attributed[EnrichmentValue]]:
        """KEV fields. Unloaded/empty mirror -> unknown (None, DERIVED/LOW), never False."""
        if not self.cisa_kev.is_loaded:
            return {
                "in_kev": Attributed[EnrichmentValue](
                    value=None,
                    provenance=Provenance(
                        source=Source.DERIVED,
                        confidence=Confidence.LOW,
                        retrieved_at=now,
                        note=KEV_UNKNOWN_NOTE,
                    ),
                )
            }

        hit: tuple[str, CISAKevRecord] | None = None
        for cve_id in cve_ids:
            rec = self.cisa_kev.lookup(cve_id)
            if rec is not None and rec.is_in_kev:
                hit = (cve_id, rec)
                break

        if hit is None:
            return {
                "in_kev": Attributed[EnrichmentValue](
                    value=False,
                    provenance=Provenance(
                        source=Source.KEV,
                        confidence=Confidence.HIGH,
                        retrieved_at=self.cisa_kev.catalog_date or now,
                        note=f"None of {', '.join(cve_ids)} listed in the loaded CISA KEV catalog",
                    ),
                )
            }

        kev_cve, kev_record = hit
        out: dict[str, Attributed[EnrichmentValue]] = {
            "in_kev": Attributed[EnrichmentValue](
                value=True,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=kev_record.retrieved_at,
                    note=f"Confirmed active exploitation in the wild via {kev_cve}",
                ),
            )
        }
        if kev_record.date_added:
            out["kev_date_added"] = Attributed[EnrichmentValue](
                value=kev_record.date_added,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=kev_record.retrieved_at,
                    note=f"Date added to KEV catalog ({kev_cve})",
                ),
            )
        if kev_record.has_known_ransomware_use:
            out["ransomware_use"] = Attributed[EnrichmentValue](
                value=kev_record.known_ransomware_campaign_use,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=kev_record.retrieved_at,
                    note=f"Known ransomware campaign use per CISA ({kev_cve})",
                ),
            )
        return out

    def _exploit_fields(
        self, cve_ids: list[str], now: datetime
    ) -> dict[str, Attributed[EnrichmentValue]]:
        """Exploit availability signals (Hard Rule 4: IDs/names only, no code)."""
        out: dict[str, Attributed[EnrichmentValue]] = {}

        # 1. ExploitDB metadata
        if self.exploitdb is not None:
            if not self.exploitdb.is_loaded:
                out["has_public_exploit"] = Attributed[EnrichmentValue](
                    value=None,
                    provenance=Provenance(
                        source=Source.DERIVED,
                        confidence=Confidence.LOW,
                        retrieved_at=now,
                        note="ExploitDB mirror not loaded; public exploit status unknown",
                    ),
                )
            else:
                edb_ids: list[str] = []
                edb_records: list[ExploitDBRecord] = []
                for cve_id in cve_ids:
                    rec = self.exploitdb.lookup(cve_id)
                    if rec is not None and rec.has_public_exploit:
                        edb_records.append(rec)
                        for eid in rec.exploit_ids:
                            if eid not in edb_ids:
                                edb_ids.append(eid)
                if edb_ids:
                    retrieved = min(r.retrieved_at for r in edb_records)
                    out["has_public_exploit"] = Attributed[EnrichmentValue](
                        value=True,
                        provenance=Provenance(
                            source=Source.EXPLOITDB,
                            confidence=Confidence.HIGH,
                            retrieved_at=retrieved,
                            note="Confirmed public exploit available in ExploitDB",
                        ),
                    )
                    out["exploit_ids"] = Attributed[EnrichmentValue](
                        value=sorted(edb_ids),
                        provenance=Provenance(
                            source=Source.EXPLOITDB,
                            confidence=Confidence.HIGH,
                            retrieved_at=retrieved,
                            note=f"ExploitDB identifiers: {', '.join(sorted(edb_ids))}",
                        ),
                    )
                else:
                    out["has_public_exploit"] = Attributed[EnrichmentValue](
                        value=False,
                        provenance=Provenance(
                            source=Source.EXPLOITDB,
                            confidence=Confidence.HIGH,
                            retrieved_at=now,
                            note=f"None of {', '.join(cve_ids)} listed in loaded ExploitDB mirror",
                        ),
                    )

        # 2. Metasploit module metadata
        if self.metasploit is not None:
            if not self.metasploit.is_loaded:
                out["has_metasploit_module"] = Attributed[EnrichmentValue](
                    value=None,
                    provenance=Provenance(
                        source=Source.DERIVED,
                        confidence=Confidence.LOW,
                        retrieved_at=now,
                        note="Metasploit mirror not loaded; module status unknown",
                    ),
                )
            else:
                msf_modules: list[str] = []
                msf_records: list[MetasploitRecord] = []
                for cve_id in cve_ids:
                    rec_msf = self.metasploit.lookup(cve_id)
                    if rec_msf is not None and rec_msf.has_metasploit_module:
                        msf_records.append(rec_msf)
                        for mname in rec_msf.module_names:
                            if mname not in msf_modules:
                                msf_modules.append(mname)
                if msf_modules:
                    retrieved = min(r.retrieved_at for r in msf_records)
                    out["has_metasploit_module"] = Attributed[EnrichmentValue](
                        value=True,
                        provenance=Provenance(
                            source=Source.METASPLOIT,
                            confidence=Confidence.HIGH,
                            retrieved_at=retrieved,
                            note="Confirmed Metasploit module available",
                        ),
                    )
                    out["metasploit_modules"] = Attributed[EnrichmentValue](
                        value=sorted(msf_modules),
                        provenance=Provenance(
                            source=Source.METASPLOIT,
                            confidence=Confidence.HIGH,
                            retrieved_at=retrieved,
                            note=f"Metasploit modules: {', '.join(sorted(msf_modules))}",
                        ),
                    )
                else:
                    out["has_metasploit_module"] = Attributed[EnrichmentValue](
                        value=False,
                        provenance=Provenance(
                            source=Source.METASPLOIT,
                            confidence=Confidence.HIGH,
                            retrieved_at=now,
                            note=f"None of {', '.join(cve_ids)} listed in loaded Metasploit mirror",
                        ),
                    )

        return out

    def _fuse_non_cve_finding(
        self, finding: Finding, now: datetime
    ) -> dict[str, Attributed[EnrichmentValue]]:
        """Synthesize derived attributes for non-CVE heuristic findings."""
        out: dict[str, Attributed[EnrichmentValue]] = {
            "cvss_score": Attributed[EnrichmentValue](
                value=PLACEHOLDER_CVSS_NON_CVE,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived placeholder CVSS for non-CVE scanner heuristic. "
                    "Not a measurement.",
                ),
            ),
            "cwe_ids": Attributed[EnrichmentValue](
                value=["CWE-Other"],
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived categorization for scanner heuristic",
                ),
            ),
            "in_kev": Attributed[EnrichmentValue](
                value=False,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note="Finding has no CVE identifiers; CISA KEV lists only CVEs",
                ),
            ),
            "epss_score": Attributed[EnrichmentValue](
                value=PLACEHOLDER_EPSS_NON_CVE,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived placeholder EPSS; non-CVE finding has no EPSS score. "
                    "Not a measurement.",
                ),
            ),
            "epss_percentile": Attributed[EnrichmentValue](
                value=PLACEHOLDER_EPSS_PERCENTILE_NON_CVE,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived placeholder EPSS percentile for non-CVE finding. "
                    "Not a measurement.",
                ),
            ),
            "summary": Attributed[EnrichmentValue](
                value=finding.description or finding.title,
                provenance=Provenance(
                    source=Source.SCANNER,
                    confidence=Confidence.MEDIUM,
                    retrieved_at=now,
                    note="Summary derived from scanner observation",
                ),
            ),
        }
        if self.exploitdb is not None:
            out["has_public_exploit"] = Attributed[EnrichmentValue](
                value=False,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note="Finding has no CVE identifiers; ExploitDB tracks only CVEs",
                ),
            )
        if self.metasploit is not None:
            out["has_metasploit_module"] = Attributed[EnrichmentValue](
                value=False,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note="Finding has no CVE identifiers; Metasploit tracks only CVEs",
                ),
            )
        return out

    def fuse_to_enriched_finding(
        self, finding: Finding, compute_ers: bool = True
    ) -> EnrichedFinding:
        """Fuse intelligence and construct an EnrichedFinding domain model."""
        from services.enrichment.ers import calculate_ers

        fields = self.fuse(finding)
        ers = calculate_ers(fields) if compute_ers else None
        return EnrichedFinding(
            finding=finding,
            fields=fields,
            ers=ers,
        )


def fuse_finding(
    finding: Finding,
    cve_org: CVEOrgSource | None = None,
    cisa_kev: CISAKevSource | None = None,
    first_epss: FirstEPSSSource | None = None,
    vulnrichment: VulnrichmentSource | None = None,
    euvd: EUVDSource | None = None,
    exploitdb: ExploitDBSource | None = None,
    metasploit: MetasploitSource | None = None,
    cache_dir: Path | None = None,
) -> dict[str, Attributed[EnrichmentValue]]:
    """Convenience helper to fuse a single finding with given sources."""
    engine = FusionEngine(
        cve_org=cve_org,
        cisa_kev=cisa_kev,
        first_epss=first_epss,
        vulnrichment=vulnrichment,
        euvd=euvd,
        exploitdb=exploitdb,
        metasploit=metasploit,
        cache_dir=cache_dir,
    )
    return engine.fuse(finding)
