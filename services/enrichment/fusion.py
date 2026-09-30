"""Multi-source intelligence fusion engine and fallback chain.

Load-bearing rules from services/enrichment/README.md:
1. Every field gets a Provenance. No unattributed data.
   Every field is wrapped in Attributed[EnrichmentValue] — an unattributed value
   must be unrepresentable, not just discouraged.
2. Fallback chain: CVE.org -> Vulnrichment -> EUVD -> derived. Label derived values.
5. Mirror sources locally. Don't hit APIs on the request path.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from services.enrichment.sources.cisa_kev import CISAKevSource
from services.enrichment.sources.cve_org import CVEOrgSource
from services.enrichment.sources.epss import FirstEPSSSource
from services.enrichment.sources.secondary import EUVDSource, VulnrichmentSource


class FusionEngine:
    """Fuses multi-source intelligence for findings, executing fallback chains with provenance."""

    def __init__(
        self,
        cve_org: CVEOrgSource | None = None,
        cisa_kev: CISAKevSource | None = None,
        first_epss: FirstEPSSSource | None = None,
        vulnrichment: VulnrichmentSource | None = None,
        euvd: EUVDSource | None = None,
    ) -> None:
        self.cve_org = cve_org or CVEOrgSource()
        self.cisa_kev = cisa_kev or CISAKevSource()
        self.first_epss = first_epss or FirstEPSSSource()
        self.vulnrichment = vulnrichment
        self.euvd = euvd

    def fuse(self, finding: Finding) -> dict[str, Attributed[EnrichmentValue]]:
        """Fuse intelligence across sources into an attributed field dictionary."""
        now = datetime.now(UTC)
        fields: dict[str, Attributed[EnrichmentValue]] = {}

        if not finding.cve_ids:
            return self._fuse_non_cve_finding(finding, now)

        # 1. Fallback chain for CVSS and CWE per CVE, selecting maximum severity
        best_cvss_score: float | None = None
        best_cvss_vector: str | None = None
        best_cvss_source: Source = Source.DERIVED
        best_cvss_confidence: Confidence = Confidence.LOW
        best_cvss_note: str = ""
        best_cvss_cve: str | None = None

        all_cwes: list[str] = []
        cwe_source: Source = Source.DERIVED
        cwe_confidence: Confidence = Confidence.LOW
        cwe_source_cve: str | None = None

        cve_summaries: list[str] = []
        summary_source: Source = Source.DERIVED
        summary_confidence: Confidence = Confidence.LOW

        for cve_id in finding.cve_ids:
            norm_cve = cve_id.strip().upper()

            # Execute fallback chain: CVE.org -> Vulnrichment -> EUVD -> derived
            cvss_cand, vec_cand, cwe_cand, desc_cand, s_cand, conf_cand, note_cand = (
                self._resolve_cvss_and_cwe(norm_cve)
            )

            if cvss_cand is not None:
                if best_cvss_score is None or cvss_cand > best_cvss_score:
                    best_cvss_score = cvss_cand
                    best_cvss_vector = vec_cand
                    best_cvss_source = s_cand
                    best_cvss_confidence = conf_cand
                    best_cvss_cve = norm_cve
                    best_cvss_note = f"{note_cand} (selected from {norm_cve})"

            if cwe_cand:
                for cwe in cwe_cand:
                    if cwe not in all_cwes:
                        all_cwes.append(cwe)
                # Keep highest confidence source for CWE
                if cwe_source == Source.DERIVED or (
                    conf_cand == Confidence.HIGH and cwe_confidence != Confidence.HIGH
                ):
                    cwe_source = s_cand
                    cwe_confidence = conf_cand
                    cwe_source_cve = norm_cve

            if desc_cand and not cve_summaries:
                cve_summaries.append(desc_cand)
                summary_source = s_cand
                summary_confidence = conf_cand

        # Populate CVSS fields
        if best_cvss_score is not None:
            fields["cvss_score"] = Attributed[EnrichmentValue](
                value=best_cvss_score,
                provenance=Provenance(
                    source=best_cvss_source,
                    confidence=best_cvss_confidence,
                    retrieved_at=now,
                    note=best_cvss_note,
                ),
            )
            if best_cvss_vector:
                fields["cvss_vector"] = Attributed[EnrichmentValue](
                    value=best_cvss_vector,
                    provenance=Provenance(
                        source=best_cvss_source,
                        confidence=best_cvss_confidence,
                        retrieved_at=now,
                        note=f"Vector for {best_cvss_cve}",
                    ),
                )
        else:
            # Derived fallback CVSS
            fields["cvss_score"] = Attributed[EnrichmentValue](
                value=5.0,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived fallback CVSS; all upstream sources lacked metrics",
                ),
            )

        # Populate CWE fields
        if all_cwes:
            fields["cwe_ids"] = Attributed[EnrichmentValue](
                value=sorted(all_cwes),
                provenance=Provenance(
                    source=cwe_source,
                    confidence=cwe_confidence,
                    retrieved_at=now,
                    note=f"CWE taxonomy from {cwe_source.value} ({cwe_source_cve})",
                ),
            )
        else:
            fields["cwe_ids"] = Attributed[EnrichmentValue](
                value=["CWE-Other"],
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived fallback CWE classification",
                ),
            )

        # 2. CISA KEV Intelligence
        matching_kev_cve: str | None = None
        kev_record: Any = None
        for cve_id in finding.cve_ids:
            rec = self.cisa_kev.lookup(cve_id)
            if rec and rec.is_in_kev:
                matching_kev_cve = cve_id
                kev_record = rec
                break

        if matching_kev_cve and kev_record:
            fields["in_kev"] = Attributed[EnrichmentValue](
                value=True,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note=f"Confirmed active exploitation in the wild via {matching_kev_cve}",
                ),
            )
            if kev_record.date_added:
                fields["kev_date_added"] = Attributed[EnrichmentValue](
                    value=kev_record.date_added,
                    provenance=Provenance(
                        source=Source.KEV,
                        confidence=Confidence.HIGH,
                        retrieved_at=now,
                        note=f"Date added to KEV catalog ({matching_kev_cve})",
                    ),
                )
            if kev_record.known_ransomware_campaign_use:
                fields["ransomware_use"] = Attributed[EnrichmentValue](
                    value=kev_record.known_ransomware_campaign_use,
                    provenance=Provenance(
                        source=Source.KEV,
                        confidence=Confidence.HIGH,
                        retrieved_at=now,
                        note=f"Known ransomware campaign use per CISA ({matching_kev_cve})",
                    ),
                )
        else:
            fields["in_kev"] = Attributed[EnrichmentValue](
                value=False,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note="No associated CVEs listed in CISA KEV catalog",
                ),
            )

        # 3. FIRST EPSS v4 Intelligence (max probability selection)
        best_epss_score: float | None = None
        best_epss_percentile: float | None = None
        best_epss_cve: str | None = None

        for cve_id in finding.cve_ids:
            rec_epss = self.first_epss.lookup(cve_id)
            if rec_epss and rec_epss.epss is not None:
                if best_epss_score is None or rec_epss.epss > best_epss_score:
                    best_epss_score = rec_epss.epss
                    best_epss_percentile = rec_epss.percentile
                    best_epss_cve = cve_id

        if best_epss_score is not None and best_epss_percentile is not None:
            fields["epss_score"] = Attributed[EnrichmentValue](
                value=best_epss_score,
                provenance=Provenance(
                    source=Source.EPSS,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note=f"FIRST EPSS v4 probability score for {best_epss_cve}",
                ),
            )
            fields["epss_percentile"] = Attributed[EnrichmentValue](
                value=best_epss_percentile,
                provenance=Provenance(
                    source=Source.EPSS,
                    confidence=Confidence.HIGH,
                    retrieved_at=now,
                    note=f"FIRST EPSS v4 percentile ranking for {best_epss_cve}",
                ),
            )
        else:
            # Derived baseline floor when EPSS feed lacks score
            fields["epss_score"] = Attributed[EnrichmentValue](
                value=0.001,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="No EPSS score found; conservative baseline floor applied",
                ),
            )
            fields["epss_percentile"] = Attributed[EnrichmentValue](
                value=0.05,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived baseline percentile floor",
                ),
            )

        # Summary
        if cve_summaries:
            fields["summary"] = Attributed[EnrichmentValue](
                value=cve_summaries[0],
                provenance=Provenance(
                    source=summary_source,
                    confidence=summary_confidence,
                    retrieved_at=now,
                    note="Vulnerability summary from intelligence feed",
                ),
            )

        return fields

    def _resolve_cvss_and_cwe(
        self, cve_id: str
    ) -> tuple[
        float | None,
        str | None,
        list[str],
        str | None,
        Source,
        Confidence,
        str,
    ]:
        """Execute fallback chain: CVE.org -> Vulnrichment -> EUVD -> derived."""
        # 1. Primary: CVE.org
        cve_record = self.cve_org.lookup(cve_id)
        if cve_record and cve_record.cvss_score is not None:
            return (
                cve_record.cvss_score,
                cve_record.cvss_vector,
                list(cve_record.cwe_ids),
                cve_record.description or cve_record.title,
                Source.CVE_ORG,
                Confidence.HIGH,
                f"Canonical CVE.org CVSS {cve_record.cvss_version or 'v3.1'}",
            )

        # 2. Secondary fallback: CISA Vulnrichment
        if self.vulnrichment:
            vuln_record = self.vulnrichment.lookup(cve_id)
            if vuln_record and vuln_record.cvss_score is not None:
                return (
                    vuln_record.cvss_score,
                    vuln_record.cvss_vector,
                    list(vuln_record.cwe_ids),
                    None,
                    Source.VULNRICHMENT,
                    Confidence.MEDIUM,
                    "CISA Vulnrichment fallback CVSS",
                )

        # 3. Secondary fallback: ENISA EUVD
        if self.euvd:
            euvd_record = self.euvd.lookup(cve_id)
            if euvd_record and euvd_record.cvss_score is not None:
                return (
                    euvd_record.cvss_score,
                    euvd_record.cvss_vector,
                    list(euvd_record.cwe_ids),
                    None,
                    Source.EUVD,
                    Confidence.MEDIUM,
                    "ENISA EUVD fallback CVSS",
                )

        # 4. If CVE.org had description or CWE but no CVSS
        if cve_record and (cve_record.cwe_ids or cve_record.description):
            return (
                None,
                None,
                list(cve_record.cwe_ids),
                cve_record.description or cve_record.title,
                Source.CVE_ORG,
                Confidence.HIGH,
                "Canonical CVE.org record (metrics missing)",
            )

        # Fallback to derived
        return (
            None,
            None,
            [],
            None,
            Source.DERIVED,
            Confidence.LOW,
            "All sources lacked metrics",
        )

    def _fuse_non_cve_finding(
        self, finding: Finding, now: datetime
    ) -> dict[str, Attributed[EnrichmentValue]]:
        """Synthesize derived attributes for non-CVE heuristic findings."""
        return {
            "cvss_score": Attributed[EnrichmentValue](
                value=4.0,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Derived baseline score for non-CVE scanner heuristic",
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
                    note="Non-CVE finding is not tracked in CISA KEV catalog",
                ),
            ),
            "epss_score": Attributed[EnrichmentValue](
                value=0.0001,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Non-CVE finding has no EPSS probability",
                ),
            ),
            "epss_percentile": Attributed[EnrichmentValue](
                value=0.01,
                provenance=Provenance(
                    source=Source.DERIVED,
                    confidence=Confidence.LOW,
                    retrieved_at=now,
                    note="Non-CVE finding assigned floor percentile",
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
) -> dict[str, Attributed[EnrichmentValue]]:
    """Convenience helper to fuse a single finding with given sources."""
    engine = FusionEngine(
        cve_org=cve_org,
        cisa_kev=cisa_kev,
        first_epss=first_epss,
        vulnrichment=vulnrichment,
        euvd=euvd,
    )
    return engine.fuse(finding)
