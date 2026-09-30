"""Secondary intelligence source stubs, prioritized per services/enrichment/README.md.

Planned source roadmap:
1. CVE.org (MVP)
2. CISA Vulnrichment (Priority 2) - SSVC decision points, CWE, CVSS on higher-risk CVEs
3. CISA KEV (MVP)
4. FIRST EPSS v4 (MVP)
5. NVD 2.0 (Priority 5) - CVSS/CPE where still enriched
6. ENISA EUVD (Priority 6) - European fallback (beta, incomplete)
7. OSV.dev (Priority 7) - Package/ecosystem vulns NVD misses
8. GitHub Advisories (Priority 8) - Open-source package coverage
9. ExploitDB (Priority 9) - Public exploit existence
10. Metasploit (Priority 10) - Exploit maturity signal
"""

from __future__ import annotations

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.sources.base import BaseEnrichmentSource, BaseSourceRecord


class VulnrichmentRecord(BaseSourceRecord):
    """CISA Vulnrichment data (SSVC decision points, CWE, CVSS)."""

    source: Source = Source.VULNRICHMENT
    confidence: Confidence = Confidence.MEDIUM
    ssvc_decision: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = []


class VulnrichmentSource(BaseEnrichmentSource[VulnrichmentRecord]):
    """CISA Vulnrichment local-mirror client (Priority 2)."""

    source = Source.VULNRICHMENT
    priority = 2

    def load(self) -> None:
        self._loaded = True


class NVDSource(BaseEnrichmentSource[BaseSourceRecord]):
    """NVD 2.0 local-mirror client (Priority 5)."""

    source = Source.NVD
    priority = 5

    def load(self) -> None:
        self._loaded = True


class EUVDRecord(BaseSourceRecord):
    """ENISA European Vulnerability Database record."""

    source: Source = Source.EUVD
    confidence: Confidence = Confidence.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_ids: list[str] = []


class EUVDSource(BaseEnrichmentSource[EUVDRecord]):
    """ENISA European Vulnerability Database client (Priority 6)."""

    source = Source.EUVD
    priority = 6

    def load(self) -> None:
        self._loaded = True


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


class ExploitDBSource(BaseEnrichmentSource[BaseSourceRecord]):
    """ExploitDB exploit existence client (Priority 9)."""

    source = Source.EXPLOITDB
    priority = 9

    def load(self) -> None:
        self._loaded = True


class MetasploitSource(BaseEnrichmentSource[BaseSourceRecord]):
    """Metasploit exploit maturity client (Priority 10)."""

    source = Source.METASPLOIT
    priority = 10

    def load(self) -> None:
        self._loaded = True
