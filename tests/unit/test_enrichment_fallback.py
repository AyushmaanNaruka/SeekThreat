"""Unit tests for multi-source intelligence fusion and fallback chain."""

from __future__ import annotations

from pathlib import Path

from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.sources import (
    CISAKevSource,
    CVEOrgSource,
    EUVDSource,
    ExploitDBSource,
    FirstEPSSSource,
    MetasploitSource,
    VulnrichmentSource,
)
from services.enrichment.sources.secondary import (
    EUVDRecord,
    VulnrichmentRecord,
)
from tests.fixtures.findings.baseline_findings import (
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_HEURISTIC_NO_CVE,
    FINDING_LOG4SHELL,
    FINDING_NON_KEV_MODERATE,
    FINDING_NVD_UNENRICHED_RECENT,
    FINDING_SPRING_GATEWAY_RCE,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


def get_test_engine(
    vulnrichment: VulnrichmentSource | None = None,
    euvd: EUVDSource | None = None,
) -> FusionEngine:
    """Helper to instantiate FusionEngine with sample fixtures."""
    return FusionEngine(
        cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
        cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
        first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
        vulnrichment=vulnrichment,
        euvd=euvd,
    )


class TestFallbackChain:
    """Tests the fallback chain: CVE.org -> Vulnrichment -> EUVD -> derived."""

    def test_cve_org_primary_selected_when_present(self) -> None:
        engine = get_test_engine()
        fields = engine.fuse(FINDING_LOG4SHELL)

        assert "cvss_score" in fields
        attr_cvss = fields["cvss_score"]
        assert isinstance(attr_cvss, Attributed)
        assert attr_cvss.value == 10.0
        assert attr_cvss.provenance.source == Source.CVE_ORG
        assert attr_cvss.provenance.confidence == Confidence.HIGH

    def test_fallback_to_vulnrichment_when_cve_org_lacks_cvss(self) -> None:
        cve_id = "CVE-2025-0001"
        test_finding = Finding(
            finding_id="find-vulnrichment-fallback-001",
            engagement_id="eng-001",
            asset_id="asset-001",
            scanner="nuclei",
            cve_ids=[cve_id],
            observation_ids=["obs-001"],
            detected_at=FINDING_LOG4SHELL.detected_at,
        )

        vuln_source = VulnrichmentSource()
        vuln_source._cache[cve_id] = VulnrichmentRecord(
            cve_id=cve_id,
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cwe_ids=["CWE-79"],
        )
        vuln_source._loaded = True

        engine = get_test_engine(vulnrichment=vuln_source)
        fields = engine.fuse(test_finding)

        assert fields["cvss_score"].value == 8.1
        assert fields["cvss_score"].provenance.source == Source.VULNRICHMENT
        assert fields["cvss_score"].provenance.confidence == Confidence.MEDIUM

    def test_fallback_to_euvd_when_cve_org_and_vulnrichment_lack_cvss(self) -> None:
        cve_id = "CVE-2025-0002"
        test_finding = Finding(
            finding_id="find-euvd-fallback-001",
            engagement_id="eng-001",
            asset_id="asset-001",
            scanner="nuclei",
            cve_ids=[cve_id],
            observation_ids=["obs-001"],
            detected_at=FINDING_LOG4SHELL.detected_at,
        )

        euvd_source = EUVDSource()
        euvd_source._cache[cve_id] = EUVDRecord(
            cve_id=cve_id,
            cvss_score=6.5,
            cwe_ids=["CWE-20"],
        )
        euvd_source._loaded = True

        engine = get_test_engine(euvd=euvd_source)
        fields = engine.fuse(test_finding)

        assert fields["cvss_score"].value == 6.5
        assert fields["cvss_score"].provenance.source == Source.EUVD
        assert fields["cvss_score"].provenance.confidence == Confidence.MEDIUM

    def test_fallback_to_derived_when_all_sources_lack_cvss(self) -> None:
        cve_id = "CVE-2025-9999"
        test_finding = Finding(
            finding_id="find-derived-fallback-001",
            engagement_id="eng-001",
            asset_id="asset-001",
            scanner="nuclei",
            cve_ids=[cve_id],
            observation_ids=["obs-001"],
            detected_at=FINDING_LOG4SHELL.detected_at,
        )

        engine = get_test_engine()
        fields = engine.fuse(test_finding)

        assert fields["cvss_score"].provenance.source == Source.DERIVED
        assert fields["cvss_score"].provenance.confidence == Confidence.LOW
        assert fields["cwe_ids"].provenance.source == Source.DERIVED


class TestFusionIntelligenceOutputs:
    """Test full multi-source fusion against baseline fixtures."""

    def test_log4shell_fusion(self) -> None:
        engine = get_test_engine()
        fields = engine.fuse(FINDING_LOG4SHELL)

        assert fields["cvss_score"].value == 10.0
        assert fields["in_kev"].value is True
        assert fields["in_kev"].provenance.source == Source.KEV
        assert fields["in_kev"].provenance.confidence == Confidence.HIGH
        assert fields["epss_score"].value > 0.95
        assert fields["epss_score"].provenance.source == Source.EPSS

    def test_multi_cve_aggregation_selects_max_severity(self) -> None:
        engine = get_test_engine()
        fields = engine.fuse(FINDING_SPRING_GATEWAY_RCE)

        # Both CVE-2022-22947 and CVE-2022-22965 are in the finding
        assert fields["cvss_score"].value == 9.8
        assert fields["in_kev"].value is True
        assert "CVE-2022-22947" in (fields["in_kev"].provenance.note or "")
        # EPSS max should be >= 0.94
        assert fields["epss_score"].value >= 0.94

    def test_non_kev_moderate_finding(self) -> None:
        engine = get_test_engine()
        fields = engine.fuse(FINDING_NON_KEV_MODERATE)

        assert fields["cvss_score"].value == 7.3
        assert fields["in_kev"].value is False
        assert fields["in_kev"].provenance.source == Source.KEV
        assert fields["in_kev"].provenance.confidence == Confidence.HIGH
        assert 0.1 <= fields["epss_score"].value <= 0.5

    def test_heuristic_non_cve_finding_fusion(self) -> None:
        engine = get_test_engine()
        fields = engine.fuse(FINDING_HEURISTIC_NO_CVE)

        assert fields["cvss_score"].provenance.source == Source.DERIVED
        assert fields["in_kev"].value is False
        assert fields["epss_score"].provenance.source == Source.DERIVED

    def test_every_field_wrapped_in_attributed(self) -> None:
        engine = get_test_engine()
        for finding in [
            FINDING_LOG4SHELL,
            FINDING_APACHE_PATH_TRAVERSAL,
            FINDING_SPRING_GATEWAY_RCE,
            FINDING_NVD_UNENRICHED_RECENT,
            FINDING_NON_KEV_MODERATE,
            FINDING_HEURISTIC_NO_CVE,
        ]:
            fields = engine.fuse(finding)
            assert len(fields) >= 4
            for field_name, attr in fields.items():
                assert isinstance(attr, Attributed), f"{field_name} is not Attributed"
                assert attr.provenance is not None
                assert attr.provenance.source is not None
                assert attr.provenance.confidence is not None
                assert attr.provenance.retrieved_at.tzinfo is not None

    def test_fuse_to_enriched_finding(self) -> None:
        engine = get_test_engine()
        enriched = engine.fuse_to_enriched_finding(FINDING_LOG4SHELL)
        assert isinstance(enriched, EnrichedFinding)
        assert enriched.finding == FINDING_LOG4SHELL
        assert enriched.fields["cvss_score"].value == 10.0
        assert enriched.ers is not None
        assert enriched.ers.value > 9.5

        enriched_no_ers = engine.fuse_to_enriched_finding(FINDING_LOG4SHELL, compute_ers=False)
        assert enriched_no_ers.ers is None


def _bare_finding(cve_id: str) -> Finding:
    return Finding(
        finding_id=f"find-{cve_id.lower()}",
        engagement_id="eng-001",
        asset_id="asset-001",
        scanner="nuclei",
        cve_ids=[cve_id],
        observation_ids=["obs-001"],
        detected_at=FINDING_LOG4SHELL.detected_at,
    )


class TestPerFieldFallbackChain:
    """Each field resolves independently: CVE.org -> Vulnrichment -> EUVD -> derived."""

    def test_cve_org_cwe_and_description_kept_when_cvss_from_vulnrichment(self) -> None:
        from services.enrichment.sources.cve_org import CVEOrgRecord

        cve_id = "CVE-2025-1000"
        cve_org = CVEOrgSource()
        cve_org._cache[cve_id] = CVEOrgRecord(
            cve_id=cve_id, description="CNA description", cwe_ids=["CWE-89"]
        )
        cve_org._loaded = True
        vuln = VulnrichmentSource()
        vuln._cache[cve_id] = VulnrichmentRecord(cve_id=cve_id, cvss_score=8.8, cwe_ids=["CWE-20"])
        vuln._loaded = True

        fields = FusionEngine(cve_org=cve_org, vulnrichment=vuln).fuse(_bare_finding(cve_id))

        assert fields["cvss_score"].value == 8.8
        assert fields["cvss_score"].provenance.source == Source.VULNRICHMENT
        assert fields["cwe_ids"].value == ["CWE-89"]
        assert fields["cwe_ids"].provenance.source == Source.CVE_ORG
        assert fields["summary"].value == "CNA description"
        assert fields["summary"].provenance.source == Source.CVE_ORG

    def test_vulnrichment_asked_for_cwe_when_cve_org_lacks_it(self) -> None:
        from services.enrichment.sources.cve_org import CVEOrgRecord

        cve_id = "CVE-2025-1001"
        cve_org = CVEOrgSource()
        cve_org._cache[cve_id] = CVEOrgRecord(cve_id=cve_id, cvss_score=7.0)
        cve_org._loaded = True
        vuln = VulnrichmentSource()
        vuln._cache[cve_id] = VulnrichmentRecord(cve_id=cve_id, cwe_ids=["CWE-79"])
        vuln._loaded = True

        fields = FusionEngine(cve_org=cve_org, vulnrichment=vuln).fuse(_bare_finding(cve_id))

        assert fields["cvss_score"].provenance.source == Source.CVE_ORG
        assert fields["cwe_ids"].value == ["CWE-79"]
        assert fields["cwe_ids"].provenance.source == Source.VULNRICHMENT
        assert fields["cwe_ids"].provenance.confidence == Confidence.MEDIUM


class TestRansomwareUse:
    def test_ransomware_emitted_only_when_known(self) -> None:
        engine = get_test_engine()
        assert engine.fuse(FINDING_LOG4SHELL)["ransomware_use"].value == "Known"
        # CVE-2022-22947 is in the KEV fixture with knownRansomwareCampaignUse == "Unknown"
        assert "ransomware_use" not in engine.fuse(FINDING_SPRING_GATEWAY_RCE)


class TestRecordDatesAsRetrievedAt:
    def test_epss_retrieved_at_is_feed_date(self) -> None:
        fields = get_test_engine().fuse(FINDING_LOG4SHELL)
        retrieved = fields["epss_score"].provenance.retrieved_at
        assert retrieved.date().isoformat() == "2026-09-20"
        assert retrieved.tzinfo is not None

    def test_kev_retrieved_at_is_catalog_release_date(self) -> None:
        engine = get_test_engine()
        for finding in (FINDING_LOG4SHELL, FINDING_NON_KEV_MODERATE):
            retrieved = engine.fuse(finding)["in_kev"].provenance.retrieved_at
            assert retrieved.date().isoformat() == "2024-09-20"

    def test_cve_org_retrieved_at_is_date_updated(self, tmp_path: Path) -> None:
        import json

        record = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2025-2000", "dateUpdated": "2025-03-04T05:06:07Z"},
            "containers": {
                "cna": {"metrics": [{"cvssV3_1": {"baseScore": 6.1}}], "descriptions": []}
            },
        }
        path = tmp_path / "cve_org.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        fields = FusionEngine(cve_org=CVEOrgSource(cache_file=path)).fuse(
            _bare_finding("CVE-2025-2000")
        )
        assert (
            fields["cvss_score"]
            .provenance.retrieved_at.isoformat()
            .startswith("2025-03-04T05:06:07")
        )


class TestFullFallbackChainIntegration:
    """Integration test verifying end-to-end fallback chain with real mirror files."""

    def test_full_chain_file_fixtures(self) -> None:
        """Verify: CVE.org -> Vulnrichment -> EUVD -> Derived."""
        engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
            cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
            first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
            vulnrichment=VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json"),
            euvd=EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json"),
        )

        # 1. Primary: CVE-2021-44228 has CVSS in CVE.org
        fields_cve_org = engine.fuse(_bare_finding("CVE-2021-44228"))
        assert fields_cve_org["cvss_score"].value == 10.0
        assert fields_cve_org["cvss_score"].provenance.source == Source.CVE_ORG
        assert fields_cve_org["cvss_score"].provenance.confidence == Confidence.HIGH

        # 2. Secondary fallback 1: CVE-2025-0001 is missing from CVE.org, present in Vulnrichment
        fields_vuln = engine.fuse(_bare_finding("CVE-2025-0001"))
        assert fields_vuln["cvss_score"].value == 8.1
        assert fields_vuln["cvss_score"].provenance.source == Source.VULNRICHMENT
        assert fields_vuln["cvss_score"].provenance.confidence == Confidence.MEDIUM
        assert fields_vuln["cwe_ids"].value == ["CWE-79"]
        assert fields_vuln["cwe_ids"].provenance.source == Source.VULNRICHMENT

        # 3. Secondary fallback 2: CVE-2025-0002 missing from CVE.org
        # and Vulnrichment, present in EUVD
        fields_euvd = engine.fuse(_bare_finding("CVE-2025-0002"))
        assert fields_euvd["cvss_score"].value == 6.5
        assert fields_euvd["cvss_score"].provenance.source == Source.EUVD
        assert fields_euvd["cvss_score"].provenance.confidence == Confidence.MEDIUM
        assert fields_euvd["cwe_ids"].value == ["CWE-20"]
        assert fields_euvd["cwe_ids"].provenance.source == Source.EUVD

        # 4. Fallback 3: CVE-2025-9999 missing from all sources -> Derived placeholder
        fields_derived = engine.fuse(_bare_finding("CVE-2025-9999"))
        assert fields_derived["cvss_score"].value == 5.0
        assert fields_derived["cvss_score"].provenance.source == Source.DERIVED
        assert fields_derived["cvss_score"].provenance.confidence == Confidence.LOW
        assert fields_derived["cwe_ids"].value == ["CWE-Other"]
        assert fields_derived["cwe_ids"].provenance.source == Source.DERIVED


class TestExploitAvailabilityIntegration:
    """Integration test verifying ExploitDB and Metasploit metadata in FusionEngine."""

    def test_exploit_signals_when_mirrors_loaded(self) -> None:
        engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
            cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
            first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
            exploitdb=ExploitDBSource(cache_file=FIXTURES_DIR / "exploitdb_sample.json"),
            metasploit=MetasploitSource(cache_file=FIXTURES_DIR / "metasploit_sample.json"),
        )

        # Log4Shell has both ExploitDB and Metasploit
        fields = engine.fuse(FINDING_LOG4SHELL)
        assert fields["has_public_exploit"].value is True
        assert fields["has_public_exploit"].provenance.source == Source.EXPLOITDB
        assert fields["has_public_exploit"].provenance.confidence == Confidence.HIGH
        assert fields["exploit_ids"].value == ["EDB-50592", "EDB-50593"]

        assert fields["has_metasploit_module"].value is True
        assert fields["has_metasploit_module"].provenance.source == Source.METASPLOIT
        assert fields["has_metasploit_module"].provenance.confidence == Confidence.HIGH
        assert fields["metasploit_modules"].value == [
            "exploit/multi/http/log4shell_header_injection"
        ]

        # Moderate finding has no exploit entries in sample mirrors
        fields_mod = engine.fuse(FINDING_NON_KEV_MODERATE)
        assert fields_mod["has_public_exploit"].value is False
        assert fields_mod["has_public_exploit"].provenance.source == Source.EXPLOITDB
        assert fields_mod["has_metasploit_module"].value is False
        assert fields_mod["has_metasploit_module"].provenance.source == Source.METASPLOIT

    def test_exploit_signals_when_mirrors_unloaded(self) -> None:
        """When exploit sources are unloaded, status is unknown (None, DERIVED/LOW)."""
        engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
            cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
            first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
            exploitdb=ExploitDBSource(cache_file=Path("/nonexistent/exploitdb.json")),
            metasploit=MetasploitSource(cache_file=Path("/nonexistent/metasploit.json")),
        )
        fields = engine.fuse(FINDING_LOG4SHELL)
        assert fields["has_public_exploit"].value is None
        assert fields["has_public_exploit"].provenance.source == Source.DERIVED
        assert fields["has_public_exploit"].provenance.confidence == Confidence.LOW

        assert fields["has_metasploit_module"].value is None
        assert fields["has_metasploit_module"].provenance.source == Source.DERIVED
        assert fields["has_metasploit_module"].provenance.confidence == Confidence.LOW

