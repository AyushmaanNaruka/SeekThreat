"""Unit tests and invariant guards for intelligence provenance completeness.

Guards Rule 1 from services/enrichment/README.md:
"Every field gets a Provenance. No unattributed data. Every field is wrapped
in Attributed[EnrichmentValue] — an unattributed value must be unrepresentable,
not just discouraged."
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.service import EnrichmentService
from services.enrichment.sources import CISAKevSource, CVEOrgSource, FirstEPSSSource
from tests.fixtures.findings.baseline_findings import (
    FINDING_HEURISTIC_NO_CVE,
    FINDING_LOG4SHELL,
    get_baseline_findings,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


@pytest.fixture
def enrichment_service() -> EnrichmentService:
    engine = FusionEngine(
        cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
        cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
        first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
    )
    return EnrichmentService(fusion_engine=engine)


class TestProvenanceCompleteness:
    """Verifies that every field in every enriched finding carries rigorous provenance."""

    def test_every_field_in_every_baseline_finding_is_attributed(
        self, enrichment_service: EnrichmentService
    ) -> None:
        """Rule 1 invariant across all baseline findings."""
        for finding in get_baseline_findings():
            enriched = enrichment_service.enrich_finding(finding, persist=False)
            assert len(enriched.fields) > 0, f"No fields for {finding.finding_id}"

            for field_name, attr in enriched.fields.items():
                # 1. Type check
                assert isinstance(attr, Attributed), (
                    f"Field '{field_name}' in finding {finding.finding_id} "
                    "is not wrapped in Attributed"
                )

                # 2. Provenance presence
                prov = attr.provenance
                assert prov is not None, f"Provenance missing for '{field_name}'"

                # 3. Valid Source enum
                assert isinstance(prov.source, Source), (
                    f"Invalid source '{prov.source}' for '{field_name}'"
                )

                # 4. Valid Confidence enum
                assert isinstance(prov.confidence, Confidence), (
                    f"Invalid confidence '{prov.confidence}' for '{field_name}'"
                )

                # 5. Timezone-aware UTC timestamp
                assert prov.retrieved_at is not None, f"retrieved_at missing for '{field_name}'"
                assert prov.retrieved_at.tzinfo is not None, (
                    f"retrieved_at is naive for '{field_name}'"
                )

    def test_ers_components_carry_provenance(self, enrichment_service: EnrichmentService) -> None:
        """Every ScoreComponent inside ERS must carry a valid Provenance."""
        for finding in get_baseline_findings():
            enriched = enrichment_service.enrich_finding(finding, persist=False)
            assert enriched.ers is not None

            for component in enriched.ers.components:
                prov = component.provenance
                assert prov is not None, (
                    f"Component '{component.name}' in {finding.finding_id} missing provenance"
                )
                assert isinstance(prov.source, Source)
                assert isinstance(prov.confidence, Confidence)
                assert prov.retrieved_at.tzinfo is not None

    def test_derived_fields_are_explicitly_labeled_as_derived(
        self, enrichment_service: EnrichmentService
    ) -> None:
        """Rule 2 requirement: derived values must be explicitly labeled."""
        enriched = enrichment_service.enrich_finding(FINDING_HEURISTIC_NO_CVE, persist=False)

        cvss_attr = enriched.fields["cvss_score"]
        assert cvss_attr.provenance.source == Source.DERIVED
        assert cvss_attr.provenance.confidence == Confidence.LOW
        assert (
            "fallback" in cvss_attr.provenance.note.lower()
            or "derived" in cvss_attr.provenance.note.lower()
        )

        epss_attr = enriched.fields["epss_score"]
        assert epss_attr.provenance.source == Source.DERIVED
        assert epss_attr.provenance.confidence == Confidence.LOW

    def test_cve_org_provenance_attributes(self, enrichment_service: EnrichmentService) -> None:
        enriched = enrichment_service.enrich_finding(FINDING_LOG4SHELL, persist=False)

        cvss_attr = enriched.fields["cvss_score"]
        assert cvss_attr.provenance.source == Source.CVE_ORG
        assert cvss_attr.provenance.confidence == Confidence.HIGH
        assert cvss_attr.value == 10.0

    def test_cisa_kev_provenance_attributes(self, enrichment_service: EnrichmentService) -> None:
        enriched = enrichment_service.enrich_finding(FINDING_LOG4SHELL, persist=False)

        kev_attr = enriched.fields["in_kev"]
        assert kev_attr.provenance.source == Source.KEV
        assert kev_attr.provenance.confidence == Confidence.HIGH
        assert kev_attr.value is True
        assert "CVE-2021-44228" in (kev_attr.provenance.note or "")

    def test_first_epss_provenance_attributes(self, enrichment_service: EnrichmentService) -> None:
        enriched = enrichment_service.enrich_finding(FINDING_LOG4SHELL, persist=False)

        epss_attr = enriched.fields["epss_score"]
        assert epss_attr.provenance.source == Source.EPSS
        assert epss_attr.provenance.confidence == Confidence.HIGH
        assert epss_attr.value > 0.9

    def test_serialization_round_trip_preserves_provenance(
        self, enrichment_service: EnrichmentService
    ) -> None:
        """Serializing to JSON and validating back must preserve exact provenance."""
        enriched = enrichment_service.enrich_finding(FINDING_LOG4SHELL, persist=False)
        serialized = enriched.model_dump(mode="json")

        restored = EnrichedFinding.model_validate(serialized)

        for field_name in enriched.fields:
            orig_prov = enriched.fields[field_name].provenance
            rest_prov = restored.fields[field_name].provenance

            assert rest_prov.source == orig_prov.source
            assert rest_prov.confidence == orig_prov.confidence
            assert rest_prov.retrieved_at == orig_prov.retrieved_at
            assert rest_prov.note == orig_prov.note
