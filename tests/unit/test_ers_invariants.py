"""Unit tests and invariant guards for Exposure Risk Score (ERS) calculation.

Guards rules from services/enrichment/README.md and DECISIONS.md D-008:
1. Never multiply EPSS by CVSS (anti-multiplication regression guard).
2. Components combine additively with documented, hand-tuned weights.
3. Every score renders its own explanation through ScoreComponent.
4. KEV membership provides an additive validation boost, not a training target.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent
from services.enrichment.ers import (
    DEFAULT_WEIGHT_CVSS,
    DEFAULT_WEIGHT_EPSS,
    DEFAULT_WEIGHT_KEV,
    ERSWeights,
    calculate_ers,
)
from services.enrichment.fusion import FusionEngine
from services.enrichment.sources import CISAKevSource, CVEOrgSource, FirstEPSSSource
from tests.fixtures.findings.baseline_findings import (
    FINDING_LOG4SHELL,
    FINDING_NON_KEV_MODERATE,
    get_baseline_findings,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


@pytest.fixture
def fusion_engine() -> FusionEngine:
    return FusionEngine(
        cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
        cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
        first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
    )


class TestERSAntiMultiplicationInvariant:
    """Non-negotiable rule 3: Never multiply EPSS by CVSS."""

    def test_ers_is_never_literally_epss_times_cvss(self, fusion_engine: FusionEngine) -> None:
        """Explicit regression guard across all baseline findings.

        FIRST is explicit that the product (EPSS * CVSS) is meaningless.
        We assert that ERS is never equal to (cvss * epss).
        """
        for finding in get_baseline_findings():
            fields = fusion_engine.fuse(finding)
            ers = calculate_ers(fields)

            cvss_val = float(fields["cvss_score"].value)  # type: ignore[arg-type]
            epss_val = float(fields["epss_score"].value)  # type: ignore[arg-type]

            # Product that FIRST explicitly forbids
            forbidden_product = cvss_val * epss_val

            assert abs(ers.value - forbidden_product) > 0.05, (
                f"ERS value {ers.value} for {finding.finding_id} is unexpectedly close "
                f"to forbidden product (cvss {cvss_val} * epss {epss_val} = {forbidden_product}). "
                f"ERS must be an additive weighted sum, never a multiplicative product!"
            )


class TestERSAdditiveFormulasAndWeights:
    """Test additive formula and D-008 hand-tuned weight behavior."""

    def test_ers_value_matches_weighted_sum_of_components(
        self, fusion_engine: FusionEngine
    ) -> None:
        for finding in get_baseline_findings():
            fields = fusion_engine.fuse(finding)
            ers = calculate_ers(fields)

            expected_sum = sum(c.value * c.weight for c in ers.components)
            assert abs(ers.value - expected_sum) < 1e-6
            assert 0.0 <= ers.value <= 10.0

    def test_weights_sum_to_one(self) -> None:
        assert abs((DEFAULT_WEIGHT_CVSS + DEFAULT_WEIGHT_EPSS + DEFAULT_WEIGHT_KEV) - 1.0) < 1e-6

    def test_invalid_weights_raise_value_error(self) -> None:
        with pytest.raises(ValueError, match="must sum to 1.0"):
            ERSWeights(weight_cvss=0.5, weight_epss=0.5, weight_kev=0.5)


class TestKEVValidationBoostBehavior:
    """D-008: KEV validates and boosts the score; it does not dictate it."""

    def test_kev_boosts_score_additively(self, fusion_engine: FusionEngine) -> None:
        # Log4Shell is in KEV
        fields_log4j = fusion_engine.fuse(FINDING_LOG4SHELL)
        ers_log4j = calculate_ers(fields_log4j)

        kev_component = next(
            c for c in ers_log4j.components if c.name == "CISA KEV Active Exploitation"
        )
        assert kev_component.value == 10.0
        assert kev_component.weight == DEFAULT_WEIGHT_KEV
        # Boost contribution is exactly 10.0 * 0.25 = 2.50
        assert abs(kev_component.value * kev_component.weight - 2.50) < 1e-6

        # Express-fileupload is NOT in KEV
        fields_express = fusion_engine.fuse(FINDING_NON_KEV_MODERATE)
        ers_express = calculate_ers(fields_express)

        kev_comp_express = next(
            c for c in ers_express.components if c.name == "CISA KEV Active Exploitation"
        )
        assert kev_comp_express.value == 0.0
        assert kev_comp_express.value * kev_comp_express.weight == 0.0

    def test_kev_presence_does_not_solely_determine_high_score(self) -> None:
        """A low-severity vulnerability in KEV must not artificially jump to critical."""
        from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

        low_sev_kev_fields = {
            "cvss_score": Attributed(
                value=2.0,
                provenance=Provenance(
                    source=Source.CVE_ORG,
                    confidence=Confidence.HIGH,
                    retrieved_at=FINDING_LOG4SHELL.detected_at,
                ),
            ),
            "epss_score": Attributed(
                value=0.01,
                provenance=Provenance(
                    source=Source.EPSS,
                    confidence=Confidence.HIGH,
                    retrieved_at=FINDING_LOG4SHELL.detected_at,
                ),
            ),
            "in_kev": Attributed(
                value=True,
                provenance=Provenance(
                    source=Source.KEV,
                    confidence=Confidence.HIGH,
                    retrieved_at=FINDING_LOG4SHELL.detected_at,
                ),
            ),
        }

        ers = calculate_ers(low_sev_kev_fields)
        # 2.0 * 0.40 + 0.1 * 0.35 + 10.0 * 0.25 = 0.80 + 0.035 + 2.50 = 3.335
        assert ers.value < 4.0, (
            "Low severity in KEV should still reflect moderate/low composite risk"
        )


class TestERSSelfExplainingOutput:
    """Rule 4: ERS must explain itself. Every score renders its component breakdown."""

    def test_every_component_has_explanation_and_provenance(
        self, fusion_engine: FusionEngine
    ) -> None:
        fields = fusion_engine.fuse(FINDING_LOG4SHELL)
        ers = calculate_ers(fields)

        assert len(ers.components) == 3
        for comp in ers.components:
            assert isinstance(comp, ScoreComponent)
            assert comp.explanation.strip() != ""
            assert comp.provenance is not None
            assert comp.weight > 0.0

        explanation_text = ers.explain()
        assert "Exposure Risk Score:" in explanation_text
        assert "CVSS Base Severity" in explanation_text
        assert "EPSS Exploit Likelihood" in explanation_text
        assert "CISA KEV Active Exploitation" in explanation_text

    def test_fuse_to_enriched_finding_attaches_ers(self, fusion_engine: FusionEngine) -> None:
        enriched = fusion_engine.fuse_to_enriched_finding(FINDING_LOG4SHELL, compute_ers=True)
        assert enriched.ers is not None
        assert isinstance(enriched.ers, ExposureRiskScore)
        assert enriched.ers.value > 9.5


def _attr(value: object, source: Source, confidence: Confidence = Confidence.HIGH) -> Attributed:
    return Attributed(
        value=value,
        provenance=Provenance(
            source=source, confidence=confidence, retrieved_at=FINDING_LOG4SHELL.detected_at
        ),
    )


class TestDerivedPlaceholdersExplainedHonestly:
    """Derived placeholder values must not be explained as measurements."""

    def test_derived_cvss_and_epss_explained_as_placeholders(self) -> None:
        fields = {
            "cvss_score": _attr(5.0, Source.DERIVED, Confidence.LOW),
            "epss_score": _attr(0.001, Source.DERIVED, Confidence.LOW),
            "in_kev": _attr(False, Source.KEV),
        }
        ers = calculate_ers(fields)
        cvss, epss, _ = ers.components
        for comp in (cvss, epss):
            text = comp.explanation.lower()
            assert "placeholder" in text
            assert "no source data" in text
            assert comp.provenance.source == Source.DERIVED
            assert comp.provenance.confidence == Confidence.LOW
        assert "5.0" in cvss.explanation
        assert "first epss" not in epss.explanation.lower()
        assert "empirical" not in epss.explanation.lower()
        assert "cvss base severity score" not in cvss.explanation.lower()

    def test_heuristic_finding_ers_uses_placeholder_language(
        self, fusion_engine: FusionEngine
    ) -> None:
        from tests.fixtures.findings.baseline_findings import FINDING_HEURISTIC_NO_CVE

        ers = calculate_ers(fusion_engine.fuse(FINDING_HEURISTIC_NO_CVE))
        cvss, epss, _ = ers.components
        assert "placeholder" in cvss.explanation.lower()
        assert "placeholder" in epss.explanation.lower()

    def test_measured_values_keep_measurement_language(self, fusion_engine: FusionEngine) -> None:
        ers = calculate_ers(fusion_engine.fuse(FINDING_LOG4SHELL))
        cvss, epss, _ = ers.components
        assert "placeholder" not in cvss.explanation.lower()
        assert "FIRST EPSS" in epss.explanation


class TestERSBounds:
    def test_cvss_component_clamped_to_ten(self) -> None:
        fields = {
            "cvss_score": _attr(15.0, Source.CVE_ORG),
            "epss_score": _attr(0.5, Source.EPSS),
            "in_kev": _attr(False, Source.KEV),
        }
        ers = calculate_ers(fields)
        assert ers.components[0].value == 10.0
        assert ers.value <= 10.0

    def test_cvss_component_clamped_to_zero(self) -> None:
        fields = {
            "cvss_score": _attr(-3.0, Source.CVE_ORG),
            "epss_score": _attr(0.5, Source.EPSS),
            "in_kev": _attr(False, Source.KEV),
        }
        assert calculate_ers(fields).components[0].value == 0.0

    def test_negative_weights_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            ERSWeights(weight_cvss=1.2, weight_epss=-0.2, weight_kev=0.0)

    def test_absent_in_kev_defaults_to_derived_unknown(self) -> None:
        fields = {
            "cvss_score": _attr(7.0, Source.CVE_ORG),
            "epss_score": _attr(0.5, Source.EPSS),
        }
        kev = calculate_ers(fields).components[2]
        assert kev.value == 0.0
        assert kev.provenance.source == Source.DERIVED
        assert kev.provenance.confidence == Confidence.LOW
        assert "unknown" in kev.explanation.lower()
        assert "not listed" not in kev.explanation.lower()
