"""Unit tests and invariant guards for CISA KEV scoring behavior.

Guards DECISIONS.md D-008 and services/enrichment/README.md:
"KEV Validates; It Does Not Train."
- CISA KEV membership provides an additive validation boost reflecting
  confirmed active weaponization in the wild.
- KEV presence increases score via additive boost (+2.5 points under default weights),
  but does NOT arbitrarily peg the score to maximum (10.0).
- Non-KEV vulnerabilities with high CVSS and EPSS still receive appropriately high scores.
"""

from __future__ import annotations

from datetime import UTC, datetime

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from services.enrichment.ers import (
    DEFAULT_WEIGHT_KEV,
    calculate_ers,
)

NOW = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)


def _prov(source: Source = Source.CVE_ORG) -> Provenance:
    return Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW)


def _make_fields(
    cvss: float,
    epss: float,
    in_kev: bool,
) -> dict[str, Attributed[EnrichmentValue]]:
    return {
        "cvss_score": Attributed[EnrichmentValue](value=cvss, provenance=_prov(Source.CVE_ORG)),
        "epss_score": Attributed[EnrichmentValue](value=epss, provenance=_prov(Source.EPSS)),
        "in_kev": Attributed[EnrichmentValue](value=in_kev, provenance=_prov(Source.KEV)),
    }


class TestKEVScoringInvariants:
    """Invariant checks proving KEV validates rather than trains or dictates."""

    def test_kev_presence_adds_exact_weighted_boost(self) -> None:
        """KEV presence contributes exactly (10.0 * DEFAULT_WEIGHT_KEV) points."""
        fields_without_kev = _make_fields(cvss=7.0, epss=0.5, in_kev=False)
        fields_with_kev = _make_fields(cvss=7.0, epss=0.5, in_kev=True)

        ers_no_kev = calculate_ers(fields_without_kev)
        ers_kev = calculate_ers(fields_with_kev)

        expected_boost = 10.0 * DEFAULT_WEIGHT_KEV  # 2.5 points
        assert abs((ers_kev.value - ers_no_kev.value) - expected_boost) < 1e-6

    def test_low_severity_cve_with_kev_does_not_peg_to_maximum(self) -> None:
        """Low CVSS + Low EPSS on KEV must not peg score to 10.0 or critical."""
        # e.g., an informational / low flaw used in a chained exploit
        fields = _make_fields(cvss=2.0, epss=0.01, in_kev=True)
        ers = calculate_ers(fields)

        # Expected: (2.0 * 0.40) + (0.1 * 0.35) + (10.0 * 0.25) = 0.8 + 0.035 + 2.5 = 3.335
        assert ers.value < 4.0, (
            f"Low severity finding on KEV reached {ers.value}, unexpectedly high"
        )
        assert ers.value != 10.0

    def test_high_severity_cve_without_kev_retains_high_score(self) -> None:
        """High CVSS + High EPSS without KEV must still score high, not artificially depressed."""
        fields = _make_fields(cvss=9.8, epss=0.95, in_kev=False)
        ers = calculate_ers(fields)

        # Expected: (9.8 * 0.40) + (9.5 * 0.35) + 0.0 = 3.92 + 3.325 = 7.245
        assert ers.value >= 7.0, (
            f"High severity finding without KEV dropped to {ers.value}, unexpectedly low"
        )

    def test_kev_component_breakdown_is_explicit(self) -> None:
        """ScoreComponent for KEV must explicitly state whether KEV presence was validated."""
        fields_with_kev = _make_fields(cvss=7.5, epss=0.3, in_kev=True)
        ers = calculate_ers(fields_with_kev)

        kev_comp = next((c for c in ers.components if "kev" in c.name.lower()), None)
        assert kev_comp is not None
        assert kev_comp.value == 10.0
        assert kev_comp.weight == DEFAULT_WEIGHT_KEV
        assert (
            "confirmed" in kev_comp.explanation.lower()
            or "active exploitation" in kev_comp.explanation.lower()
        )
        assert kev_comp.provenance.source == Source.KEV

        fields_without_kev = _make_fields(cvss=7.5, epss=0.3, in_kev=False)
        ers_no_kev = calculate_ers(fields_without_kev)
        kev_comp_no = next((c for c in ers_no_kev.components if "kev" in c.name.lower()), None)
        assert kev_comp_no is not None
        assert kev_comp_no.value == 0.0
        assert "not listed" in kev_comp_no.explanation.lower()
