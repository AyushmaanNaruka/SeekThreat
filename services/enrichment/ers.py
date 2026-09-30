"""Exposure Risk Score (ERS) calculation engine.

Non-negotiable rules from services/enrichment/README.md and DECISIONS.md D-008:
1. NEVER multiply EPSS by CVSS:
   "Components combine ADDITIVELY (D-008). Never multiply EPSS by CVSS: the product
   is not probability times severity, and FIRST is explicit that it means nothing."
2. Hand-tuned, documented, additive weights (D-008):
   Weights are chosen transparently with documented reasoning. KEV membership
   provides an additive validation boost for confirmed active exploitation;
   it does not train the score.
3. Self-explaining breakdown:
   Every composite score renders its own ScoreComponent breakdown with non-empty
   explanations and valid Provenance. No opaque numbers, ever.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

# Hand-tuned, documented weights satisfying DECISIONS.md D-008.
# Sum of weights strictly equals 1.00.
DEFAULT_WEIGHT_CVSS: float = 0.40  # Technical severity & potential impact
DEFAULT_WEIGHT_EPSS: float = 0.35  # Empirical 30-day exploit probability
DEFAULT_WEIGHT_KEV: float = 0.25   # Confirmed active exploitation boost


@dataclass(frozen=True)
class ERSWeights:
    """Documented weights configuration for Exposure Risk Score calculation."""

    weight_cvss: float = DEFAULT_WEIGHT_CVSS
    weight_epss: float = DEFAULT_WEIGHT_EPSS
    weight_kev: float = DEFAULT_WEIGHT_KEV

    def __post_init__(self) -> None:
        total = self.weight_cvss + self.weight_epss + self.weight_kev
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"ERS weights must sum to 1.0; got {total}")


def calculate_ers(
    fields: dict[str, Attributed[EnrichmentValue]],
    weights: ERSWeights | None = None,
) -> ExposureRiskScore:
    """Calculate the additive Exposure Risk Score with self-explaining components.

    STRICT INVARIANT: Never multiplies EPSS * CVSS.
    Components combine additively as:
      ERS = (cvss_val * weight_cvss) + (epss_val * weight_epss) + (kev_val * weight_kev)
    where all component values are normalized to a 0.0 - 10.0 scale.
    """
    w = weights or ERSWeights()
    now = datetime.now(UTC)

    # 1. CVSS Technical Severity Component (0.0 to 10.0)
    attr_cvss = fields.get("cvss_score")
    if attr_cvss and isinstance(attr_cvss.value, (int, float)):
        cvss_val = float(attr_cvss.value)
        cvss_prov = attr_cvss.provenance
        cvss_exp = (
            f"CVSS base severity score of {cvss_val:.1f}/10.0 reflects technical "
            f"impact and attack vector characteristics [{cvss_prov.source.value}]."
        )
    else:
        cvss_val = 5.0
        cvss_prov = Provenance(
            source=Source.DERIVED,
            confidence=Confidence.LOW,
            retrieved_at=now,
            note="Default derived baseline CVSS",
        )
        cvss_exp = "No upstream CVSS metrics; conservative baseline severity of 5.0 applied."

    comp_cvss = ScoreComponent(
        name="CVSS Base Severity",
        value=cvss_val,
        weight=w.weight_cvss,
        explanation=cvss_exp,
        provenance=cvss_prov,
    )

    # 2. EPSS Exploit Probability Component (0.0 to 1.0 normalized to 0.0 - 10.0)
    attr_epss = fields.get("epss_score")
    attr_percentile = fields.get("epss_percentile")
    if attr_epss and isinstance(attr_epss.value, (int, float)):
        epss_prob = float(attr_epss.value)
        epss_val = min(10.0, max(0.0, epss_prob * 10.0))
        epss_prov = attr_epss.provenance
        pct_text = (
            f" ({float(attr_percentile.value) * 100:.1f}th percentile)"
            if attr_percentile and isinstance(attr_percentile.value, (int, float))
            else ""
        )
        epss_exp = (
            f"FIRST EPSS v4 empirical probability of {epss_prob * 100:.2f}%{pct_text} "
            f"measures exploitation likelihood in the wild over next 30 days."
        )
    else:
        epss_val = 0.01  # Default conservative floor
        epss_prov = Provenance(
            source=Source.DERIVED,
            confidence=Confidence.LOW,
            retrieved_at=now,
            note="Default derived baseline EPSS floor",
        )
        epss_exp = "No EPSS score found; baseline floor likelihood of 0.1% applied."

    comp_epss = ScoreComponent(
        name="EPSS Exploit Likelihood",
        value=epss_val,
        weight=w.weight_epss,
        explanation=epss_exp,
        provenance=epss_prov,
    )

    # 3. CISA KEV Active Exploitation Validation Boost Component (0.0 or 10.0)
    attr_kev = fields.get("in_kev")
    is_in_kev = bool(attr_kev.value) if attr_kev else False
    kev_prov = (
        attr_kev.provenance
        if attr_kev
        else Provenance(
            source=Source.KEV,
            confidence=Confidence.HIGH,
            retrieved_at=now,
            note="KEV status unavailable; defaulted to False",
        )
    )

    if is_in_kev:
        kev_val = 10.0
        attr_date = fields.get("kev_date_added")
        date_str = f" on {attr_date.value}" if attr_date and attr_date.value else ""
        kev_exp = (
            f"Confirmed active exploitation in the wild (added to CISA KEV{date_str}); "
            f"provides full additive validation boost (+{w.weight_kev * 10.0:.1f} ERS points)."
        )
    else:
        kev_val = 0.0
        kev_exp = "Vulnerability is not listed on CISA KEV catalog; zero active exploitation boost applied."

    comp_kev = ScoreComponent(
        name="CISA KEV Active Exploitation",
        value=kev_val,
        weight=w.weight_kev,
        explanation=kev_exp,
        provenance=kev_prov,
    )

    components = (comp_cvss, comp_epss, comp_kev)
    composite_value = sum(c.value * c.weight for c in components)

    return ExposureRiskScore(
        value=composite_value,
        components=components,
    )
