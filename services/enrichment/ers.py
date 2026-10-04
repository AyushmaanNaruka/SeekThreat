"""Exposure Risk Score (ERS) calculation engine.

Non-negotiable rules from services/enrichment/README.md and DECISIONS.md D-008 / D-027:
1. NEVER multiply EPSS by CVSS:
   Components combine ADDITIVELY (D-008). Never multiply EPSS by CVSS: the product
   is not probability times severity, and FIRST is explicit that it means nothing.
2. Hand-tuned, additive weights (D-008, rationale and sensitivity analysis in D-027).
   Weights: CVSS=0.40, EPSS=0.35, KEV=0.25. KEV is an input component (not a
   validator — D-027 resolves the circularity). Validation uses ExploitDB/Metasploit.
3. Self-explaining breakdown:
   Every composite score renders its own ScoreComponent breakdown with non-empty
   explanations and valid Provenance. No opaque numbers, ever. Derived placeholder
   inputs (Source.DERIVED) are explained as placeholders, never as measurements.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

# Hand-tuned weights. Rationale and sensitivity analysis documented in D-027.
# CVSS dominates (technical severity); EPSS near-parity (exploitation probability);
# KEV is an additive input for confirmed active exploitation — not a validator (D-027).
# Sum of weights strictly equals 1.00.
DEFAULT_WEIGHT_CVSS: float = 0.40  # Technical severity & potential impact
DEFAULT_WEIGHT_EPSS: float = 0.35  # 30-day exploitation probability (FIRST EPSS v4)
DEFAULT_WEIGHT_KEV: float = 0.25  # Confirmed active exploitation (CISA KEV input)

# Values used only when a field is entirely absent from the fused dict. Same
# values as fusion.py's derived placeholders (CVSS 5.0, EPSS 0.001).
_ABSENT_CVSS: float = 5.0
_ABSENT_EPSS_PROBABILITY: float = 0.001


@dataclass(frozen=True)
class ERSWeights:
    """Weights configuration for Exposure Risk Score calculation."""

    weight_cvss: float = DEFAULT_WEIGHT_CVSS
    weight_epss: float = DEFAULT_WEIGHT_EPSS
    weight_kev: float = DEFAULT_WEIGHT_KEV

    def __post_init__(self) -> None:
        weights = (self.weight_cvss, self.weight_epss, self.weight_kev)
        if any(w < 0.0 for w in weights):
            raise ValueError(f"ERS weights must be non-negative; got {weights}")
        total = sum(weights)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"ERS weights must sum to 1.0; got {total}")


def _clamp(value: float, low: float = 0.0, high: float = 10.0) -> float:
    return min(high, max(low, value))


def _derived_provenance(now: datetime, note: str) -> Provenance:
    return Provenance(source=Source.DERIVED, confidence=Confidence.LOW, retrieved_at=now, note=note)


def _cvss_component(
    attr: Attributed[EnrichmentValue] | None, weight: float, now: datetime
) -> ScoreComponent:
    if (
        attr is not None
        and isinstance(attr.value, (int, float))
        and not isinstance(attr.value, bool)
    ):
        raw = float(attr.value)
        prov = attr.provenance
    else:
        raw = _ABSENT_CVSS
        prov = _derived_provenance(now, "No CVSS field supplied to ERS")

    value = _clamp(raw)
    if prov.source == Source.DERIVED:
        explanation = (
            f"No source data was available for CVSS; a placeholder value of {raw:.1f}/10.0 "
            f"was used [derived, {prov.confidence.value} confidence]. "
            "This is not a measured severity."
        )
    else:
        explanation = (
            f"CVSS base severity score of {value:.1f}/10.0 reflects technical "
            f"impact and attack vector characteristics [{prov.source.value}]."
        )
    if value != raw:
        explanation += f" Input {raw:g} clamped to the 0-10 range."

    return ScoreComponent(
        name="CVSS Base Severity",
        value=value,
        weight=weight,
        explanation=explanation,
        provenance=prov,
    )


def _epss_component(
    attr: Attributed[EnrichmentValue] | None,
    attr_percentile: Attributed[EnrichmentValue] | None,
    weight: float,
    now: datetime,
) -> ScoreComponent:
    if (
        attr is not None
        and isinstance(attr.value, (int, float))
        and not isinstance(attr.value, bool)
    ):
        prob = float(attr.value)
        prov = attr.provenance
    else:
        prob = _ABSENT_EPSS_PROBABILITY
        prov = _derived_provenance(now, "No EPSS field supplied to ERS")

    value = _clamp(prob * 10.0)
    if prov.source == Source.DERIVED:
        explanation = (
            f"No source data was available for EPSS; a placeholder probability of "
            f"{prob * 100:.2f}% was used [derived, {prov.confidence.value} confidence]. "
            "This is not a measured exploitation likelihood."
        )
    else:
        pct_text = (
            f" ({float(attr_percentile.value) * 100:.1f}th percentile)"
            if attr_percentile is not None
            and isinstance(attr_percentile.value, (int, float))
            and attr_percentile.provenance.source != Source.DERIVED
            else ""
        )
        explanation = (
            f"FIRST EPSS v4 probability of {prob * 100:.2f}%{pct_text} "
            f"estimates exploitation likelihood in the wild over the next 30 days "
            f"[{prov.source.value}]."
        )

    return ScoreComponent(
        name="EPSS Exploit Likelihood",
        value=value,
        weight=weight,
        explanation=explanation,
        provenance=prov,
    )


def _kev_component(
    attr: Attributed[EnrichmentValue] | None,
    attr_date: Attributed[EnrichmentValue] | None,
    weight: float,
    now: datetime,
) -> ScoreComponent:
    if attr is not None and attr.value is True:
        value = 10.0
        prov = attr.provenance
        date_str = f" on {attr_date.value}" if attr_date and attr_date.value else ""
        explanation = (
            f"Confirmed active exploitation in the wild (added to CISA KEV{date_str}); "
            f"provides full additive validation boost (+{weight * 10.0:.1f} ERS points)."
        )
    elif attr is not None and attr.value is False:
        value = 0.0
        prov = attr.provenance
        if prov.source == Source.KEV:
            explanation = (
                "Vulnerability is not listed on the loaded CISA KEV catalog; "
                "zero active exploitation boost applied."
            )
        else:
            reason = prov.note or "derived KEV status"
            explanation = f"{reason} [derived]; zero active exploitation boost applied."
    else:
        # Absent or None: KEV status is unknown. Never attribute this to CISA KEV.
        value = 0.0
        note = (attr.provenance.note if attr is not None else None) or (
            "No KEV data supplied; KEV status unknown"
        )
        prov = _derived_provenance(now, note)
        explanation = (
            f"CISA KEV status unknown ({note}); no active exploitation boost applied. "
            "This is not a confirmed negative."
        )

    return ScoreComponent(
        name="CISA KEV Active Exploitation",
        value=value,
        weight=weight,
        explanation=explanation,
        provenance=prov,
    )


def calculate_ers(
    fields: dict[str, Attributed[EnrichmentValue]],
    weights: ERSWeights | None = None,
) -> ExposureRiskScore:
    """Calculate the additive Exposure Risk Score with self-explaining components.

    STRICT INVARIANT: Never multiplies EPSS * CVSS.
    Components combine additively as:
      ERS = (cvss_val * weight_cvss) + (epss_val * weight_epss) + (kev_val * weight_kev)
    where all component values are clamped to a 0.0 - 10.0 scale.
    """
    w = weights or ERSWeights()
    now = datetime.now(UTC)

    components = (
        _cvss_component(fields.get("cvss_score"), w.weight_cvss, now),
        _epss_component(
            fields.get("epss_score"), fields.get("epss_percentile"), w.weight_epss, now
        ),
        _kev_component(fields.get("in_kev"), fields.get("kev_date_added"), w.weight_kev, now),
    )
    composite_value = sum(c.value * c.weight for c in components)

    return ExposureRiskScore(
        value=composite_value,
        components=components,
    )
