"""Exposure Risk Score.

Every score renders its own explanation. The model validates that `value` is the
weighted sum of its components, so a number that cannot account for itself cannot
be constructed.

Components combine ADDITIVELY (D-008). Never multiply EPSS by CVSS: the product
is not probability times severity, and FIRST is explicit that it means nothing.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from packages.schema.models.provenance import Provenance

_TOLERANCE = 1e-6


class ScoreComponent(BaseModel):
    """One input to the Exposure Risk Score, with its reasoning."""

    model_config = ConfigDict(frozen=True)

    name: str
    value: float
    weight: float
    explanation: str
    provenance: Provenance

    @field_validator("explanation")
    @classmethod
    def _explanation_is_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("every component needs an explanation; no opaque numbers")
        return value


class ExposureRiskScore(BaseModel):
    """Composite risk. Always able to explain itself."""

    model_config = ConfigDict(frozen=True)

    value: float
    components: tuple[ScoreComponent, ...]

    @model_validator(mode="after")
    def _value_accounts_for_its_components(self) -> ExposureRiskScore:
        if not self.components:
            raise ValueError("a score needs at least one component to explain it")
        expected = sum(c.value * c.weight for c in self.components)
        if abs(self.value - expected) > _TOLERANCE:
            raise ValueError(
                f"value {self.value} is not the weighted sum of its components "
                f"({expected}); a score must account for itself"
            )
        return self

    def explain(self) -> str:
        lines = [f"Exposure Risk Score: {self.value:.2f}", ""]
        for c in self.components:
            lines.append(
                f"  {c.name}: {c.value:.2f} (weight {c.weight:.2f}) — {c.explanation}"
                f"  [{c.provenance.source.value}, {c.provenance.confidence.value}]"
            )
        return "\n".join(lines)
