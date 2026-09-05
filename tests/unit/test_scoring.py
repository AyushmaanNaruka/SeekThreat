from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.schema.models.provenance import Confidence, Provenance, Source
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _component(name: str, value: float, weight: float, source: Source) -> ScoreComponent:
    return ScoreComponent(
        name=name,
        value=value,
        weight=weight,
        explanation=f"{name} contributed {value}",
        provenance=Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW),
    )


def _components() -> list[ScoreComponent]:
    return [
        _component("epss", 0.8, 0.5, Source.EPSS),
        _component("kev_listed", 1.0, 0.3, Source.KEV),
    ]


def test_score_equals_the_weighted_sum_of_its_components() -> None:
    score = ExposureRiskScore(value=0.7, components=_components())
    assert score.value == pytest.approx(0.7)


def test_score_inconsistent_with_its_components_is_rejected() -> None:
    with pytest.raises(ValidationError, match="weighted sum"):
        ExposureRiskScore(value=0.99, components=_components())


def test_score_must_have_components() -> None:
    with pytest.raises(ValidationError, match="component"):
        ExposureRiskScore(value=0.0, components=[])


def test_explain_names_every_component_with_its_source() -> None:
    text = ExposureRiskScore(value=0.7, components=_components()).explain()
    assert "epss" in text
    assert "kev_listed" in text
    assert "first.epss" in text
    assert "cisa.kev" in text
    assert "0.70" in text


def test_components_cannot_be_mutated_in_place() -> None:
    score = ExposureRiskScore(value=0.7, components=_components())
    with pytest.raises(AttributeError):
        score.components.append(_component("kev_listed", 1.0, 0.3, Source.KEV))  # type: ignore[attr-defined]


def test_component_requires_an_explanation() -> None:
    with pytest.raises(ValidationError, match="explanation"):
        ScoreComponent(
            name="epss",
            value=0.8,
            weight=0.5,
            explanation="   ",
            provenance=Provenance(source=Source.EPSS, confidence=Confidence.HIGH, retrieved_at=NOW),
        )
