from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.schema.models.provenance import (
    Attributed,
    Confidence,
    Provenance,
    Source,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _prov() -> Provenance:
    return Provenance(source=Source.KEV, confidence=Confidence.HIGH, retrieved_at=NOW)


def test_provenance_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Provenance(
            source=Source.KEV,
            confidence=Confidence.HIGH,
            retrieved_at=datetime(2026, 9, 5, 12, 0),
        )


def test_provenance_is_frozen() -> None:
    p = _prov()
    with pytest.raises(ValidationError):
        p.source = Source.NVD  # type: ignore[misc]


def test_attributed_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Attributed[str](value="9.8")  # type: ignore[call-arg]


def test_attributed_carries_value_and_provenance() -> None:
    a = Attributed[float](value=9.8, provenance=_prov())
    assert a.value == 9.8
    assert a.provenance.source is Source.KEV


def test_derived_source_exists_and_is_labelled() -> None:
    assert Source.DERIVED.value == "derived"
