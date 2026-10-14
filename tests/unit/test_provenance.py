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


def test_provenance_sources_match_frontend_contract() -> None:
    """Ensure Source enum is strictly in sync with frontend PROVENANCE_SOURCES."""
    import re
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    findings_ts = repo_root / "apps" / "web" / "lib" / "findings.ts"
    assert findings_ts.is_file(), f"missing {findings_ts}"

    content = findings_ts.read_text(encoding="utf-8")
    match = re.search(r"export const PROVENANCE_SOURCES = \[(.*?)\] as const;", content, re.DOTALL)
    assert match is not None, "PROVENANCE_SOURCES definition not found in findings.ts"

    frontend_sources = set(re.findall(r'"([^"]+)"', match.group(1)))
    backend_sources = {s.value for s in Source}
    assert frontend_sources == backend_sources, (
        f"Frontend PROVENANCE_SOURCES drifted from backend Source enum.\n"
        f"In frontend only: {frontend_sources - backend_sources}\n"
        f"In backend only: {backend_sources - frontend_sources}"
    )


def test_confidence_levels_match_frontend_contract() -> None:
    """Ensure Confidence enum is strictly in sync with frontend CONFIDENCE_LEVELS."""
    import re
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    findings_ts = repo_root / "apps" / "web" / "lib" / "findings.ts"
    assert findings_ts.is_file(), f"missing {findings_ts}"

    content = findings_ts.read_text(encoding="utf-8")
    match = re.search(r"export const CONFIDENCE_LEVELS = \[(.*?)\] as const;", content, re.DOTALL)
    assert match is not None, "CONFIDENCE_LEVELS definition not found in findings.ts"

    frontend_confidence = set(re.findall(r'"([^"]+)"', match.group(1)))
    backend_confidence = {c.value for c in Confidence}
    assert frontend_confidence == backend_confidence, (
        f"Frontend CONFIDENCE_LEVELS drifted from backend Confidence enum.\n"
        f"In frontend only: {frontend_confidence - backend_confidence}\n"
        f"In backend only: {backend_confidence - frontend_confidence}"
    )
