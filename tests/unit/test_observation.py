from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
    ScanResult,
)
from packages.schema.models.provenance import Confidence, Provenance, Source

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _observation(artifact_id: str = "art-001") -> Observation:
    return Observation(
        observation_id="obs-001",
        engagement_id="eng-001",
        scanner="nmap",
        kind=ObservationKind.SERVICE_VERSION,
        subject="172.20.1.10:80/tcp",
        attributes={"product": "apache", "version": "2.4.49"},
        artifact_id=artifact_id,
        observed_at=NOW,
        provenance=Provenance(source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW),
    )


def _artifact(artifact_id: str = "art-001") -> RawArtifact:
    return RawArtifact(
        artifact_id=artifact_id,
        scanner="nmap",
        content="x",
        content_type="application/xml",
        captured_at=NOW,
    )


def test_observation_is_immutable() -> None:
    obs = _observation()
    with pytest.raises(ValidationError):
        obs.subject = "172.20.1.11:80"  # type: ignore[misc]


def test_attributes_dict_is_mutable_in_place_a_known_limitation() -> None:
    """Pydantic has no frozen-dict type, so `attributes` stays mutable in place
    even though Observation itself is frozen. Accepted limitation, documented
    above the field in packages/schema/models/observation.py — this test makes
    it visible rather than silent.
    """
    obs = _observation()
    obs.attributes["version"] = "tampered"
    assert obs.attributes["version"] == "tampered"


def test_observation_carries_provenance_and_artifact() -> None:
    obs = _observation()
    assert obs.provenance.source is Source.SCANNER
    assert obs.artifact_id == "art-001"


def test_observation_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Observation(  # type: ignore[call-arg]
            observation_id="obs-002",
            engagement_id="eng-001",
            scanner="nmap",
            kind=ObservationKind.PORT_OPEN,
            subject="172.20.1.10:22",
            attributes={},
            artifact_id="art-001",
            observed_at=NOW,
        )


def test_observation_rejects_naive_datetime() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Observation(
            observation_id="obs-003",
            engagement_id="eng-001",
            scanner="nmap",
            kind=ObservationKind.HOST_UP,
            subject="172.20.1.10",
            attributes={},
            artifact_id="art-001",
            observed_at=datetime(2026, 9, 5, 12, 0),
            provenance=Provenance(
                source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
            ),
        )


def test_raw_artifact_preserves_content_verbatim() -> None:
    xml = '<?xml version="1.0"?><nmaprun scanner="nmap"/>'
    art = RawArtifact(
        artifact_id="art-001",
        scanner="nmap",
        content=xml,
        content_type="application/xml",
        captured_at=NOW,
    )
    assert art.content == xml


def test_raw_artifact_is_immutable() -> None:
    art = RawArtifact(
        artifact_id="art-001",
        scanner="nmap",
        content="x",
        content_type="application/xml",
        captured_at=NOW,
    )
    with pytest.raises(ValidationError):
        art.content = "tampered"  # type: ignore[misc]


def test_scan_result_accepts_observations_matching_its_artifact() -> None:
    result = ScanResult(artifact=_artifact(), observations=(_observation(),))
    assert result.observations[0].artifact_id == result.artifact.artifact_id


def test_scan_result_allows_zero_observations() -> None:
    result = ScanResult(artifact=_artifact())
    assert result.observations == ()


def test_scan_result_rejects_an_observation_from_a_foreign_artifact() -> None:
    with pytest.raises(ValidationError, match="art-001"):
        ScanResult(
            artifact=_artifact("art-001"),
            observations=(_observation(artifact_id="art-999"),),
        )


def test_scan_result_is_immutable() -> None:
    result = ScanResult(artifact=_artifact())
    with pytest.raises(ValidationError):
        result.artifact = _artifact("art-002")  # type: ignore[misc]
