from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _observation() -> Observation:
    return Observation(
        observation_id="obs-001",
        engagement_id="eng-001",
        scanner="nmap",
        kind=ObservationKind.SERVICE_VERSION,
        subject="172.20.1.10:80",
        attributes={"product": "apache", "version": "2.4.49"},
        artifact_id="art-001",
        observed_at=NOW,
        provenance=Provenance(
            source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
        ),
    )


def test_observation_is_immutable() -> None:
    obs = _observation()
    with pytest.raises(ValidationError):
        obs.subject = "172.20.1.11:80"


def test_observation_carries_provenance_and_artifact() -> None:
    obs = _observation()
    assert obs.provenance.source is Source.SCANNER
    assert obs.artifact_id == "art-001"


def test_observation_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Observation(
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
        art.content = "tampered"
