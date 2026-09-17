"""Tests for the ScannerAdapter base contract: artifact construction and ScanResult.

The authorization-gate behavior itself (gate precedes _execute, rejects unauthorized
targets) is covered exhaustively for every concrete adapter by
tests/architecture/test_authorization_gate.py. These tests cover the parts that gate
doesn't reach: building the RawArtifact and assembling the ScanResult.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import Confidence, Provenance, Source
from services.scanners.base import ScannerAdapter

NOW = datetime.now(UTC)


def _authorization(target: str = "172.20.0.0/16") -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=[target],
        granted_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
    )


class _StubAdapter(ScannerAdapter):
    """A minimal concrete adapter for exercising the base class alone."""

    name = "stub"
    version_command = ["stub", "--version"]
    content_type = "text/plain"

    def __init__(self, output: str = "stub output") -> None:
        self._output = output

    def is_available(self) -> bool:
        return True

    def _execute(self, request: ScanRequest) -> str:
        return self._output

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return (
            Observation(
                observation_id="obs-stub-001",
                engagement_id=request.authorization.engagement_id,
                scanner=self.name,
                kind=ObservationKind.HOST_UP,
                subject="172.20.1.10",
                attributes={},
                artifact_id=artifact.artifact_id,
                observed_at=artifact.captured_at,
                provenance=Provenance(
                    source=Source.SCANNER, confidence=Confidence.HIGH, retrieved_at=NOW
                ),
            ),
        )


def test_scan_returns_a_scan_result_whose_observations_reference_its_artifact() -> None:
    adapter = _StubAdapter()
    request = ScanRequest(target="172.20.1.10", authorization=_authorization())

    result = adapter.scan(request)

    assert result.artifact.content == "stub output"
    assert result.artifact.scanner == "stub"
    assert len(result.observations) == 1
    assert result.observations[0].artifact_id == result.artifact.artifact_id


def test_artifact_id_is_content_addressed_and_stable() -> None:
    adapter = _StubAdapter(output="identical output")
    request = ScanRequest(target="172.20.1.10", authorization=_authorization())

    first = adapter.scan(request)
    second = adapter.scan(request)

    assert first.artifact.artifact_id == second.artifact.artifact_id
    assert first.artifact.artifact_id.startswith("sha256:")


def test_different_output_produces_a_different_artifact_id() -> None:
    request = ScanRequest(target="172.20.1.10", authorization=_authorization())

    result_a = _StubAdapter(output="output A").scan(request)
    result_b = _StubAdapter(output="output B").scan(request)

    assert result_a.artifact.artifact_id != result_b.artifact.artifact_id


def test_artifact_id_is_namespaced_by_scanner_name() -> None:
    class _OtherAdapter(_StubAdapter):
        name = "other"

    request = ScanRequest(target="172.20.1.10", authorization=_authorization())

    stub_result = _StubAdapter(output="same bytes").scan(request)
    other_result = _OtherAdapter(output="same bytes").scan(request)

    assert stub_result.artifact.artifact_id != other_result.artifact.artifact_id


def test_default_captured_at_is_timezone_aware() -> None:
    adapter = _StubAdapter()
    request = ScanRequest(target="172.20.1.10", authorization=_authorization())

    result = adapter.scan(request)

    assert result.artifact.captured_at.tzinfo is not None
