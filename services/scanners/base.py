"""
Scanner adapter interface.

Every scanner integration implements ScannerAdapter. The contract:

  1. Adapters NEVER scan without an authorization record. Enforced here, not by callers.
  2. Adapters invoke tools as subprocesses or containers and parse their output.
     We do not vendor or link scanner source code.
  3. Adapters emit Observation objects from packages.schema. Raw tool output is
     preserved as a RawArtifact for provenance.
  4. Adapters do not enrich. Severity, EPSS and scoring belong to services.enrichment.

Adapters must be constructible with no arguments — tests/architecture discovers
every subclass by reflection and instantiates it to prove the authorization gate
holds.

See docs/01-open-source-policy.md before adding an adapter for a new tool.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import Observation, RawArtifact, ScanResult

__all__ = [
    "Authorization",
    "AuthorizationError",
    "Observation",
    "RawArtifact",
    "ScanRequest",
    "ScanResult",
    "ScannerAdapter",
    "ScannerUnavailableError",
]


class AuthorizationError(Exception):
    """Raised when a scan is attempted without valid authorization."""


class ScannerUnavailableError(Exception):
    """Raised when the scanner's underlying tool is not installed or runnable.

    Permanent by nature: a binary that is missing when the job starts will
    still be missing on a retry, so callers must not re-attempt the scan.
    """


class ScannerAdapter(ABC):
    """Base for all scanner integrations."""

    name: str
    version_command: list[str]
    content_type: str

    def scan(self, request: ScanRequest) -> ScanResult:
        """Entry point. Do not override — override _execute, _parse and _captured_at."""
        if not request.authorization.permits(request.target):
            raise AuthorizationError(
                f"No valid authorization for {request.target!r}. "
                f"Scans require an authorization record covering the target."
            )
        raw = self._execute(request)
        artifact = self._artifact(raw)
        return ScanResult(artifact=artifact, observations=self._parse(artifact, request))

    def _artifact(self, raw: str) -> RawArtifact:
        """Build the RawArtifact this run produced.

        The id is content-addressed (sha256 of the scanner name, content type and raw
        content), so re-ingesting byte-identical output is naturally idempotent rather
        than an accidental collision.
        """
        digest = hashlib.sha256(
            f"{self.name}\x00{self.content_type}\x00".encode() + raw.encode("utf-8")
        ).hexdigest()
        return RawArtifact(
            artifact_id=f"sha256:{digest}",
            scanner=self.name,
            content=raw,
            content_type=self.content_type,
            captured_at=self._captured_at(raw),
        )

    def _captured_at(self, raw: str) -> datetime:
        """When this run's output was produced.

        Default is the wall clock at parse time. Override when the tool's own output
        carries a timestamp — doing so lets _parse derive every timestamp it needs from
        its inputs alone, which is what keeps _parse a pure, replayable function.
        """
        return datetime.now(UTC)

    @abstractmethod
    def _execute(self, request: ScanRequest) -> str:
        """Invoke the tool. Return its raw output."""

    @abstractmethod
    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        """Convert a captured artifact into Observation objects.

        Must be a pure function of (artifact, request): same inputs, byte-identical
        output, every time. No wall-clock reads, no random ids, no iteration order that
        depends on dict/set internals — this is what lets tests/fixtures/observations/
        stand in for a real scan in every layer above collection.

        Every returned Observation.artifact_id must equal artifact.artifact_id.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Is the tool installed and runnable?"""
