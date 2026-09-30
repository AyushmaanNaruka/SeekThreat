"""Unit tests and invariant guards for offline mirror isolation.

Guards Rule 5 from services/enrichment/README.md:
"Mirror sources locally. Don't hit APIs on the request path."

This test blocks all outbound socket connections and HTTP client requests,
verifying that EnrichmentService and FusionEngine execute strictly offline
from cached local data without making external network calls.
"""

from __future__ import annotations

import socket
import urllib.request
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.schema.models.finding import EnrichedFinding
from services.enrichment.fusion import FusionEngine
from services.enrichment.service import EnrichmentService
from services.enrichment.sources import CISAKevSource, CVEOrgSource, FirstEPSSSource
from tests.fixtures.findings.baseline_findings import (
    FINDING_APACHE_PATH_TRAVERSAL,
    FINDING_HEURISTIC_NO_CVE,
    FINDING_LOG4SHELL,
    FINDING_NON_KEV_MODERATE,
    FINDING_NVD_UNENRICHED_RECENT,
    FINDING_SPRING_GATEWAY_RCE,
    get_baseline_findings,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


class NetworkAttemptForbiddenError(RuntimeError):
    """Raised whenever code attempts to make a network connection."""


def _forbidden_connect(*args, **kwargs):  # type: ignore[no-untyped-def]
    raise NetworkAttemptForbiddenError(
        "Outbound network connection forbidden during enrichment! "
        "Enrichment must query local offline mirrors only."
    )


@pytest.fixture
def offline_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Monkeypatches socket and standard HTTP mechanisms to forbid network access."""
    # Block low-level socket connections
    monkeypatch.setattr(socket.socket, "connect", _forbidden_connect)
    monkeypatch.setattr(socket, "create_connection", _forbidden_connect)

    # Block urllib
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden_connect)

    # Block requests / httpx if imported
    try:
        import requests

        monkeypatch.setattr(requests.Session, "send", _forbidden_connect)
    except ImportError:
        pass

    try:
        import httpx

        monkeypatch.setattr(httpx.Client, "send", _forbidden_connect)
    except ImportError:
        pass


@pytest.fixture
def offline_enrichment_service() -> EnrichmentService:
    engine = FusionEngine(
        cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
        cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
        first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
    )
    return EnrichmentService(fusion_engine=engine)


class TestOfflineMirrorIsolation:
    """Invariant tests ensuring enrichment never attempts outbound network requests."""

    def test_enrich_finding_executes_with_zero_network_calls(
        self,
        offline_guard: None,
        offline_enrichment_service: EnrichmentService,
    ) -> None:
        """Every baseline finding must enrich cleanly with zero outbound network calls."""
        for finding in get_baseline_findings():
            # If any outbound connection is attempted, NetworkAttemptForbiddenError will be raised
            enriched = offline_enrichment_service.enrich_finding(finding, persist=False)
            assert isinstance(enriched, EnrichedFinding)
            assert enriched.finding.finding_id == finding.finding_id
            assert "cvss_score" in enriched.fields
            assert enriched.ers is not None

    def test_enrich_batch_executes_strictly_offline(
        self,
        offline_guard: None,
        offline_enrichment_service: EnrichmentService,
    ) -> None:
        """Batch enrichment across multiple findings executes without network calls."""
        findings = [
            FINDING_LOG4SHELL,
            FINDING_APACHE_PATH_TRAVERSAL,
            FINDING_SPRING_GATEWAY_RCE,
            FINDING_NVD_UNENRICHED_RECENT,
            FINDING_NON_KEV_MODERATE,
            FINDING_HEURISTIC_NO_CVE,
        ]
        results = offline_enrichment_service.enrich_batch(findings, persist=False)
        assert len(results) == len(findings)

    def test_network_block_fixture_actually_catches_connections(
        self, offline_guard: None
    ) -> None:
        """Guards that our offline test fixture genuinely traps network attempts."""
        with pytest.raises(NetworkAttemptForbiddenError):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("8.8.8.8", 53))
