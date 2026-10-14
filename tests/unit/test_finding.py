from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packages.schema.models.asset import Asset, Service
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


def _prov(source: Source = Source.CVE_ORG) -> Provenance:
    return Provenance(source=source, confidence=Confidence.HIGH, retrieved_at=NOW)


def _finding() -> Finding:
    return Finding(
        finding_id="fnd-001",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nmap",
        cve_ids=["CVE-2021-41773"],
        title="Apache path traversal",
        description="Apache 2.4.49 path traversal",
        observation_ids=["obs-001"],
        detected_at=NOW,
    )


def test_service_is_typed_not_a_dict() -> None:
    svc = Service(port=80, name="http", product="apache", version="2.4.49")
    assert svc.protocol == "tcp"
    assert svc.port == 80


def test_service_rejects_out_of_range_port() -> None:
    with pytest.raises(ValidationError):
        Service(port=70000)


def test_asset_holds_typed_services() -> None:
    asset = Asset(
        asset_id="ast-001",
        engagement_id="eng-001",
        ip="172.20.1.10",
        services=[Service(port=80, name="http")],
    )
    assert asset.services[0].port == 80
    assert asset.aliases == []


def test_finding_traces_to_observations() -> None:
    assert _finding().observation_ids == ["obs-001"]


def test_finding_requires_at_least_one_observation() -> None:
    with pytest.raises(ValidationError, match="observation"):
        Finding(
            finding_id="fnd-002",
            engagement_id="eng-001",
            asset_id="ast-001",
            scanner="nmap",
            observation_ids=[],
            detected_at=NOW,
        )


def test_finding_normalizes_cve_ids_to_uppercase_and_deduplicates() -> None:
    finding = Finding(
        finding_id="fnd-003",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nuclei",
        cve_ids=["cve-2021-44228", "CVE-2021-44228", "cve-2024-3400"],
        observation_ids=["obs-001"],
        detected_at=NOW,
    )
    assert finding.cve_ids == ["CVE-2021-44228", "CVE-2024-3400"]


def test_finding_rejects_malformed_cve_ids() -> None:
    with pytest.raises(ValidationError, match="invalid CVE ID 'GHSA-jfh8-c2jp-5v3q'"):
        Finding(
            finding_id="fnd-004",
            engagement_id="eng-001",
            asset_id="ast-001",
            scanner="nuclei",
            cve_ids=["GHSA-jfh8-c2jp-5v3q"],
            observation_ids=["obs-001"],
            detected_at=NOW,
        )

    with pytest.raises(ValidationError, match="invalid CVE ID 'CWE-502'"):
        Finding(
            finding_id="fnd-005",
            engagement_id="eng-001",
            asset_id="ast-001",
            scanner="nuclei",
            cve_ids=["CWE-502"],
            observation_ids=["obs-001"],
            detected_at=NOW,
        )


@pytest.mark.parametrize(
    "raw",
    [
        "CVE-٢٠٢١-44228",  # Arabic-Indic digits: \d matches them
        "CVE-2021-４４２２８",  # fullwidth digits
        "CVE-2021-44228\nCVE-2014-0160",  # embedded newline
    ],
)
def test_finding_rejects_non_ascii_digit_cve_ids(raw: str) -> None:
    with pytest.raises(ValidationError, match="invalid CVE ID"):
        Finding(
            finding_id="fnd-007",
            engagement_id="eng-001",
            asset_id="ast-001",
            scanner="nuclei",
            cve_ids=[raw],
            observation_ids=["obs-001"],
            detected_at=NOW,
        )


def test_finding_allows_empty_cve_ids() -> None:
    finding = Finding(
        finding_id="fnd-006",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nmap",
        cve_ids=[],
        observation_ids=["obs-001"],
        detected_at=NOW,
    )
    assert finding.cve_ids == []


def test_enriched_field_carries_value_and_provenance_together() -> None:
    enriched = EnrichedFinding(
        finding=_finding(),
        fields={
            "cvss_base": Attributed[EnrichmentValue](value=7.5, provenance=_prov()),
            "kev_listed": Attributed[EnrichmentValue](value=True, provenance=_prov(Source.KEV)),
        },
    )
    assert enriched.fields["cvss_base"].value == 7.5
    assert enriched.fields["kev_listed"].provenance.source is Source.KEV


def test_enriched_finding_has_no_score_until_one_is_computed() -> None:
    enriched = EnrichedFinding(finding=_finding(), fields={})
    assert enriched.ers is None


def test_enriched_finding_accepts_a_score() -> None:
    from packages.schema.models.provenance import Confidence, Provenance, Source
    from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

    finding = Finding(
        finding_id="fnd-001",
        engagement_id="eng-001",
        asset_id="ast-001",
        scanner="nmap",
        observation_ids=["obs-001"],
        detected_at=NOW,
    )
    prov = Provenance(source=Source.EPSS, confidence=Confidence.HIGH, retrieved_at=NOW)
    components = [
        ScoreComponent(
            name="epss",
            value=0.8,
            weight=0.5,
            explanation="epss contributed 0.8",
            provenance=prov,
        ),
    ]
    enriched = EnrichedFinding(
        finding=finding,
        fields={},
        ers=ExposureRiskScore(value=0.4, components=components),
    )
    assert enriched.ers is not None
    assert "epss" in enriched.ers.explain()
