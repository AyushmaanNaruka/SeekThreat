"""Unit tests for Task A-3: Fair NVD-only baseline KEV parsing and crediting.

Verifies:
1. NVDSource parses CISA KEV fields (cisaExploitAdd, cisaActionDue, cisaRequiredAction, cisaVulnerabilityName).
2. FusionEngine with NVD-only baseline credits KEV detection when NVD record carries cisaExploitAdd.
3. Baseline engine returns in_kev = False (Source.NVD, Confidence.HIGH) when NVD record lacks KEV fields.
4. Baseline engine returns in_kev = None (DERIVED, Confidence.LOW) when CVE is not in NVD.
5. evals/enrichment_coverage._signal_mirror_loaded recognizes baseline engine as loaded for in_kev.
6. evals/enrichment_coverage._signal_state classifies in_kev from Source.NVD as positive.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evals.enrichment_coverage import _signal_mirror_loaded, _signal_state, build_engines
from packages.schema.models.finding import Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from services.enrichment.fusion import FusionEngine
from services.enrichment.sources.cisa_kev import CISAKevSource
from services.enrichment.sources.cve_org import CVEOrgSource
from services.enrichment.sources.epss import FirstEPSSSource
from services.enrichment.sources.secondary import NVDRecord, NVDSource

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def temp_nvd_cache(tmp_path: Path) -> Path:
    data = {
        "CVE-2021-44228": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T00:00:00.000",
            "lastModified": "2021-12-12T00:00:00.000",
            "vulnStatus": "Analyzed",
            "cisaExploitAdd": "2021-12-10",
            "cisaActionDue": "2021-12-24",
            "cisaRequiredAction": "Apply patch immediately.",
            "cisaVulnerabilityName": "Apache Log4j Remote Code Execution Vulnerability",
            "descriptions": [{"lang": "en", "value": "Log4Shell vulnerability"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseScore": 10.0,
                    }
                }]
            },
        },
        "CVE-2020-0001": {
            "id": "CVE-2020-0001",
            "published": "2020-01-01T00:00:00.000",
            "lastModified": "2020-01-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            # No cisaExploitAdd field
            "descriptions": [{"lang": "en", "value": "Non-KEV test vulnerability"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "baseScore": 7.5,
                    }
                }]
            },
        },
    }
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TestNVDKEVParsing:
    def test_nvd_source_parses_kev_fields(self, temp_nvd_cache: Path) -> None:
        source = NVDSource(cache_file=temp_nvd_cache)
        rec = source.lookup("CVE-2021-44228")
        assert rec is not None
        assert rec.cisa_exploit_add == "2021-12-10"
        assert rec.cisa_action_due == "2021-12-24"
        assert rec.cisa_required_action == "Apply patch immediately."
        assert rec.cisa_vulnerability_name == "Apache Log4j Remote Code Execution Vulnerability"

    def test_nvd_source_handles_absent_kev_fields(self, temp_nvd_cache: Path) -> None:
        source = NVDSource(cache_file=temp_nvd_cache)
        rec = source.lookup("CVE-2020-0001")
        assert rec is not None
        assert rec.cisa_exploit_add is None
        assert rec.cisa_action_due is None


class TestFairNVDBaselineInKEV:
    def test_baseline_credits_nvd_for_kev_hit(self, temp_nvd_cache: Path) -> None:
        nvd_source = NVDSource(cache_file=temp_nvd_cache)
        baseline_engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=None),
            cisa_kev=CISAKevSource(cache_file=None),
            first_epss=FirstEPSSSource(cache_file=None),
            nvd=nvd_source,
        )

        finding = Finding(
            finding_id="fnd-1",
            engagement_id="eng-1",
            asset_id="host:192.0.2.1",
            cve_ids=["CVE-2021-44228"],
            scanner="nvd",
            severity="critical",
            observation_ids=["obs-1"],
            detected_at=datetime.now(UTC),
        )
        fields = baseline_engine.fuse(finding)

        assert "in_kev" in fields
        in_kev_attr = fields["in_kev"]
        assert in_kev_attr.value is True
        assert in_kev_attr.provenance.source == Source.NVD
        assert in_kev_attr.provenance.confidence == Confidence.HIGH
        assert fields["kev_date_added"].value == "2021-12-10"

    def test_baseline_reports_negative_when_nvd_lacks_kev(self, temp_nvd_cache: Path) -> None:
        nvd_source = NVDSource(cache_file=temp_nvd_cache)
        baseline_engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=None),
            cisa_kev=CISAKevSource(cache_file=None),
            first_epss=FirstEPSSSource(cache_file=None),
            nvd=nvd_source,
        )

        finding = Finding(
            finding_id="fnd-2",
            engagement_id="eng-1",
            asset_id="host:192.0.2.1",
            cve_ids=["CVE-2020-0001"],
            scanner="nvd",
            severity="high",
            observation_ids=["obs-1"],
            detected_at=datetime.now(UTC),
        )
        fields = baseline_engine.fuse(finding)

        assert "in_kev" in fields
        in_kev_attr = fields["in_kev"]
        assert in_kev_attr.value is False
        assert in_kev_attr.provenance.source == Source.NVD
        assert in_kev_attr.provenance.confidence == Confidence.HIGH

    def test_baseline_reports_unknown_when_cve_not_in_nvd(self, temp_nvd_cache: Path) -> None:
        nvd_source = NVDSource(cache_file=temp_nvd_cache)
        baseline_engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=None),
            cisa_kev=CISAKevSource(cache_file=None),
            first_epss=FirstEPSSSource(cache_file=None),
            nvd=nvd_source,
        )

        finding = Finding(
            finding_id="fnd-3",
            engagement_id="eng-1",
            asset_id="host:192.0.2.1",
            cve_ids=["CVE-1999-9999"],
            scanner="nvd",
            severity="low",
            observation_ids=["obs-1"],
            detected_at=datetime.now(UTC),
        )
        fields = baseline_engine.fuse(finding)

        assert "in_kev" in fields
        in_kev_attr = fields["in_kev"]
        assert in_kev_attr.value is None
        assert in_kev_attr.provenance.source == Source.DERIVED
        assert in_kev_attr.provenance.confidence == Confidence.LOW


class TestCoverageHarnessSignalHelpers:
    def test_signal_mirror_loaded_true_for_baseline_when_nvd_loaded(self, temp_nvd_cache: Path) -> None:
        nvd_source = NVDSource(cache_file=temp_nvd_cache)
        engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=None),
            cisa_kev=CISAKevSource(cache_file=None),
            first_epss=FirstEPSSSource(cache_file=None),
            nvd=nvd_source,
        )
        assert _signal_mirror_loaded("in_kev", engine) is True

    def test_signal_state_recognizes_source_nvd(self) -> None:
        fields = {
            "in_kev": Attributed[bool](
                value=True,
                provenance=Provenance(
                    source=Source.NVD,
                    confidence=Confidence.HIGH,
                    retrieved_at=datetime.now(UTC),
                ),
            )
        }
        assert _signal_state("in_kev", fields) == "positive"
