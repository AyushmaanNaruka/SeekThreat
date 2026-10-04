"""Tests for local-mirror wiring and honest handling of missing/empty mirrors.

Guards two review findings on PR #17:
1. `FusionEngine` / `EnrichmentService` accept a `cache_dir` and load each source
   from the file name `SourceSynchronizer` writes for it.
2. A missing or empty KEV mirror must not be reported as a confident negative
   ("not in KEV", Source.KEV / Confidence.HIGH). KEV status is unknown in that case.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from packages.schema.models.provenance import Confidence, Source
from services.enrichment.ers import calculate_ers
from services.enrichment.fusion import FusionEngine
from services.enrichment.service import EnrichmentService
from services.enrichment.sources import CISAKevSource, CVEOrgSource, FirstEPSSSource
from services.enrichment.sources.sync import MIRROR_FILENAMES, SourceSynchronizer
from tests.fixtures.findings.baseline_findings import (
    FINDING_LOG4SHELL,
    FINDING_NON_KEV_MODERATE,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enrichment"


@pytest.fixture
def mirror_dir(tmp_path: Path) -> Path:
    """A cache dir laid out exactly as SourceSynchronizer writes it."""
    syncer = SourceSynchronizer(cache_dir=tmp_path)
    shutil.copy(FIXTURES_DIR / "cve_org_sample.json", syncer.get_source_path(Source.CVE_ORG))
    shutil.copy(FIXTURES_DIR / "cisa_kev_sample.json", syncer.get_source_path(Source.KEV))
    shutil.copy(FIXTURES_DIR / "epss_v4_sample.json", syncer.get_source_path(Source.EPSS))
    return tmp_path


class TestMirrorFilenames:
    def test_synchronizer_and_fusion_share_one_filename_map(self, tmp_path: Path) -> None:
        syncer = SourceSynchronizer(cache_dir=tmp_path)
        for source, filename in MIRROR_FILENAMES.items():
            assert syncer.get_source_path(source) == tmp_path / filename


class TestCacheDirWiring:
    def test_fusion_engine_loads_sources_from_cache_dir(self, mirror_dir: Path) -> None:
        engine = FusionEngine(cache_dir=mirror_dir)
        assert engine.cve_org.is_loaded
        assert engine.cisa_kev.is_loaded
        assert engine.first_epss.is_loaded

        fields = engine.fuse(FINDING_LOG4SHELL)
        assert fields["cvss_score"].provenance.source == Source.CVE_ORG
        assert fields["in_kev"].value is True
        assert fields["epss_score"].provenance.source == Source.EPSS

    def test_enrichment_service_accepts_cache_dir(self, mirror_dir: Path) -> None:
        service = EnrichmentService(cache_dir=mirror_dir)
        enriched = service.enrich_finding(FINDING_LOG4SHELL)
        assert enriched.fields["cvss_score"].provenance.source == Source.CVE_ORG
        assert enriched.fields["in_kev"].value is True

    def test_enrichment_service_cache_dir_and_engine_are_exclusive(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="cache_dir"):
            EnrichmentService(fusion_engine=FusionEngine(), cache_dir=tmp_path)

    def test_explicit_source_overrides_cache_dir(self, mirror_dir: Path) -> None:
        explicit = CISAKevSource()
        engine = FusionEngine(cisa_kev=explicit, cache_dir=mirror_dir)
        assert engine.cisa_kev is explicit
        assert engine.cve_org.is_loaded

    def test_no_cache_dir_means_sources_unloaded(self) -> None:
        engine = FusionEngine()
        assert not engine.cve_org.is_loaded
        assert not engine.cisa_kev.is_loaded
        assert not engine.first_epss.is_loaded

    def test_empty_cache_dir_means_sources_unloaded(self, tmp_path: Path) -> None:
        engine = FusionEngine(cache_dir=tmp_path)
        assert not engine.cve_org.is_loaded
        assert not engine.cisa_kev.is_loaded
        assert not engine.first_epss.is_loaded


class TestIsLoaded:
    def test_loaded_from_fixture(self) -> None:
        assert CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json").is_loaded
        assert CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json").is_loaded
        assert FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json").is_loaded

    def test_missing_file_is_not_loaded(self, tmp_path: Path) -> None:
        assert not CISAKevSource(cache_file=tmp_path / "nope.json").is_loaded

    def test_empty_catalog_is_not_loaded(self, tmp_path: Path) -> None:
        path = tmp_path / "cisa_kev.json"
        path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
        assert not CISAKevSource(cache_file=path).is_loaded


class TestUnloadedKevIsUnknownNotNegative:
    def test_unloaded_kev_lookup_returns_none(self) -> None:
        assert CISAKevSource().lookup("CVE-2020-7699") is None

    def test_unloaded_kev_emits_unknown_in_kev(self) -> None:
        engine = FusionEngine(
            cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
            first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
        )
        fields = engine.fuse(FINDING_NON_KEV_MODERATE)
        attr = fields["in_kev"]
        assert attr.value is None
        assert attr.provenance.source == Source.DERIVED
        assert attr.provenance.confidence == Confidence.LOW
        assert "KEV mirror not loaded; KEV status unknown" in (attr.provenance.note or "")

    def test_empty_kev_catalog_emits_unknown_in_kev(self, tmp_path: Path) -> None:
        path = tmp_path / "cisa_kev.json"
        path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
        engine = FusionEngine(cisa_kev=CISAKevSource(cache_file=path))
        attr = engine.fuse(FINDING_LOG4SHELL)["in_kev"]
        assert attr.value is None
        assert attr.provenance.source == Source.DERIVED

    def test_ers_says_unknown_not_unlisted_when_kev_unloaded(self) -> None:
        engine = FusionEngine()
        ers = calculate_ers(engine.fuse(FINDING_NON_KEV_MODERATE))
        kev = next(c for c in ers.components if "KEV" in c.name)
        assert kev.value == 0.0
        assert "unknown" in kev.explanation.lower()
        assert "not listed" not in kev.explanation.lower()
        assert kev.provenance.source == Source.DERIVED
        assert kev.provenance.confidence == Confidence.LOW

    def test_loaded_kev_still_gives_confident_negative(self) -> None:
        engine = FusionEngine(
            cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
        )
        attr = engine.fuse(FINDING_NON_KEV_MODERATE)["in_kev"]
        assert attr.value is False
        assert attr.provenance.source == Source.KEV
        assert attr.provenance.confidence == Confidence.HIGH
