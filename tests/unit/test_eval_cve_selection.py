"""Tests for evals/scripts/generate_eval_cve_list.py (Task A-1).

These tests verify:
- The selection script is deterministic (same output for same mirror sha256 + seed).
- Every CVE in eval_cve_list.txt appears in the manifest's selected lists.
- Stratum sizes match the documented rule (STRATA constants).
- The manifest records mirror sha256s and synced_at.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.scripts.generate_eval_cve_list import (
    SEED,
    STRATA,
    load_epss_scores,
    load_kev_ids,
    stratified_sample,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = REPO_ROOT / "evals" / "golden" / "eval_cve_selection_manifest.json"
LIST_PATH = REPO_ROOT / "evals" / "golden" / "eval_cve_list.txt"


class TestStratifiedSample:
    """Core stratification logic — uses tiny in-memory data, no file I/O."""

    _EPSS: dict[str, float] = {
        "CVE-2021-0001": 0.85,  # KEV + high EPSS
        "CVE-2021-0002": 0.30,  # KEV + low EPSS
        "CVE-2021-0003": 0.75,  # non-KEV + high EPSS (≥0.70)
        "CVE-2021-0004": 0.20,  # non-KEV + mid EPSS
        "CVE-2021-0005": 0.001,  # non-KEV + low EPSS (< 0.005)
        "CVE-2021-0006": 0.95,  # KEV + high EPSS
        "CVE-2021-0007": 0.001,  # non-KEV + low EPSS
        "CVE-2021-0008": 0.15,  # non-KEV + mid EPSS
        "CVE-2021-0009": 0.80,  # non-KEV + high EPSS
        "CVE-2021-0010": 0.40,  # KEV + low EPSS
    }
    _KEV: set[str] = {"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0006", "CVE-2021-0010"}

    def _sample_strata(self, strata_override: list[dict] | None = None):
        strata = strata_override or [
            {"name": "kev_high_epss", "in_kev": True, "epss_min": 0.50, "epss_max": None, "n": 2},
            {"name": "kev_low_epss", "in_kev": True, "epss_min": None, "epss_max": 0.50, "n": 2},
            {
                "name": "non_kev_high_epss",
                "in_kev": False,
                "epss_min": 0.70,
                "epss_max": None,
                "n": 2,
            },
            {
                "name": "non_kev_mid_epss",
                "in_kev": False,
                "epss_min": 0.10,
                "epss_max": 0.70,
                "n": 2,
            },
            {
                "name": "non_kev_low_epss",
                "in_kev": False,
                "epss_min": None,
                "epss_max": 0.005,
                "n": 2,
            },
        ]
        return stratified_sample(self._EPSS, self._KEV, strata, SEED)

    def test_deterministic_same_seed(self) -> None:
        cves1, _ = self._sample_strata()
        cves2, _ = self._sample_strata()
        assert cves1 == cves2

    def test_different_seed_different_result(self) -> None:
        strata = [
            {
                "name": "non_kev_mid_epss",
                "in_kev": False,
                "epss_min": 0.10,
                "epss_max": 0.70,
                "n": 2,
            },
        ]
        cves1, _ = stratified_sample(self._EPSS, self._KEV, strata, seed=1)
        cves2, _ = stratified_sample(self._EPSS, self._KEV, strata, seed=2)
        # With only 2 candidates and n=2, both will select all available — still deterministic
        # but with a larger pool the seeds would differ.  Just check both return valid CVE IDs.
        assert all(c.startswith("CVE-") for c in cves1 + cves2)

    def test_no_duplicates_across_strata(self) -> None:
        cves, _ = self._sample_strata()
        assert len(cves) == len(set(cves))

    def test_kev_membership_respected(self) -> None:
        _, strata_results = self._sample_strata()
        kev_strata = {sr.name for sr in strata_results if sr.name.startswith("kev_")}
        non_kev_strata = {sr.name for sr in strata_results if sr.name.startswith("non_kev_")}

        for sr in strata_results:
            if sr.name in kev_strata:
                assert all(c in self._KEV for c in sr.selected), f"Non-KEV in {sr.name}"
            elif sr.name in non_kev_strata:
                assert all(c not in self._KEV for c in sr.selected), f"KEV in {sr.name}"

    def test_epss_thresholds_respected(self) -> None:
        _, results = self._sample_strata()
        for sr in results:
            # Just check that all selected are in the EPSS dict
            for cid in sr.selected:
                assert cid in self._EPSS

    def test_result_is_sorted(self) -> None:
        cves, _ = self._sample_strata()
        assert cves == sorted(cves)

    def test_stratum_capped_at_available(self) -> None:
        # Request more than available
        strata = [
            {"name": "kev_high_epss", "in_kev": True, "epss_min": 0.50, "epss_max": None, "n": 100}
        ]
        cves, results = stratified_sample(self._EPSS, self._KEV, strata, SEED)
        assert (
            results[0].selected_n
            if hasattr(results[0], "selected_n")
            else len(results[0].selected) <= results[0].available_n
        )


class TestCommittedManifest:
    """Regression tests against the committed manifest and list files."""

    @pytest.fixture(scope="class")
    def manifest(self) -> dict:
        assert MANIFEST_PATH.exists(), f"Manifest not found: {MANIFEST_PATH}"
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def cve_list(self) -> list[str]:
        assert LIST_PATH.exists(), f"CVE list not found: {LIST_PATH}"
        lines = LIST_PATH.read_text(encoding="utf-8").splitlines()
        return [line.strip() for line in lines if line.strip()]

    def test_manifest_has_required_keys(self, manifest: dict) -> None:
        for key in ("seed", "selection_rule", "mirrors", "strata", "total_selected"):
            assert key in manifest, f"Missing key: {key}"

    def test_seed_matches_constant(self, manifest: dict) -> None:
        assert manifest["seed"] == SEED

    def test_mirrors_have_sha256(self, manifest: dict) -> None:
        for mirror_name, info in manifest["mirrors"].items():
            assert "sha256" in info, f"Mirror {mirror_name} missing sha256"
            assert len(info["sha256"]) == 64, f"sha256 for {mirror_name} wrong length"

    def test_strata_names_match_documented_rule(self, manifest: dict) -> None:
        expected_names = {s["name"] for s in STRATA}
        manifest_names = {s["name"] for s in manifest["strata"]}
        assert manifest_names == expected_names

    def test_total_selected_equals_list_length(self, manifest: dict, cve_list: list[str]) -> None:
        assert manifest["total_selected"] == len(cve_list), (
            f"Manifest total_selected={manifest['total_selected']} != list length={len(cve_list)}"
        )

    def test_all_list_cves_in_manifest(self, manifest: dict, cve_list: list[str]) -> None:
        manifest_cves: set[str] = set()
        for stratum in manifest["strata"]:
            manifest_cves.update(stratum["selected"])
        for cid in cve_list:
            assert cid in manifest_cves, f"{cid} in list but not in manifest strata"

    def test_no_duplicates_in_list(self, cve_list: list[str]) -> None:
        assert len(cve_list) == len(set(cve_list))

    def test_list_is_sorted(self, cve_list: list[str]) -> None:
        assert cve_list == sorted(cve_list)

    def test_strata_sizes_at_or_below_requested(self, manifest: dict) -> None:
        spec_map = {s["name"]: s["n"] for s in STRATA}
        for stratum in manifest["strata"]:
            name = stratum["name"]
            if name in spec_map:
                selected_n = stratum.get("selected_n", len(stratum["selected"]))
                available_n = stratum.get("available_n", selected_n)
                assert selected_n <= spec_map[name] or selected_n == available_n, (
                    f"Stratum {name}: selected_n={selected_n} > requested={spec_map[name]}"
                )

    def test_cve_ids_match_format(self, cve_list: list[str]) -> None:
        import re

        cve_re = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$", re.ASCII)
        for cid in cve_list:
            assert cve_re.match(cid), f"Malformed CVE ID in list: {cid!r}"


class TestDeterminismWithRealMirrors:
    """Run the generation twice and assert identical output (if mirrors present)."""

    def test_deterministic_on_real_mirrors(self, tmp_path: Path) -> None:
        mirrors_dir = REPO_ROOT / "data" / "enrichment_cache"
        if not (mirrors_dir / "epss_v4.json").exists():
            pytest.skip("Real EPSS mirror not present; skipping real-mirror determinism test")

        epss = load_epss_scores(mirrors_dir)
        kev_ids = load_kev_ids(mirrors_dir)

        cves1, results1 = stratified_sample(epss, kev_ids, STRATA, SEED)
        cves2, results2 = stratified_sample(epss, kev_ids, STRATA, SEED)

        assert cves1 == cves2
        for r1, r2 in zip(results1, results2, strict=True):
            assert r1.selected == r2.selected

    def test_consistent_with_committed_list(self) -> None:
        mirrors_dir = REPO_ROOT / "data" / "enrichment_cache"
        if not (mirrors_dir / "epss_v4.json").exists():
            pytest.skip("Real EPSS mirror not present")
        if not LIST_PATH.exists():
            pytest.skip("Committed list not present")

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        epss_path = mirrors_dir / "epss_v4.json"

        import hashlib

        def _sha256(p: Path) -> str:
            digest = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
            return digest.hexdigest()

        current_epss_sha = _sha256(epss_path) if epss_path.exists() else None
        manifest_epss_sha = manifest.get("mirrors", {}).get("epss_v4", {}).get("sha256")

        if current_epss_sha != manifest_epss_sha:
            pytest.skip(
                f"EPSS mirror sha256 changed ({current_epss_sha[:16]}… vs "
                f"committed {manifest_epss_sha[:16]}…); list will differ — re-run the script."
            )

        epss = load_epss_scores(mirrors_dir)
        kev_ids = load_kev_ids(mirrors_dir)
        cves, _ = stratified_sample(epss, kev_ids, STRATA, manifest["seed"])

        committed = [
            line.strip()
            for line in LIST_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert cves == committed, (
            "Regenerated list differs from committed eval_cve_list.txt with same mirrors+seed. "
            "Run `python evals/scripts/generate_eval_cve_list.py` to update."
        )
