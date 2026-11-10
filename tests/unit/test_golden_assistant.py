"""The Layer 4 golden set (evals/golden/*.jsonl) and its generator.

The set is fixture-derived and auto-generated: these tests check that it is current,
well-formed, and that every reference resolves to a record in the fixture engagement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evals.assistant_eval import load_golden, mentions, validate_item
from evals.scripts.build_assistant_golden import (
    CATEGORIES,
    FOREIGN_ADDRESSES,
    FOREIGN_CVES,
    GOLDEN_DIR,
    MANIFEST_NAME,
    Engagement,
    absent_from_engagement,
    build,
    chokepoint_ref,
    finding_ref,
    golden_sha256,
    load_engagement,
    main,
    obs_ref,
    path_ref,
    stale_files,
)


@pytest.fixture(scope="module")
def built() -> dict[str, str]:
    return build()


@pytest.fixture(scope="module")
def engagement() -> Engagement:
    return load_engagement()


@pytest.fixture(scope="module")
def items() -> list[dict[str, Any]]:
    return load_golden()


@pytest.fixture(scope="module")
def records(engagement: Engagement) -> dict[str, str]:
    """{document id: serialised record} for every citable record in the engagement."""
    out: dict[str, str] = {}
    for obs in engagement.observations:
        out[obs_ref(obs)] = obs.model_dump_json()
    for finding in engagement.findings:
        out[finding_ref(finding.finding_id)] = finding.model_dump_json()
    for path in engagement.graph.paths:
        out[path_ref(path.path_id)] = path.model_dump_json()
    for cp in engagement.graph.chokepoints:
        # The count is derived from the record, not stored in it.
        out[chokepoint_ref(cp.finding_id)] = (
            cp.model_dump_json() + f" paths_broken_count {len(cp.paths_broken)}"
        )
    out[engagement.topology.topology_id] = engagement.topology.model_dump_json()
    return out


class TestGenerator:
    def test_regeneration_is_a_no_op(self, built: dict[str, str]) -> None:
        assert stale_files(built, GOLDEN_DIR) == [], (
            "evals/golden assistant files are stale; rerun "
            "python evals/scripts/build_assistant_golden.py"
        )

    def test_deterministic(self, built: dict[str, str]) -> None:
        assert build() == built

    def test_check_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--check"]) == 0
        assert "current" in capsys.readouterr().out

    def test_check_flag_detects_drift(self, tmp_path: Path, built: dict[str, str]) -> None:
        for name, content in built.items():
            (tmp_path / name).write_text(content, encoding="utf-8")
        (tmp_path / "adversarial.jsonl").write_text("", encoding="utf-8")
        assert main(["--check", "--out-dir", str(tmp_path)]) == 1

    def test_manifest_counts_and_digest(self, built: dict[str, str]) -> None:
        manifest = json.loads(built[MANIFEST_NAME])
        for category in CATEGORIES:
            lines = built[f"{category}.jsonl"].splitlines()
            assert manifest["counts"][category] == len(lines)
        assert manifest["counts"]["total"] == sum(manifest["counts"][c] for c in CATEGORIES)
        assert manifest["golden_sha256"] == golden_sha256()
        assert "FIXTURE-DERIVED, AUTO-GENERATED" in manifest["provenance"]

    def test_absence_guard_raises_when_present(self, engagement: Engagement) -> None:
        with pytest.raises(ValueError, match="present"):
            absent_from_engagement(engagement, ["CVE-2022-22947"])
        absent_from_engagement(engagement, [*FOREIGN_ADDRESSES, *FOREIGN_CVES])


class TestGoldenFiles:
    def test_every_category_has_items(self, items: list[dict[str, Any]]) -> None:
        for category in CATEGORIES:
            assert any(i["category"] == category for i in items), category

    def test_schema(self, items: list[dict[str, Any]]) -> None:
        problems = {i["id"]: validate_item(i) for i in items}
        assert {k: v for k, v in problems.items() if v} == {}

    def test_ids_unique_and_prefixed(self, items: list[dict[str, Any]]) -> None:
        ids = [i["id"] for i in items]
        assert len(ids) == len(set(ids))
        for item in items:
            assert item["id"].startswith(item["category"] + "-")

    def test_provenance_fields(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            assert item["source"] == "fixture"
            assert item["lab_configuration"] == "baseline"
            assert item["verified_by"] == "generated:evals/scripts/build_assistant_golden.py"

    def test_adversarial_items_expect_refusal(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            assert item["expect_refusal"] == (item["category"] == "adversarial"), item["id"]

    def test_required_refs_resolve_to_engagement_records(
        self, items: list[dict[str, Any]], records: dict[str, str]
    ) -> None:
        missing = {
            i["id"]: [r for r in i["required_refs"] if r not in records]
            for i in items
            if any(r not in records for r in i["required_refs"])
        }
        assert missing == {}

    def test_must_mention_is_in_the_referenced_records(
        self, items: list[dict[str, Any]], records: dict[str, str]
    ) -> None:
        """Every expected entity is carried by one of the item's own records, so no
        reference answer adds a fact the engagement does not hold."""
        gaps: dict[str, list[str]] = {}
        for item in items:
            texts = [records[r] for r in item["required_refs"]]
            aliases = item["must_mention_aliases"]
            absent = [
                e
                for e in item["must_mention"]
                if not any(mentions(t, e, aliases.get(e, ())) for t in texts)
            ]
            if absent:
                gaps[item["id"]] = absent
        assert gaps == {}

    def test_refusal_items_name_nothing_the_engagement_holds(
        self, items: list[dict[str, Any]], engagement: Engagement
    ) -> None:
        """Absent-data items ("what evidence for X", "which hosts have X", "what runs on
        IP") must name a CVE or address the engagement does not hold. Out-of-scope and
        unsupported-fact asks may name real hosts and CVEs; the ask itself is the point."""
        import re

        known = {c for f in engagement.findings for c in f.cve_ids}
        absent_data = [
            i
            for i in items
            if i["expect_refusal"]
            and re.match(r"(What evidence|Which hosts|What services)", i["question"])
        ]
        assert len(absent_data) >= 10
        for item in absent_data:
            cves = set(re.findall(r"CVE-\d{4}-\d{4,7}", item["question"]))
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", item["question"])
            assert not cves & known, item["id"]
            absent_from_engagement(engagement, [*cves, *ips])


@pytest.mark.parametrize("category", CATEGORIES)
def test_jsonl_lines_are_lf_and_parse(category: str) -> None:
    raw = (GOLDEN_DIR / f"{category}.jsonl").read_bytes().replace(b"\r\n", b"\n")
    for line in raw.decode("utf-8").splitlines():
        assert json.loads(line)["category"] == category
