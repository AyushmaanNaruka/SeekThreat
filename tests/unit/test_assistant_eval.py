"""Metric functions of evals/assistant_eval.py, on plain inputs.

No model and no assistant package are needed, except for the --fake end-to-end smoke at
the bottom, which is skipped until services.assistant's modules exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evals.assistant_eval import (
    HARNESS_BANNER,
    AnswerView,
    aggregate,
    aggregate_by_category,
    context_scores,
    cosine,
    default_outputs,
    generate_markdown_report,
    golden_diagnostics,
    judge_citations,
    judge_prompt,
    main,
    mentions,
    must_mention_recall,
    parse_judge_verdict,
    run_judge,
    score_item,
    validate_item,
)


def _item(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "cve_lookups-001",
        "category": "cve_lookups",
        "question": "Which CVE did nuclei report on 172.20.1.12?",
        "reference_answer": "CVE-2021-23017",
        "required_refs": ["obs:a"],
        "must_mention": ["CVE-2021-23017"],
        "must_mention_aliases": {},
        "expect_refusal": False,
        "lab_configuration": "baseline",
        "source": "fixture",
        "verified_by": "generated:x",
        "verified_at": "2026-11-07",
    }
    base.update(over)
    return base


def _view(**over: Any) -> AnswerView:
    base: dict[str, Any] = {
        "text": "nuclei reported CVE-2021-23017 [cite:obs:a].",
        "refused": False,
        "cited_ids": ("obs:a",),
        "retrieved_ids": ("obs:a", "obs:b"),
        "retrieved_texts": {"obs:a": "nuclei CVE-2021-23017 on 172.20.1.12", "obs:b": "nmap"},
        "checked_entities": ("CVE-2021-23017",),
    }
    base.update(over)
    return AnswerView(**base)


class TestMentions:
    def test_whole_token(self) -> None:
        assert mentions("port 80/tcp", "80")
        assert not mentions("port 8080/tcp", "80")
        assert not mentions("allow", "low")
        assert mentions("confidence LOW.", "low")
        assert not mentions("nginx 11.18.0", "1.18.0")
        assert mentions("nginx 1.18.0.", "1.18.0")
        assert mentions("CVE-2021-23017,", "cve-2021-23017")

    def test_aliases(self) -> None:
        assert mentions("reach 172.20.3.20", "cache-redis", ["172.20.3.20"])
        assert not mentions("reach 172.20.3.2", "cache-redis", ["172.20.3.20"])

    def test_recall(self) -> None:
        aliases = {"bastion-ssh": ["172.20.2.50"]}
        text = "via 172.20.2.50 then dmz-proxy"
        assert must_mention_recall(text, ["bastion-ssh", "dmz-proxy", "low"], aliases) == (
            pytest.approx(2 / 3)
        )
        assert must_mention_recall("x", [], {}) is None


class TestContext:
    def test_precision_recall(self) -> None:
        assert context_scores(["a", "b", "c", "d"], ["a", "x"]) == (0.25, 0.5)

    def test_duplicates_count_once(self) -> None:
        assert context_scores(["a", "a"], ["a"]) == (1.0, 1.0)

    def test_undefined_without_required(self) -> None:
        assert context_scores(["a"], []) == (None, None)

    def test_nothing_retrieved(self) -> None:
        assert context_scores([], ["a"]) == (0.0, 0.0)


class TestCitations:
    def test_required_ref_is_correct(self) -> None:
        out = judge_citations(["obs:a"], [], {"obs:a": "t"}, ["obs:a"], ["CVE-1"], {})
        assert out == [{"doc_id": "obs:a", "valid": True, "relevant": True, "correct": True}]

    def test_retrieved_doc_with_entity_is_correct(self) -> None:
        texts = {"finding:f": "CVE-2021-23017 on host"}
        out = judge_citations(["finding:f"], [], texts, ["obs:a"], ["CVE-2021-23017"], {})
        assert out[0]["correct"]

    def test_retrieved_but_irrelevant(self) -> None:
        out = judge_citations(["obs:b"], [], {"obs:b": "nmap"}, ["obs:a"], ["CVE-1"], {})
        assert out[0] == {"doc_id": "obs:b", "valid": True, "relevant": False, "correct": False}

    def test_invalid_citation(self) -> None:
        out = judge_citations(["obs:z"], ["obs:z"], {"obs:a": "t"}, ["obs:z"], [], {})
        assert out[0]["valid"] is False and out[0]["correct"] is False

    def test_not_retrieved_is_invalid_even_if_unflagged(self) -> None:
        out = judge_citations(["obs:a"], [], {}, ["obs:a"], [], {})
        assert out[0]["valid"] is False

    def test_dedup(self) -> None:
        assert len(judge_citations(["a", "a"], [], {"a": "t"}, ["a"], [], {})) == 1


class TestCosine:
    def test_values(self) -> None:
        assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
        assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
        assert cosine([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)

    def test_degenerate(self) -> None:
        assert cosine([0.0, 0.0], [1.0, 0.0]) is None
        assert cosine([1.0], [1.0, 0.0]) is None
        assert cosine([], []) is None


class TestScoreItem:
    def test_grounded_answer(self) -> None:
        s = score_item(_item(), _view(), latency_s=1.5, relevancy=0.7)
        assert s.faithful and not s.refused
        assert s.context_precision == 0.5 and s.context_recall == 1.0
        assert s.must_mention_recall == 1.0
        assert s.citations[0]["correct"]
        assert s.relevancy == 0.7 and s.latency_s == 1.5

    def test_unsupported_entity_is_unfaithful(self) -> None:
        s = score_item(_item(), _view(unsupported_entities=("10.0.0.1",)), latency_s=0.0)
        assert not s.faithful

    def test_invalid_citation_is_unfaithful(self) -> None:
        view = _view(cited_ids=("obs:zzz",), invalid_citations=("obs:zzz",))
        s = score_item(_item(), view, latency_s=0.0)
        assert not s.faithful and not s.citations[0]["valid"]

    def test_refusal_item(self) -> None:
        item = _item(category="adversarial", required_refs=[], must_mention=[], expect_refusal=True)
        view = _view(text="I don't have that data.", refused=True, cited_ids=())
        s = score_item(item, view, latency_s=0.1, relevancy=0.9)
        assert s.refused and s.faithful
        assert s.must_mention_recall is None and s.context_recall is None
        assert s.relevancy is None and s.citations == []


class TestAggregate:
    def _scores(self) -> list[Any]:
        ok = score_item(_item(), _view(), latency_s=1.0, relevancy=0.8)
        bad = score_item(
            _item(id="cve_lookups-002", must_mention=["CVE-2021-23017", "80"]),
            _view(unsupported_entities=("10.0.0.1",), checked_entities=("a", "10.0.0.1")),
            latency_s=3.0,
            relevancy=0.4,
        )
        refused_ok = score_item(
            _item(
                id="adversarial-001",
                category="adversarial",
                required_refs=[],
                must_mention=[],
                expect_refusal=True,
            ),
            _view(text="I don't have that data.", refused=True, cited_ids=()),
            latency_s=0.5,
        )
        false_refusal = score_item(
            _item(id="cve_lookups-003"),
            _view(text="I don't have that data.", refused=True, cited_ids=()),
            latency_s=0.5,
        )
        return [ok, bad, refused_ok, false_refusal]

    def test_overall(self) -> None:
        agg = aggregate(self._scores())
        assert agg["items"] == 4 and agg["answered"] == 2
        assert agg["faithfulness_answered"] == 0.5
        assert agg["faithfulness_all"] == 0.75
        assert agg["claim_entity_precision"] == pytest.approx(2 / 3)
        assert agg["refusal_accuracy"] == 1.0
        assert agg["false_refusal_rate"] == pytest.approx(1 / 3)
        assert agg["citation_accuracy"] == 1.0 and agg["citations"] == 2
        # ok 1.0, bad 0.5, false refusal 0.0 (refusal text mentions nothing)
        assert agg["answer_correctness_proxy"] == pytest.approx(0.5)
        assert agg["answer_relevancy_embedding"] == pytest.approx(0.6)
        assert agg["context_recall"] == 1.0  # all three items retrieved obs:a
        assert agg["latency_s"]["max"] == 3.0 and agg["latency_s"]["p50"] == 0.75
        assert agg["judge_faithfulness"] is None

    def test_by_category(self) -> None:
        by = aggregate_by_category(self._scores())
        assert set(by) == {"cve_lookups", "adversarial"}
        assert by["adversarial"]["refusal_accuracy"] == 1.0
        assert by["adversarial"]["false_refusal_rate"] is None

    def test_empty(self) -> None:
        agg = aggregate([])
        assert agg["faithfulness_answered"] is None and agg["latency_s"]["mean"] is None


class TestJudge:
    def test_parse_yes(self) -> None:
        assert parse_judge_verdict("VERDICT: yes")["verdict"] == "yes"

    def test_parse_no_with_statements(self) -> None:
        out = parse_judge_verdict("verdict: NO\n- port 22 is open\n- runs Debian\nnote")
        assert out["verdict"] == "no"
        assert out["unsupported_statements"] == ["port 22 is open", "runs Debian"]

    def test_unparseable(self) -> None:
        assert parse_judge_verdict("Looks fine to me")["verdict"] == "unparseable"

    def test_prompt_lists_documents(self) -> None:
        prompt = judge_prompt("q?", "a.", {"obs:a": "text a"})
        assert "[obs:a]\ntext a" in prompt and "Answer:\na." in prompt

    def test_run_judge(self) -> None:
        calls: list[dict[str, str]] = []

        def generate(*, system: str, prompt: str) -> str:
            calls.append({"system": system, "prompt": prompt})
            return "VERDICT: yes"

        assert run_judge(generate, "q", _view())["verdict"] == "yes"  # type: ignore[index]
        assert "obs:a" in calls[0]["prompt"] and "obs:b" not in calls[0]["prompt"]
        assert run_judge(generate, "q", _view(refused=True)) is None
        uncited = run_judge(generate, "q", _view(cited_ids=()))
        assert uncited is not None and uncited["verdict"] == "no_citations"
        assert len(calls) == 1

    def test_judge_aggregate(self) -> None:
        s1 = score_item(_item(), _view(), latency_s=0.0)
        s1.judge = {"verdict": "yes"}
        s2 = score_item(_item(id="x-2"), _view(), latency_s=0.0)
        s2.judge = {"verdict": "no_citations"}
        s3 = score_item(_item(id="x-3"), _view(), latency_s=0.0)
        s3.judge = {"verdict": "unparseable"}
        agg = aggregate([s1, s2, s3])
        assert agg["judge_faithfulness"] == 0.5
        assert agg["judge_items"] == 2 and agg["judge_unparseable"] == 1


class TestDiagnosticsAndSchema:
    def test_golden_diagnostics(self) -> None:
        items = [
            _item(required_refs=["obs:a"], must_mention=["CVE-2021-23017"]),
            _item(id="b", required_refs=["obs:missing"]),
            _item(id="c", required_refs=["obs:a"], must_mention=["9.9"]),
        ]
        diag = golden_diagnostics(items, {"obs:a": "CVE-2021-23017"})
        assert diag["unresolved_required_refs"] == [{"id": "b", "refs": ["obs:missing"]}]
        assert diag["must_mention_not_in_required_docs"] == [{"id": "c", "entities": ["9.9"]}]

    def test_validate_item(self) -> None:
        assert validate_item(_item()) == []
        assert validate_item({"id": "x"})[0].startswith("missing key")
        assert "an answerable item needs at least one required_ref" in validate_item(
            _item(required_refs=[])
        )
        assert any("prefix" in p for p in validate_item(_item(required_refs=["doc:1"])))
        assert any("refusal item" in p for p in validate_item(_item(expect_refusal=True)))

    def test_default_outputs_separate_harness_checks(self) -> None:
        fake_json, _ = default_outputs(True, "qwen2.5:7b")
        real_json, real_md = default_outputs(False, "qwen2.5:7b")
        assert fake_json.name == "assistant_eval_harness_check.json"
        assert real_json.name == "assistant_eval_qwen2_5_7b.json"
        assert real_md.suffix == ".md"


def _results(banner: str) -> dict[str, Any]:
    scores = [score_item(_item(), _view(), latency_s=1.0, relevancy=0.5)]
    return {
        "metadata": {
            "banner": banner,
            "fixture_banner": "FIXTURE",
            "faithfulness_note": "proxy",
            "mode": "harness-check (FakeModelClient)",
            "model": "fake",
            "embed_model": "fake-embed",
            "judge_model": None,
            "ollama_url": None,
            "ollama_version": None,
            "golden_dir": "evals/golden",
            "golden_sha256": "0" * 64,
            "golden_generator_version": "1.0.0",
            "item_counts": {"cve_lookups": 1},
            "documents_indexed": 2,
            "retrieval_limit": 8,
            "run_at": "2026-11-07T00:00:00+00:00",
            "git": {"sha": "abc", "dirty": False},
            "metric_definitions": {"faithfulness_answered": "def"},
        },
        "golden_diagnostics": {
            "unresolved_required_refs": [],
            "must_mention_not_in_required_docs": [],
        },
        "overall": aggregate(scores),
        "by_category": aggregate_by_category(scores),
        "items": [s.__dict__ for s in scores],
    }


def test_markdown_carries_banners() -> None:
    md = generate_markdown_report(_results(HARNESS_BANNER))
    assert HARNESS_BANNER in md and "FIXTURE" in md and "proxy" in md
    assert "| Faithfulness (answered, entity proxy) | 1.000 |" in md


def test_cli_rejects_unknown_category(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--fake", "--categories", "nope"]) == 1
    assert "unknown categories" in capsys.readouterr().err


def test_fake_end_to_end(tmp_path: Path) -> None:
    """Harness smoke with FakeModelClient. Skipped until the assistant modules exist."""
    for module in (
        "services.assistant.client",
        "services.assistant.documents",
        "services.assistant.retrieval",
        "services.assistant.answer",
        "services.assistant.citations",
    ):
        pytest.importorskip(module)
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    rc = main(
        [
            "--fake",
            "--limit-items",
            "2",
            "--output-json",
            str(out_json),
            "--output-md",
            str(out_md),
            "--quiet",
        ]
    )
    assert rc == 0
    results = json.loads(out_json.read_text(encoding="utf-8"))
    assert results["metadata"]["banner"] == HARNESS_BANNER
    assert results["overall"]["items"] == 12
    assert set(results["by_category"]) == {
        "cve_lookups",
        "remediation",
        "attack_paths",
        "prioritization",
        "adversarial",
        "multi_hop",
    }
    assert results["golden_diagnostics"]["unresolved_required_refs"] == []
    assert HARNESS_BANNER in out_md.read_text(encoding="utf-8")


def test_golden_refs_are_document_ids() -> None:
    """Every required_ref is a document id documents_for_engagement produces. Skipped
    until services.assistant.documents exists."""
    pytest.importorskip("services.assistant.documents")
    from evals.assistant_eval import build_documents, load_golden

    _, docs = build_documents()
    ids = {d.doc_id for d in docs}
    texts = {d.doc_id: d.text for d in docs}
    items = load_golden()
    missing = {i["id"]: [r for r in i["required_refs"] if r not in ids] for i in items}
    assert {k: v for k, v in missing.items() if v} == {}
    diag = golden_diagnostics(items, texts)
    assert diag["must_mention_not_in_required_docs"] == [], diag
