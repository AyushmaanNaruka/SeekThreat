"""Track B evaluation of the Layer 4 assistant against the generated golden set.

Builds the fixture engagement (observations, interim-bridge findings, the attack graph
from ``services.graph.analyze`` and ``lab/topology.yaml``), turns it into assistant
documents, indexes them in an ``InMemoryVectorStore``, answers every golden item with
``answer_question`` and scores the answers.

What this is NOT
----------------
* Not a lab run. The engagement is the observation fixtures, in which 8 of 10 lab hosts
  are synthetic (``tests/fixtures/observations/README.md``).
* Not RAGAS. Faithfulness here is an entity-level proxy computed by the assistant's own
  deterministic grounding check (CVE ids, IPs and ports must appear in a cited document or
  the question; every citation must name a supplied document). It cannot see a wrong
  claim that names no such entity. The optional LLM judge (``--judge-model``) is a second,
  separately reported measure.
* ``--fake`` runs ``FakeModelClient``. Its output carries a HARNESS CHECK banner and is
  never a measurement.

Metric definitions (also written into every report)
---------------------------------------------------
faithfulness (entity proxy)
    Share of answers whose grounding check lists no unsupported entity and no invalid
    citation. Reported over answered (non-refused) items, the headline, and over all items
    (a refusal is trivially faithful, so the all-items figure is inflated by refusals).
claim-entity precision
    Over answered items, sum(checked - unsupported) / sum(checked) entities.
context precision / recall
    Per item with required_refs: |retrieved ∩ required| / |retrieved| and
    |retrieved ∩ required| / |required|, by document id, averaged over items. Plain set
    overlap, not RAGAS's rank-weighted precision.
citation accuracy
    Over every citation in answered items: a citation is correct when (a) it names a
    document that was retrieved and supplied to the model (not in invalid_citations) AND
    (b) that document is in the item's required_refs, or its text contains one of the
    item's must_mention entities (or an alias). Micro-averaged over citations.
answer correctness (proxy)
    Must-mention recall: share of the item's must_mention entities (or aliases) the answer
    text contains, whole-token and case-insensitive. Non-refusal items only.
refusal accuracy / false refusals
    Share of expect_refusal items the assistant refused; share of the other items it
    refused.
answer relevancy (embedding cosine)
    Cosine similarity between the embeddings of the question and of the answer, with the
    same embed model as retrieval. Answered items only. Not RAGAS answer relevancy (which
    generates questions back from the answer).
latency
    Wall-clock seconds for one ``answer_question`` call (retrieval embedding included).

Usage:
    python evals/assistant_eval.py --fake                    # harness check, no model
    python evals/assistant_eval.py --model qwen2.5:7b --embed-model nomic-embed-text
"""

from __future__ import annotations

# ruff: noqa: E402
import argparse
import json
import math
import re
import statistics
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.scripts.build_assistant_golden import (
    CATEGORIES,
    GOLDEN_DIR,
    MANIFEST_NAME,
    golden_sha256,
)

_RESULTS_DIR = _REPO_ROOT / "evals" / "results"
DEFAULT_MODEL = "qwen2.5:7b"
DEFAULT_EMBED_MODEL = "nomic-embed-text"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_RETRIEVAL_LIMIT = 8

REQUIRED_KEYS = (
    "id",
    "category",
    "question",
    "reference_answer",
    "required_refs",
    "must_mention",
    "must_mention_aliases",
    "expect_refusal",
    "lab_configuration",
    "source",
    "verified_by",
    "verified_at",
)

FIXTURE_BANNER = (
    "FIXTURE-BASED, NOT A LAB RUN. The engagement is tests/fixtures/observations/ (8 of 10 "
    "lab hosts synthetic), and the golden set is generated from that same engagement by "
    "evals/scripts/build_assistant_golden.py."
)
HARNESS_BANNER = (
    "HARNESS CHECK. FakeModelClient generated these answers and embeddings. Nothing here "
    "measures a model; do not report any number from this file."
)
FAITHFULNESS_NOTE = (
    "Faithfulness is an entity-level proxy (deterministic grounding check on CVE ids, IPs, "
    "ports and citation ids), not RAGAS LLM-judged claim faithfulness."
)

METRIC_DEFINITIONS: dict[str, str] = {
    "faithfulness_answered": (
        "Share of answered (non-refused) items whose grounding check has no unsupported "
        "entity and no invalid citation. Entity-level proxy, not RAGAS."
    ),
    "faithfulness_all": (
        "Same check over all items; refusals count as faithful, so this is inflated by refusals."
    ),
    "claim_entity_precision": (
        "Answered items: sum(checked - unsupported) / sum(checked) grounding entities."
    ),
    "context_precision": (
        "Items with required_refs: mean |retrieved ∩ required| / |retrieved| by doc id "
        "(plain set overlap, not rank-weighted)."
    ),
    "context_recall": "Items with required_refs: mean |retrieved ∩ required| / |required|.",
    "citation_accuracy": (
        "Citations in answered items: correct when the cited id was retrieved and supplied "
        "(not invalid) AND it is a required_ref or its text contains a must_mention entity "
        "or alias. Micro-averaged over citations."
    ),
    "answer_correctness_proxy": (
        "Non-refusal items: mean share of must_mention entities (or aliases) the answer "
        "contains, whole-token, case-insensitive."
    ),
    "refusal_accuracy": "expect_refusal items: share the assistant refused.",
    "false_refusal_rate": "Items not expecting refusal: share the assistant refused.",
    "answer_relevancy_embedding": (
        "Answered items: mean cosine(embed(question), embed(answer)) with the retrieval "
        "embed model. Not RAGAS answer relevancy."
    ),
    "latency_s": "Wall-clock seconds per answer_question call.",
    "uncited_answer_rate": "Answered items whose answer carries no citation at all.",
}


# --------------------------------------------------------------------------- golden set


def load_golden(
    golden_dir: Path = GOLDEN_DIR, categories: Sequence[str] = CATEGORIES
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for category in categories:
        path = golden_dir / f"{category}.jsonl"
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    items.append(json.loads(line))
    return items


def validate_item(item: Mapping[str, Any]) -> list[str]:
    """Schema problems with one golden item; empty when it is well-formed."""
    problems = [f"missing key {k}" for k in REQUIRED_KEYS if k not in item]
    if problems:
        return problems
    if item["category"] not in CATEGORIES:
        problems.append(f"unknown category {item['category']}")
    if not str(item["question"]).strip() or not str(item["reference_answer"]).strip():
        problems.append("empty question or reference_answer")
    if not isinstance(item["expect_refusal"], bool):
        problems.append("expect_refusal must be a bool")
    if item["expect_refusal"] and (item["required_refs"] or item["must_mention"]):
        problems.append("a refusal item cannot require refs or mentions")
    if not item["expect_refusal"] and not item["required_refs"]:
        problems.append("an answerable item needs at least one required_ref")
    if not item["expect_refusal"] and not item["must_mention"]:
        problems.append("an answerable item needs at least one must_mention entity")
    for ref in item["required_refs"]:
        if not re.match(r"^(obs|finding|path|chokepoint|topology):", ref):
            problems.append(f"required_ref {ref!r} has no known document prefix")
    for key in item["must_mention_aliases"]:
        if key not in item["must_mention"]:
            problems.append(f"alias key {key!r} is not a must_mention entity")
    if item["source"] != "fixture":
        problems.append("source must be 'fixture'")
    return problems


# --------------------------------------------------------------------------- metrics


def mentions(text: str, entity: str, aliases: Iterable[str] = ()) -> bool:
    """Whole-token, case-insensitive: "8" does not match inside "8080", "low" not in
    "allow", "1.18.0" not inside "11.18.0"."""
    for candidate in (entity, *aliases):
        if not candidate:
            continue
        pattern = r"(?<![\w.])" + re.escape(candidate) + r"(?![\w]|\.\w)"
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False


def must_mention_recall(
    text: str, must_mention: Sequence[str], aliases: Mapping[str, Sequence[str]]
) -> float | None:
    if not must_mention:
        return None
    hit = sum(mentions(text, e, aliases.get(e, ())) for e in must_mention)
    return hit / len(must_mention)


def context_scores(
    retrieved_ids: Sequence[str], required_refs: Sequence[str]
) -> tuple[float | None, float | None]:
    """(precision, recall) by document id; None where undefined."""
    if not required_refs:
        return None, None
    required = set(required_refs)
    retrieved = list(dict.fromkeys(retrieved_ids))
    overlap = sum(1 for d in retrieved if d in required)
    precision = overlap / len(retrieved) if retrieved else 0.0
    return precision, overlap / len(required)


def judge_citations(
    cited_ids: Sequence[str],
    invalid_ids: Sequence[str],
    retrieved_texts: Mapping[str, str],
    required_refs: Sequence[str],
    must_mention: Sequence[str],
    aliases: Mapping[str, Sequence[str]],
) -> list[dict[str, Any]]:
    """One verdict per distinct citation (see module docstring: citation accuracy)."""
    out: list[dict[str, Any]] = []
    invalid = set(invalid_ids)
    required = set(required_refs)
    for doc_id in dict.fromkeys(cited_ids):
        valid = doc_id not in invalid and doc_id in retrieved_texts
        relevant = False
        if valid:
            text = retrieved_texts[doc_id]
            relevant = doc_id in required or any(
                mentions(text, e, aliases.get(e, ())) for e in must_mention
            )
        out.append({"doc_id": doc_id, "valid": valid, "relevant": relevant})
        out[-1]["correct"] = valid and relevant
    return out


def cosine(a: Sequence[float], b: Sequence[float]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return None
    return dot / (na * nb)


@dataclass(frozen=True)
class AnswerView:
    """The parts of an `Answer` the metrics read, as plain data (testable without the
    assistant package)."""

    text: str
    refused: bool
    cited_ids: tuple[str, ...]
    retrieved_ids: tuple[str, ...]
    retrieved_texts: Mapping[str, str]
    checked_entities: tuple[str, ...] = ()
    unsupported_entities: tuple[str, ...] = ()
    invalid_citations: tuple[str, ...] = ()
    # (cited, resolved, rule) for near-miss ids the assistant repaired; they count as
    # valid citations of `resolved`.
    repaired_citations: tuple[tuple[str, str, str], ...] = ()


def answer_view(answer: Any) -> AnswerView:
    """Adapt a packages.schema Answer. Citations = the answer's Citation refs plus any
    invalid citation ids the grounding check found, in order, deduplicated."""
    cited = [c.ref_id for c in answer.citations]
    cited += list(answer.grounding.invalid_citations)
    retrieved = [r.document for r in answer.retrieved]
    return AnswerView(
        text=answer.text,
        refused=bool(answer.refused),
        cited_ids=tuple(dict.fromkeys(cited)),
        retrieved_ids=tuple(d.doc_id for d in retrieved),
        retrieved_texts={d.doc_id: d.text for d in retrieved},
        checked_entities=tuple(answer.grounding.checked_entities),
        unsupported_entities=tuple(answer.grounding.unsupported_entities),
        invalid_citations=tuple(answer.grounding.invalid_citations),
        repaired_citations=tuple(
            (r.cited, r.resolved, r.rule)
            for r in getattr(answer.grounding, "repaired_citations", ())
        ),
    )


@dataclass
class ItemScore:
    id: str
    category: str
    expect_refusal: bool
    refused: bool
    faithful: bool
    checked_entities: int
    unsupported_entities: list[str]
    invalid_citations: list[str]
    context_precision: float | None
    context_recall: float | None
    citations: list[dict[str, Any]]
    must_mention_recall: float | None
    relevancy: float | None
    latency_s: float
    answer: str
    retrieved_ids: list[str]
    judge: dict[str, Any] | None = None
    diagnostics: list[str] = field(default_factory=list)
    repaired_citations: list[dict[str, str]] = field(default_factory=list)


def score_item(
    item: Mapping[str, Any],
    view: AnswerView,
    *,
    latency_s: float,
    relevancy: float | None = None,
) -> ItemScore:
    aliases = item.get("must_mention_aliases") or {}
    precision, recall = context_scores(view.retrieved_ids, item["required_refs"])
    citations = (
        []
        if view.refused
        else judge_citations(
            view.cited_ids,
            view.invalid_citations,
            view.retrieved_texts,
            item["required_refs"],
            item["must_mention"],
            aliases,
        )
    )
    correctness = (
        None
        if item["expect_refusal"]
        else must_mention_recall(view.text, item["must_mention"], aliases)
    )
    return ItemScore(
        id=item["id"],
        category=item["category"],
        expect_refusal=bool(item["expect_refusal"]),
        refused=view.refused,
        faithful=not view.unsupported_entities and not view.invalid_citations,
        checked_entities=len(view.checked_entities),
        unsupported_entities=list(view.unsupported_entities),
        invalid_citations=list(view.invalid_citations),
        context_precision=precision,
        context_recall=recall,
        citations=citations,
        must_mention_recall=correctness,
        relevancy=None if view.refused else relevancy,
        latency_s=latency_s,
        answer=view.text,
        retrieved_ids=list(view.retrieved_ids),
        repaired_citations=[
            {"cited": c, "resolved": r, "rule": rule} for c, r, rule in view.repaired_citations
        ],
    )


def _mean(values: Iterable[float | None]) -> float | None:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _percentile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[k]


def aggregate(scores: Sequence[ItemScore]) -> dict[str, Any]:
    answered = [s for s in scores if not s.refused]
    refusal_items = [s for s in scores if s.expect_refusal]
    other_items = [s for s in scores if not s.expect_refusal]
    checked = sum(s.checked_entities for s in answered)
    unsupported = sum(len(s.unsupported_entities) for s in answered)
    citations = [c for s in answered for c in s.citations]
    latencies = [s.latency_s for s in scores]
    judged = [s.judge for s in scores if s.judge is not None]
    judge_yes = sum(1 for j in judged if j["verdict"] == "yes")
    judge_scored = [j for j in judged if j["verdict"] in ("yes", "no", "no_citations")]
    return {
        "items": len(scores),
        "answered": len(answered),
        "faithfulness_answered": _ratio(sum(s.faithful for s in answered), len(answered)),
        "faithfulness_all": _ratio(sum(s.faithful for s in scores), len(scores)),
        "claim_entity_precision": _ratio(checked - unsupported, checked),
        "checked_entities": checked,
        "unsupported_entities": unsupported,
        "context_precision": _mean(s.context_precision for s in scores),
        "context_recall": _mean(s.context_recall for s in scores),
        "context_items": sum(1 for s in scores if s.context_recall is not None),
        "citation_accuracy": _ratio(sum(c["correct"] for c in citations), len(citations)),
        "citations": len(citations),
        "citations_invalid": sum(1 for c in citations if not c["valid"]),
        "citations_repaired": sum(len(s.repaired_citations) for s in answered),
        "uncited_answer_rate": _ratio(sum(1 for s in answered if not s.citations), len(answered)),
        "answer_correctness_proxy": _mean(s.must_mention_recall for s in other_items),
        "refusal_items": len(refusal_items),
        "refusal_accuracy": _ratio(sum(s.refused for s in refusal_items), len(refusal_items)),
        "false_refusal_rate": _ratio(sum(s.refused for s in other_items), len(other_items)),
        "answer_relevancy_embedding": _mean(s.relevancy for s in answered),
        "latency_s": {
            "mean": _mean(latencies),
            "p50": statistics.median(latencies) if latencies else None,
            "p95": _percentile(latencies, 0.95),
            "max": max(latencies) if latencies else None,
        },
        "judge_faithfulness": _ratio(judge_yes, len(judge_scored)) if judged else None,
        "judge_items": len(judge_scored),
        "judge_unparseable": sum(1 for j in judged if j["verdict"] == "unparseable"),
    }


def aggregate_by_category(scores: Sequence[ItemScore]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for category in CATEGORIES:
        subset = [s for s in scores if s.category == category]
        if subset:
            out[category] = aggregate(subset)
    return out


# --------------------------------------------------------------------------- LLM judge

JUDGE_SYSTEM = (
    "You check whether an answer is supported by the source documents given to you, and "
    "nothing else. Reply with exactly 'VERDICT: yes' on the first line if every statement "
    "in the answer is supported by the documents, otherwise 'VERDICT: no'. Then list each "
    "unsupported statement on its own line starting with '- '."
)


def judge_prompt(question: str, answer: str, documents: Mapping[str, str]) -> str:
    docs = "\n\n".join(f"[{doc_id}]\n{text}" for doc_id, text in documents.items())
    return f"Documents:\n{docs}\n\nQuestion: {question}\n\nAnswer:\n{answer}\n"


def parse_judge_verdict(text: str) -> dict[str, Any]:
    match = re.search(r"VERDICT:\s*(yes|no)\b", text, flags=re.IGNORECASE)
    if match is None:
        return {"verdict": "unparseable", "unsupported_statements": [], "raw": text}
    statements = [
        line.strip()[2:].strip()
        for line in text[match.end() :].splitlines()
        if line.strip().startswith("- ")
    ]
    return {
        "verdict": match.group(1).lower(),
        "unsupported_statements": statements,
        "raw": text,
    }


def run_judge(
    generate: Callable[..., str], question: str, view: AnswerView
) -> dict[str, Any] | None:
    """None for refused answers. Uncited answers get verdict no_citations (not supported
    by any cited document) without a model call."""
    if view.refused:
        return None
    docs = {d: view.retrieved_texts[d] for d in view.cited_ids if d in view.retrieved_texts}
    if not docs:
        return {"verdict": "no_citations", "unsupported_statements": [], "raw": ""}
    return parse_judge_verdict(
        generate(system=JUDGE_SYSTEM, prompt=judge_prompt(question, view.text, docs))
    )


# --------------------------------------------------------------------------- diagnostics


def golden_diagnostics(
    items: Sequence[Mapping[str, Any]], doc_texts: Mapping[str, str]
) -> dict[str, list[dict[str, Any]]]:
    """Golden items the indexed documents cannot support: a required_ref that is not an
    indexed doc id, or a must_mention entity that no required_ref document contains.
    These are reported, not dropped, so a doc-builder/golden-set mismatch is visible."""
    unresolved: list[dict[str, Any]] = []
    unanswerable: list[dict[str, Any]] = []
    for item in items:
        missing = [r for r in item["required_refs"] if r not in doc_texts]
        if missing:
            unresolved.append({"id": item["id"], "refs": missing})
        aliases = item.get("must_mention_aliases") or {}
        texts = [doc_texts[r] for r in item["required_refs"] if r in doc_texts]
        absent = [
            e
            for e in item["must_mention"]
            if not any(mentions(t, e, aliases.get(e, ())) for t in texts)
        ]
        if absent and not missing:
            unanswerable.append({"id": item["id"], "entities": absent})
    return {
        "unresolved_required_refs": unresolved,
        "must_mention_not_in_required_docs": unanswerable,
    }


# --------------------------------------------------------------------------- metadata


def git_sha() -> dict[str, Any]:
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        return {"sha": sha, "dirty": bool(dirty)}
    except (OSError, subprocess.SubprocessError):
        return {"sha": None, "dirty": None}


def ollama_version(base_url: str) -> str | None:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/api/version", timeout=3) as r:
            data = json.loads(r.read().decode("utf-8"))
        version = data.get("version")
        return str(version) if version is not None else None
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- runner


def build_documents() -> tuple[str, list[Any]]:
    """The fixture engagement as assistant documents. Imports the assistant at call time."""
    from evals.scripts.build_assistant_golden import load_engagement
    from packages.schema.models.finding import EnrichedFinding
    from services.assistant.documents import documents_for_engagement

    eng = load_engagement()
    docs = documents_for_engagement(
        engagement_id=eng.engagement_id,
        observations=eng.observations,
        enriched_findings=[EnrichedFinding(finding=f) for f in eng.findings],
        graph=eng.graph,
        topology=eng.topology,
    )
    return eng.engagement_id, list(docs)


def run_evaluation(
    *,
    fake: bool,
    model: str = DEFAULT_MODEL,
    embed_model: str = DEFAULT_EMBED_MODEL,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    judge_model: str | None = None,
    categories: Sequence[str] = CATEGORIES,
    limit_items: int | None = None,
    retrieval_limit: int = DEFAULT_RETRIEVAL_LIMIT,
    golden_dir: Path = GOLDEN_DIR,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    from services.assistant.answer import answer_question
    from services.assistant.client import FakeModelClient, OllamaModelClient
    from services.assistant.retrieval import InMemoryVectorStore, Retriever

    items = load_golden(golden_dir, categories)
    if limit_items is not None:
        kept: list[dict[str, Any]] = []
        for category in categories:
            kept += [i for i in items if i["category"] == category][:limit_items]
        items = kept

    client: Any = FakeModelClient() if fake else OllamaModelClient(ollama_url, model, embed_model)
    engagement_id, docs = build_documents()
    store = InMemoryVectorStore()
    retriever = Retriever(store, client)
    retriever.index(docs)
    doc_texts = {d.doc_id: d.text for d in docs}

    judge_generate: Callable[..., str] | None = None
    if judge_model is not None:
        judge_generate = (
            FakeModelClient().generate
            if fake
            else OllamaModelClient(ollama_url, judge_model, embed_model).generate
        )

    scores: list[ItemScore] = []
    for n, item in enumerate(items, 1):
        started = time.perf_counter()
        answer = answer_question(
            question=item["question"],
            engagement_id=engagement_id,
            retriever=retriever,
            client=client,
            limit=retrieval_limit,
        )
        latency = time.perf_counter() - started
        view = answer_view(answer)
        relevancy = None
        if not view.refused and view.text.strip():
            q_vec, a_vec = client.embed([item["question"], view.text])
            relevancy = cosine(q_vec, a_vec)
        score = score_item(item, view, latency_s=latency, relevancy=relevancy)
        if judge_generate is not None:
            score.judge = run_judge(judge_generate, item["question"], view)
        scores.append(score)
        if progress is not None:
            progress(
                f"[{n}/{len(items)}] {item['id']} refused={view.refused} "
                f"faithful={score.faithful} {latency:.1f}s"
            )

    golden_dir_rel = (
        golden_dir.relative_to(_REPO_ROOT) if golden_dir.is_relative_to(_REPO_ROOT) else golden_dir
    )
    manifest_path = golden_dir / MANIFEST_NAME
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    )
    model_name = getattr(client, "model_name", model)
    embed_name = getattr(client, "embed_model_name", embed_model)
    return {
        "metadata": {
            "banner": HARNESS_BANNER if fake else FIXTURE_BANNER,
            "fixture_banner": FIXTURE_BANNER,
            "faithfulness_note": FAITHFULNESS_NOTE,
            "mode": "harness-check (FakeModelClient)" if fake else "measurement (Ollama)",
            "model": model_name,
            "embed_model": embed_name,
            "relevancy_embed_model": embed_name,
            "judge_model": judge_model,
            "ollama_url": None if fake else ollama_url,
            "ollama_version": None if fake else ollama_version(ollama_url),
            "retrieval_limit": retrieval_limit,
            "golden_dir": str(golden_dir_rel).replace("\\", "/"),
            "golden_sha256": golden_sha256(golden_dir, CATEGORIES),
            "golden_manifest_sha256": manifest.get("golden_sha256"),
            "golden_generator_version": manifest.get("generator_version"),
            "categories": list(categories),
            "limit_items_per_category": limit_items,
            "item_counts": {c: sum(1 for i in items if i["category"] == c) for c in categories},
            "documents_indexed": len(docs),
            "engagement_id": engagement_id,
            "run_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "git": git_sha(),
            "metric_definitions": METRIC_DEFINITIONS,
        },
        "golden_diagnostics": golden_diagnostics(items, doc_texts),
        "overall": aggregate(scores),
        "by_category": aggregate_by_category(scores),
        "items": [asdict(s) for s in scores],
    }


# --------------------------------------------------------------------------- output


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


_TABLE_METRICS = (
    ("faithfulness_answered", "Faithfulness (answered, entity proxy)"),
    ("faithfulness_all", "Faithfulness (all items)"),
    ("claim_entity_precision", "Claim-entity precision"),
    ("context_precision", "Context precision"),
    ("context_recall", "Context recall"),
    ("citation_accuracy", "Citation accuracy"),
    ("uncited_answer_rate", "Uncited answer rate"),
    ("answer_correctness_proxy", "Answer correctness (must-mention recall)"),
    ("refusal_accuracy", "Refusal accuracy"),
    ("false_refusal_rate", "False refusal rate"),
    ("answer_relevancy_embedding", "Answer relevancy (embedding cosine)"),
)


def generate_markdown_report(results: Mapping[str, Any]) -> str:
    meta, overall, by_cat = results["metadata"], results["overall"], results["by_category"]
    git = meta["git"]
    lines = [
        "# Assistant evaluation (Layer 4, Track B)",
        "",
        f"> **{meta['banner']}**",
        "",
    ]
    if meta["banner"] != meta["fixture_banner"]:
        lines += [f"> {meta['fixture_banner']}", ""]
    lines += [
        f"> {meta['faithfulness_note']}",
        "",
        f"**Mode:** {meta['mode']}  ",
        f"**Model:** `{meta['model']}`; **embed model:** `{meta['embed_model']}`; "
        f"**judge:** `{meta['judge_model'] or 'off'}`  ",
        f"**Ollama:** {meta['ollama_url'] or '-'} (version {meta['ollama_version'] or '-'})  ",
        f"**Golden set:** `{meta['golden_dir']}` sha256 `{meta['golden_sha256']}` "
        f"(generator {meta['golden_generator_version']})  ",
        f"**Items:** {overall['items']} "
        f"({', '.join(f'{c} {n}' for c, n in meta['item_counts'].items())}); "
        f"documents indexed {meta['documents_indexed']}; retrieval limit "
        f"{meta['retrieval_limit']}  ",
        f"**Run at:** {meta['run_at']}; **git:** `{git['sha']}`"
        f"{' (dirty)' if git['dirty'] else ''}",
        "",
        "## Results",
        "",
        "| Metric | Overall | " + " | ".join(by_cat) + " |",
        "|---|---|" + "---|" * len(by_cat),
    ]
    for key, label in _TABLE_METRICS:
        lines.append(
            f"| {label} | {_fmt(overall[key])} | "
            + " | ".join(_fmt(by_cat[c][key]) for c in by_cat)
            + " |"
        )
    lines.append(
        "| Latency mean / p95 (s) | "
        f"{_fmt(overall['latency_s']['mean'])} / {_fmt(overall['latency_s']['p95'])} | "
        + " | ".join(
            f"{_fmt(by_cat[c]['latency_s']['mean'])} / {_fmt(by_cat[c]['latency_s']['p95'])}"
            for c in by_cat
        )
        + " |"
    )
    lines += [
        "",
        f"Answered {overall['answered']}/{overall['items']}; grounding entities checked "
        f"{overall['checked_entities']}, unsupported {overall['unsupported_entities']}; "
        f"citations {overall['citations']} ({overall['citations_invalid']} invalid, "
        f"{overall.get('citations_repaired', 0)} repaired near-miss ids counted valid).",
        "",
    ]
    if meta["judge_model"]:
        lines += [
            f"## LLM-judge faithfulness (judge `{meta['judge_model']}`)",
            "",
            f"Supported {_fmt(overall['judge_faithfulness'])} over {overall['judge_items']} "
            f"answered items ({overall['judge_unparseable']} unparseable verdicts excluded; "
            "uncited answers count as unsupported). Reported separately from the entity "
            "proxy; a 7B judge is itself unvalidated.",
            "",
        ]
    diag = results["golden_diagnostics"]
    lines += ["## Golden-set diagnostics", ""]
    if diag["unresolved_required_refs"] or diag["must_mention_not_in_required_docs"]:
        for d in diag["unresolved_required_refs"]:
            lines.append(f"- {d['id']}: required ref(s) not indexed: {', '.join(d['refs'])}")
        for d in diag["must_mention_not_in_required_docs"]:
            lines.append(
                f"- {d['id']}: must_mention not in any required doc: {', '.join(d['entities'])}"
            )
    else:
        lines.append(
            "Every required_ref is an indexed document and holds its must_mention entities."
        )
    lines += ["", "## Metric definitions", ""]
    lines += [f"- **{k}**: {v}" for k, v in meta["metric_definitions"].items()]
    failures = [
        s for s in results["items"] if not s["faithful"] or s["refused"] != s["expect_refusal"]
    ]
    lines += ["", "## Unfaithful or wrongly (non-)refused items", ""]
    if failures:
        lines += ["| Item | Refused | Expected refusal | Unsupported | Invalid citations |"]
        lines += ["|---|---|---|---|---|"]
        lines += [
            f"| {s['id']} | {s['refused']} | {s['expect_refusal']} | "
            f"{', '.join(s['unsupported_entities']) or '-'} | "
            f"{', '.join(s['invalid_citations']) or '-'} |"
            for s in failures
        ]
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(results: Mapping[str, Any], output_json: Path, output_md: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(generate_markdown_report(results))


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower()


def default_outputs(fake: bool, model: str) -> tuple[Path, Path]:
    stem = "assistant_eval_harness_check" if fake else f"assistant_eval_{_slug(model)}"
    return _RESULTS_DIR / f"{stem}.json", _RESULTS_DIR / f"{stem}.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Track B evaluation of the Layer 4 assistant on the golden set."
    )
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL)
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument(
        "--fake",
        action="store_true",
        help="FakeModelClient harness check; output is never a measurement.",
    )
    parser.add_argument("--judge-model", default=None, help="Optional LLM judge (default off).")
    parser.add_argument(
        "--limit-items", type=int, default=None, help="First N items of each category."
    )
    parser.add_argument(
        "--categories",
        default=",".join(CATEGORIES),
        help=f"Comma-separated subset of: {', '.join(CATEGORIES)}",
    )
    parser.add_argument("--retrieval-limit", type=int, default=DEFAULT_RETRIEVAL_LIMIT)
    parser.add_argument("--golden-dir", type=Path, default=GOLDEN_DIR)
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-md", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")

    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    unknown = [c for c in categories if c not in CATEGORIES]
    if unknown or not categories:
        sys.stderr.write(f"Error: unknown categories {unknown}; choose from {CATEGORIES}\n")
        return 1
    problems = [
        f"{item.get('id')}: {p}"
        for item in load_golden(args.golden_dir, categories)
        for p in validate_item(item)
    ]
    if problems:
        sys.stderr.write("Error: malformed golden items:\n" + "\n".join(problems) + "\n")
        return 1
    default_json, default_md = default_outputs(args.fake, args.model)
    output_json = args.output_json or default_json
    output_md = args.output_md or default_md

    try:
        from services.assistant.client import ModelUnavailableError
    except ImportError as exc:
        sys.stderr.write(f"Error: services.assistant is not available ({exc}).\n")
        return 2
    try:
        results = run_evaluation(
            fake=args.fake,
            model=args.model,
            embed_model=args.embed_model,
            ollama_url=args.ollama_url,
            judge_model=args.judge_model,
            categories=categories,
            limit_items=args.limit_items,
            retrieval_limit=args.retrieval_limit,
            golden_dir=args.golden_dir,
            progress=None if args.quiet else print,
        )
    except ModelUnavailableError as exc:
        sys.stderr.write(f"Error: model unavailable: {exc}\n")
        return 2
    write_outputs(results, output_json, output_md)
    if not args.quiet:
        overall = results["overall"]
        print("=" * 72)
        print(results["metadata"]["banner"])
        print(FAITHFULNESS_NOTE)
        print("-" * 72)
        for key, label in _TABLE_METRICS:
            print(f"{label:45s} {_fmt(overall[key])}")
        print(f"{'Latency mean (s)':45s} {_fmt(overall['latency_s']['mean'])}")
        if args.judge_model:
            print(
                f"{'LLM-judge faithfulness (' + args.judge_model + ')':45s} "
                f"{_fmt(overall['judge_faithfulness'])}"
            )
        print("=" * 72)
        print(f"Markdown report written to: {output_md}")
        print(f"JSON results written to:    {output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
