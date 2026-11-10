"""Answer one analyst question from retrieved, citable facts.

Refusal policy:
- Nothing retrieved -> refuse without calling the model (it has nothing to ground on).
- The model replies with the refusal sentence and nothing else of substance, or with no
  valid citation -> refuse, no citations.
- The model answers part of the question with valid citations and also says it lacks the
  rest -> a partial answer, kept (not a refusal), grounding-checked like any other.
- Otherwise return the text with its parsed citations and a deterministic grounding
  check, which lists invalid citations and unsupported entities for the analyst.
  Near-miss citation ids are repaired first, only when unambiguous (citations.py).

The model only ever sees supplied documents. Attack paths reach it as `path` documents
the rules engine already proved; it is told never to infer new ones (Hard Rule 1).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence

from packages.schema.models.assistant import Answer, AssistantDocument
from services.assistant.citations import (
    build_citations,
    check_grounding,
    parse_citation_ids,
    resolve_citations,
    strip_citations,
)
from services.assistant.interfaces import ModelClient
from services.assistant.prompts import (
    ANSWER_SYSTEM,
    REFUSAL_TEXT,
    render_citable_ids,
    render_documents,
)
from services.assistant.retrieval import Retriever

__all__ = [
    "REFUSAL_TEXT",
    "answer_question",
    "build_answer_prompt",
    "is_refusal",
    "is_substantive_partial_answer",
]

NOTHING_RETRIEVED = "nothing relevant retrieved"
MODEL_REFUSED = "the retrieved documents do not answer the question"
MODEL_EMPTY = "the model returned no text"


def _normalise(text: str) -> str:
    return " ".join(text.replace("’", "'").replace("‘", "'").lower().split())


def is_refusal(text: str) -> bool:
    """True when the model's reply contains the refusal sentence (apostrophe- and
    case-insensitive)."""
    return _normalise(REFUSAL_TEXT) in _normalise(text)


_REFUSAL_PATTERN = re.compile(
    r"\s+".join(re.escape(word).replace("'", "['’‘]") for word in REFUSAL_TEXT.split()),
    re.IGNORECASE,
)
# A reply needs at least this many words besides the refusal sentence and its citation
# markers to count as a partial answer rather than a refusal.
_MIN_PARTIAL_WORDS = 4


def is_substantive_partial_answer(text: str, supplied_ids: Collection[str]) -> bool:
    """True when a reply that contains the refusal sentence also answers part of the
    question: it cites at least one supplied document and has real text besides the
    refusal sentence. Call on text already passed through `resolve_citations`."""
    rest = strip_citations(_REFUSAL_PATTERN.sub(" ", text))
    if len(re.findall(r"[A-Za-z0-9]+", rest)) < _MIN_PARTIAL_WORDS:
        return False
    supplied = set(supplied_ids)
    return any(doc_id in supplied for doc_id in parse_citation_ids(text))


def build_answer_prompt(question: str, documents: Sequence[AssistantDocument]) -> str:
    example = documents[0].doc_id if documents else "obs:sha256:..."
    return (
        f"Question: {question.strip()}\n\n"
        "Documents for this engagement (cite them by id):\n\n"
        f"{render_documents(documents)}\n\n"
        "The only ids you may cite, copied character for character:\n"
        f"{render_citable_ids(documents)}\n\n"
        f"Question: {question.strip()}\n\n"
        "Answer using only the documents above. Put a citation after every claim, using "
        f"one id from the list, for example: <claim> [cite:{example}]. Never cite a "
        "document number, a step number or a part of an id. "
        "If the documents answer the question only in part, answer that part with "
        "citations and say what is missing. Only if no document is relevant to the "
        f"question, reply exactly: {REFUSAL_TEXT}"
    )


def answer_question(
    *,
    question: str,
    engagement_id: str,
    retriever: Retriever,
    client: ModelClient,
    limit: int = 8,
) -> Answer:
    """Retrieve, generate, cite and check. Raises ModelUnavailableError (client.py) if
    the model server cannot be reached; retrieval embeds the question with `client`'s
    embedder via the retriever."""
    retrieved = retriever.retrieve(engagement_id=engagement_id, question=question, limit=limit)
    if not retrieved:
        return Answer(
            question=question,
            engagement_id=engagement_id,
            text=REFUSAL_TEXT,
            refused=True,
            refusal_reason=NOTHING_RETRIEVED,
            model=client.model_name,
        )

    documents = [hit.document for hit in retrieved]
    prompt = build_answer_prompt(question, documents)
    text = client.generate(system=ANSWER_SYSTEM, prompt=prompt).strip()

    supplied_ids = {doc.doc_id for doc in documents}
    text, repairs = resolve_citations(text, supplied_ids)

    if not text or (is_refusal(text) and not is_substantive_partial_answer(text, supplied_ids)):
        return Answer(
            question=question,
            engagement_id=engagement_id,
            text=REFUSAL_TEXT,
            refused=True,
            refusal_reason=MODEL_REFUSED if text else MODEL_EMPTY,
            retrieved=tuple(retrieved),
            model=client.model_name,
        )

    cited_ids = parse_citation_ids(text)
    citations = build_citations(cited_ids, documents)
    cited_docs = [doc for doc in documents if doc.doc_id in set(cited_ids)]
    grounding = check_grounding(
        text=text,
        cited=cited_docs,
        supplied_ids=supplied_ids,
        question=question,
        repaired=repairs,
    )
    return Answer(
        question=question,
        engagement_id=engagement_id,
        text=text,
        citations=citations,
        retrieved=tuple(retrieved),
        grounding=grounding,
        model=client.model_name,
    )
