"""Answer one analyst question from retrieved, citable facts.

Refusal policy:
- Nothing retrieved -> refuse without calling the model (it has nothing to ground on).
- The model says the documents do not answer it -> refuse, no citations.
- Otherwise return the text with its parsed citations and a deterministic grounding
  check, which lists invalid citations and unsupported entities for the analyst.

The model only ever sees supplied documents. Attack paths reach it as `path` documents
the rules engine already proved; it is told never to infer new ones (Hard Rule 1).
"""

from __future__ import annotations

from collections.abc import Sequence

from packages.schema.models.assistant import Answer, AssistantDocument
from services.assistant.citations import build_citations, check_grounding, parse_citation_ids
from services.assistant.interfaces import ModelClient
from services.assistant.prompts import ANSWER_SYSTEM, REFUSAL_TEXT, render_documents
from services.assistant.retrieval import Retriever

__all__ = ["REFUSAL_TEXT", "answer_question", "build_answer_prompt", "is_refusal"]

NOTHING_RETRIEVED = "nothing relevant retrieved"
MODEL_REFUSED = "the retrieved documents do not answer the question"
MODEL_EMPTY = "the model returned no text"


def _normalise(text: str) -> str:
    return " ".join(text.replace("’", "'").replace("‘", "'").lower().split())


def is_refusal(text: str) -> bool:
    """True when the model's reply contains the refusal sentence (apostrophe- and
    case-insensitive)."""
    return _normalise(REFUSAL_TEXT) in _normalise(text)


def build_answer_prompt(question: str, documents: Sequence[AssistantDocument]) -> str:
    example = documents[0].doc_id if documents else "obs:sha256:..."
    return (
        "Documents for this engagement (cite them by id):\n\n"
        f"{render_documents(documents)}\n\n"
        f"Question: {question.strip()}\n\n"
        "Answer using only the documents above, citing every claim with the id attribute "
        f"of its document, for example [cite:{example}]. "
        "If the documents answer the question only in part, answer that part and say what "
        "is missing. Only if no document is relevant to the question, reply exactly: "
        f"{REFUSAL_TEXT}"
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

    if not text or is_refusal(text):
        return Answer(
            question=question,
            engagement_id=engagement_id,
            text=REFUSAL_TEXT,
            refused=True,
            refusal_reason=MODEL_REFUSED if text else MODEL_EMPTY,
            retrieved=tuple(retrieved),
            model=client.model_name,
        )

    supplied_ids = {doc.doc_id for doc in documents}
    cited_ids = parse_citation_ids(text)
    citations = build_citations(cited_ids, documents)
    cited_docs = [doc for doc in documents if doc.doc_id in set(cited_ids)]
    grounding = check_grounding(
        text=text, cited=cited_docs, supplied_ids=supplied_ids, question=question
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
