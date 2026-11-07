"""Citation markers and the deterministic grounding check.

The model must cite as `[cite:<doc_id>]`. After generation we parse the markers, keep
only ids that were actually supplied, and check that every exact identifier the text
mentions (CVE id, address, port, host name) appears in a cited document or in the
question. Anything else is surfaced to the analyst, never silently passed through.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Sequence

from packages.schema.models.assistant import AssistantDocument, GroundingCheck
from packages.schema.models.citation import Citation
from services.assistant.retrieval import contains_term, extract_terms

CITE_MARKER = re.compile(r"\[cite:([^\]]*)\]", re.IGNORECASE)
_FRAMED_ID = re.compile(r'\bid="([^"]+)"')
_EXCERPT_CHARS = 200


def cite(doc_id: str) -> str:
    """The marker for one document id."""
    return f"[cite:{doc_id}]"


def parse_citation_ids(text: str) -> list[str]:
    """Cited ids in order of first appearance, unique.

    Accepts `[cite:a]` and the common model variant `[cite:a, cite:b]`.
    """
    ids: list[str] = []
    seen: set[str] = set()
    for match in CITE_MARKER.finditer(text):
        body = match.group(1)
        # Some models paste the document frame into the marker: [cite:<document id="x" ...>].
        framed = _FRAMED_ID.findall(body)
        for part in framed or re.split(r"[,;\s]+", body):
            part = part.strip()
            if part.lower().startswith("cite:"):
                part = part[len("cite:") :]
            if part and part not in seen:
                seen.add(part)
                ids.append(part)
    return ids


def strip_citations(text: str) -> str:
    return CITE_MARKER.sub(" ", text)


def _excerpt(text: str) -> str:
    return text if len(text) <= _EXCERPT_CHARS else text[:_EXCERPT_CHARS].rstrip() + "..."


def build_citations(
    ids: Sequence[str], documents: Sequence[AssistantDocument]
) -> tuple[Citation, ...]:
    """Citation objects for the ids that resolve to a supplied document, in `ids` order."""
    by_id = {doc.doc_id: doc for doc in documents}
    out: list[Citation] = []
    seen: set[str] = set()
    for doc_id in ids:
        doc = by_id.get(doc_id)
        if doc is None or doc_id in seen:
            continue
        seen.add(doc_id)
        out.append(Citation(kind=doc.kind, ref_id=doc_id, excerpt=_excerpt(doc.text)))
    return tuple(out)


def check_grounding(
    *,
    text: str,
    cited: Sequence[AssistantDocument],
    supplied_ids: Collection[str],
    question: str = "",
) -> GroundingCheck:
    """Entities in `text` that no cited document (nor the question) contains, and cited
    ids that were never supplied."""
    entities = extract_terms(strip_citations(text))
    sources = [doc.text for doc in cited] + ([question] if question else [])
    unsupported = [
        term for term in entities if not any(contains_term(src, term) for src in sources)
    ]
    supplied = set(supplied_ids)
    invalid = [doc_id for doc_id in parse_citation_ids(text) if doc_id not in supplied]
    return GroundingCheck(
        checked_entities=tuple(entities),
        unsupported_entities=tuple(unsupported),
        invalid_citations=tuple(invalid),
    )
