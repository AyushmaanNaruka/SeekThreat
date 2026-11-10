"""Citation markers and the deterministic grounding check.

The model must cite as `[cite:<doc_id>]`. After generation we parse the markers, keep
only ids that were actually supplied, and check that every exact identifier the text
mentions (CVE id, address, port, host name) appears in a cited document or in the
question. Anything else is surfaced to the analyst, never silently passed through.

Citation repair: small models mangle long hash ids (one character dropped, a stray
`#Step 2` fragment, the kind written twice as `chokepoint:path:...`). `resolve_citations`
maps such a near-miss to a supplied id only when exactly one supplied id fits a named
rule; anything ambiguous or unmatched stays invalid. Repairs are logged and returned in
`GroundingCheck.repaired_citations`, so the analyst sees what the model wrote.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Collection, Sequence

from packages.schema.models.assistant import AssistantDocument, CitationRepair, GroundingCheck
from packages.schema.models.citation import Citation
from services.assistant.retrieval import contains_term, extract_terms

logger = logging.getLogger(__name__)

CITE_MARKER = re.compile(r"\[cite:([^\]]*)\]", re.IGNORECASE)
_FRAMED_ID = re.compile(r'\bid="([^"]+)"')
_EXCERPT_CHARS = 200
# A marker part with no ':' and shorter than this is an annotation the model added
# inside the marker ("step 2", "5"), not an attempt at a document id.
_MIN_BARE_ID_CHARS = 8
# Repairs that guess at a body need this much of it, so short ids are never snapped.
_MIN_REPAIR_BODY_CHARS = 8
_MIN_EDIT_DISTANCE_CHARS = 12
_TRAILING_JUNK = ".,;:)>'\"`"
_ID_SHAPED = re.compile(r"^[A-Za-z][\w-]*:[\w:.#-]{4,}$")


def cite(doc_id: str) -> str:
    """The marker for one document id."""
    return f"[cite:{doc_id}]"


def _marker_ids(body: str) -> list[str]:
    """Candidate ids inside one marker body, in order (may repeat)."""
    # Some models paste the document frame into the marker: [cite:<document id="x" ...>].
    framed = _FRAMED_ID.findall(body)
    if framed:
        return [part.strip() for part in framed if part.strip()]
    out: list[str] = []
    for part in re.split(r"[,;]", body):
        tokens = [t for t in part.split() if t.lower() != "cite:"]
        for n, token in enumerate(tokens):
            if token.lower().startswith("cite:"):
                token = token[len("cite:") :]
            if not token:
                continue
            if n == 0:
                if ":" not in token and len(token) < _MIN_BARE_ID_CHARS:
                    continue
            elif not _ID_SHAPED.match(token):
                # Later words in a part are prose ("step 2") unless they look like an id
                # ("[cite:path:a path:b]").
                continue
            out.append(token)
    return out


def parse_citation_ids(text: str) -> list[str]:
    """Cited ids in order of first appearance, unique.

    Accepts `[cite:a]`, `[cite:a, cite:b]` and `[cite:a; b]`. Within each comma- or
    semicolon-separated part only the first token is the id: in `[cite:path:x, step 2]`
    the ids are `path:x` (and `step` is dropped as an annotation, not an id).
    """
    ids: list[str] = []
    seen: set[str] = set()
    for match in CITE_MARKER.finditer(text):
        for part in _marker_ids(match.group(1)):
            if part not in seen:
                seen.add(part)
                ids.append(part)
    return ids


def strip_citations(text: str) -> str:
    return CITE_MARKER.sub(" ", text)


# ------------------------------------------------------------------------------ repair


def _within_one_edit(a: str, b: str) -> bool:
    """Levenshtein distance between a and b is exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(1 for x, y in zip(a, b, strict=True) if x != y) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1 :]


def _body(doc_id: str) -> str:
    """The part after the kind prefix: `path:abc` -> `abc`, `obs:sha256:x` -> `sha256:x`."""
    return doc_id.split(":", 1)[1] if ":" in doc_id else doc_id


def _clean(cited: str) -> str:
    cleaned = cited.split("#", 1)[0].strip()
    while cleaned.endswith(("...", "…")):
        cleaned = cleaned[:-3] if cleaned.endswith("...") else cleaned[:-1]
    return cleaned.strip().rstrip(_TRAILING_JUNK).lstrip("<('\"`")


def resolve_citation(cited: str, supplied_ids: Collection[str]) -> tuple[str | None, str | None]:
    """(resolved id, rule) for one cited id against the ids supplied in this context.

    Rules are tried in order; the first that yields candidates decides. One candidate is
    a repair, more than one is ambiguous and stays invalid (None, None). An exact match
    returns (cited, None).
    """
    supplied = sorted(set(supplied_ids))
    if cited in supplied:
        return cited, None
    cleaned = _clean(cited)
    if not cleaned:
        return None, None
    lowered = cleaned.lower()
    rules: list[tuple[str, list[str]]] = [
        ("normalised", [s for s in supplied if s == cleaned]),
        ("case", [s for s in supplied if s.lower() == lowered]),
        # chokepoint:path:abc -> path:abc; observation:obs:sha256:x -> obs:sha256:x
        ("extra_prefix", [s for s in supplied if lowered.endswith(":" + s.lower())]),
    ]
    if len(cleaned) >= _MIN_REPAIR_BODY_CHARS:
        # sha256:x -> obs:sha256:x
        rules.append(("missing_prefix", [s for s in supplied if s.lower().endswith(":" + lowered)]))
    if len(_body(cleaned)) >= _MIN_REPAIR_BODY_CHARS and ":" in cleaned:
        # path:456a8 (truncated) -> path:456a860ed4f55b66
        rules.append(
            ("truncated", [s for s in supplied if s.lower().startswith(lowered) and s != cleaned])
        )
    if len(cleaned) >= _MIN_EDIT_DISTANCE_CHARS:
        rules.append(
            ("edit_distance_1", [s for s in supplied if _within_one_edit(s.lower(), lowered)])
        )
    for rule, candidates in rules:
        if len(candidates) == 1:
            return candidates[0], rule
        if len(candidates) > 1:
            return None, None
    return None, None


def resolve_citations(
    text: str, supplied_ids: Collection[str]
) -> tuple[str, tuple[CitationRepair, ...]]:
    """Rewrite citation markers whose ids resolve to a supplied id by a repair rule.

    Only the marker text changes, and only for markers holding a repaired id; the prose
    is untouched. Unresolved ids are kept verbatim so the grounding check lists them as
    invalid. Returns the rewritten text and the repairs made, in order.
    """
    supplied = set(supplied_ids)
    repairs: list[CitationRepair] = []
    seen: set[str] = set()

    def rewrite(match: re.Match[str]) -> str:
        parts = _marker_ids(match.group(1))
        out: list[str] = []
        changed = False
        for part in parts:
            resolved, rule = resolve_citation(part, supplied)
            if resolved is not None and rule is not None:
                changed = True
                if part not in seen:
                    seen.add(part)
                    repairs.append(CitationRepair(cited=part, resolved=resolved, rule=rule))
                    logger.info(
                        "citation repaired",
                        extra={"cited": part, "resolved": resolved, "rule": rule},
                    )
                out.append(resolved)
            else:
                out.append(part)
        if not changed:
            return match.group(0)
        return "[cite:" + ", ".join(dict.fromkeys(out)) + "]"

    return CITE_MARKER.sub(rewrite, text), tuple(repairs)


# --------------------------------------------------------------------------- citations


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
    repaired: Sequence[CitationRepair] = (),
) -> GroundingCheck:
    """Entities in `text` that no cited document (nor the question) contains, and cited
    ids that were never supplied. `repaired` is carried through for the analyst; pass the
    text after `resolve_citations` so repaired ids count as valid."""
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
        repaired_citations=tuple(repaired),
    )
