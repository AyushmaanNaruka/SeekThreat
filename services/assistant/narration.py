"""Narrate one proven attack path (Hard Rule 1).

The model sees exactly one path, rendered from its own edges, plus the evidence
documents those edges cite. It is told to narrate the steps in order and add nothing.
The AttackPath is never mutated; the narration is returned as a separate record.

Post-check: the general grounding check against the path document and the evidence,
plus a stricter CVE check: any CVE id in the narration that is not on this path's edges
or in the evidence the edges cite is flagged, even if it appears in some other supplied
document.
"""

from __future__ import annotations

from collections.abc import Sequence

from packages.schema.models.assistant import AssistantDocument, GroundingCheck, PathNarration
from packages.schema.models.graph import AttackPath, GraphNode
from services.assistant.citations import (
    build_citations,
    check_grounding,
    parse_citation_ids,
    resolve_citations,
    strip_citations,
)
from services.assistant.documents import is_assumption_step, path_document
from services.assistant.interfaces import ModelClient
from services.assistant.prompts import NARRATION_SYSTEM, render_documents
from services.assistant.retrieval import contains_term, extract_terms

__all__ = ["build_narration_prompt", "narrate_path"]


def _is_cve(term: str) -> bool:
    return term.startswith("CVE-")


def build_narration_prompt(
    path: AttackPath, path_doc: AssistantDocument, evidence: Sequence[AssistantDocument]
) -> str:
    assumptions = [
        str(n) for n, edge in enumerate(path.edges, start=1) if is_assumption_step(edge.description)
    ]
    assumption_line = (
        f"Steps {', '.join(assumptions)} are ASSUMPTIONS, not observations. Label them as "
        "assumptions."
        if assumptions
        else "No step on this path is an assumption."
    )
    return (
        f"Narrate attack path {path.path_id}. It has exactly {len(path.edges)} steps. "
        f"{assumption_line}\n\n"
        "The path, then the evidence its steps cite:\n\n"
        f"{render_documents([path_doc, *evidence])}\n\n"
        f"Narrate the {len(path.edges)} steps in order, one paragraph each, citing "
        f"[cite:{path.path_id}] and the evidence ids. Do not add steps."
    )


def narrate_path(
    *,
    path: AttackPath,
    nodes: Sequence[GraphNode],
    evidence: Sequence[AssistantDocument],
    client: ModelClient,
    engagement_id: str,
) -> PathNarration:
    foreign = sorted({doc.doc_id for doc in evidence if doc.engagement_id != engagement_id})
    if foreign:
        raise ValueError(f"evidence from another engagement: {foreign}")

    path_doc = path_document(path, nodes, engagement_id)
    evidence = [doc for doc in evidence if doc.doc_id != path.path_id]
    prompt = build_narration_prompt(path, path_doc, evidence)
    text = client.generate(system=NARRATION_SYSTEM, prompt=prompt).strip()

    supplied = [path_doc, *evidence]
    supplied_ids = {doc.doc_id for doc in supplied}
    text, repairs = resolve_citations(text, supplied_ids)
    citations = build_citations(parse_citation_ids(text), supplied)
    general = check_grounding(
        text=text, cited=supplied, supplied_ids=supplied_ids, repaired=repairs
    )

    # CVEs the path itself rests on: its rendered edges plus the evidence they cite.
    on_path_ids = {ref for edge in path.edges for ref in edge.evidence}
    on_path_ids |= {f"finding:{fid}" for edge in path.edges for fid in edge.finding_ids}
    on_path_texts = [path_doc.text] + [doc.text for doc in evidence if doc.doc_id in on_path_ids]
    off_path_cves = [
        term
        for term in extract_terms(strip_citations(text))
        if _is_cve(term) and not any(contains_term(t, term) for t in on_path_texts)
    ]
    unsupported = tuple(dict.fromkeys([*general.unsupported_entities, *off_path_cves]))
    grounding = GroundingCheck(
        checked_entities=general.checked_entities,
        unsupported_entities=unsupported,
        invalid_citations=general.invalid_citations,
        repaired_citations=general.repaired_citations,
    )
    return PathNarration(
        path_id=path.path_id,
        engagement_id=engagement_id,
        text=text,
        citations=citations,
        grounding=grounding,
        model=client.model_name,
    )
