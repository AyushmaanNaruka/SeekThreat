"""Layer 4 path narration: one proven path in, text out, nothing added (Hard Rule 1)."""

from __future__ import annotations

import re

import pytest

from packages.schema.models.assistant import AssistantDocument
from packages.schema.models.graph import AttackPath
from services.assistant.client import FakeModelClient
from services.assistant.narration import narrate_path
from tests.unit.test_assistant_documents import ENGAGEMENT, lab_documents, lab_graph


def _evidence_for(path: AttackPath) -> list[AssistantDocument]:
    refs = {ref for edge in path.edges for ref in edge.evidence}
    refs |= {f"finding:{fid}" for edge in path.edges for fid in edge.finding_ids}
    return [d for d in lab_documents() if d.doc_id in refs]


def _assumption_path() -> AttackPath:
    return next(
        p
        for p in lab_graph().paths
        if any(e.rule_name == "credential_reuse_remote_login" for e in p.edges)
    )


def test_prompt_contains_only_this_path_and_its_evidence() -> None:
    graph = lab_graph()
    path = graph.paths[0]
    evidence = _evidence_for(path)
    client = FakeModelClient()
    before = path.model_dump_json()
    narration = narrate_path(
        path=path, nodes=graph.nodes, evidence=evidence, client=client, engagement_id=ENGAGEMENT
    )
    assert path.model_dump_json() == before  # never mutated
    assert path.narration is None
    system, prompt = client.generate_calls[0]
    ids = re.findall(r'<document n="\d+" id="([^"]+)"', prompt)
    assert ids == [path.path_id, *[d.doc_id for d in evidence]]
    other_paths = {p.path_id for p in graph.paths} - {path.path_id}
    assert not any(pid in prompt for pid in other_paths)
    assert "Do not add" in system
    assert narration.path_id == path.path_id
    assert narration.model == "fake-model"
    assert narration.citations and narration.citations[0].ref_id == path.path_id
    assert narration.grounding.grounded, narration.grounding


def test_assumption_steps_are_called_out_in_the_prompt() -> None:
    path = _assumption_path()
    client = FakeModelClient()
    narrate_path(
        path=path,
        nodes=lab_graph().nodes,
        evidence=_evidence_for(path),
        client=client,
        engagement_id=ENGAGEMENT,
    )
    _, prompt = client.generate_calls[0]
    steps = [
        str(n)
        for n, e in enumerate(path.edges, start=1)
        if "Assumed, not observed" in e.description
    ]
    assert steps
    assert f"Steps {', '.join(steps)} are ASSUMPTIONS" in prompt


def test_invented_cve_is_flagged() -> None:
    graph = lab_graph()
    path = graph.paths[0]

    def respond(system: str, prompt: str) -> str:
        return f"Step 1: the attacker uses CVE-2099-12345 [cite:{path.path_id}]."

    narration = narrate_path(
        path=path,
        nodes=graph.nodes,
        evidence=_evidence_for(path),
        client=FakeModelClient(responses=respond),
        engagement_id=ENGAGEMENT,
    )
    assert "CVE-2099-12345" in narration.grounding.unsupported_entities
    assert not narration.grounding.grounded


def test_cve_from_off_path_evidence_is_still_flagged() -> None:
    """A CVE present in a supplied document that no edge of this path cites is flagged:
    the narration must not borrow a vulnerability from elsewhere into this path."""
    graph = lab_graph()
    path = graph.paths[0]
    path_cves = {c for e in path.edges for c in re.findall(r"CVE-\d{4}-\d+", e.description)}
    stray = next(
        d
        for d in lab_documents()
        if d.doc_id.startswith("finding:")
        and (found := set(re.findall(r"CVE-\d{4}-\d+", d.text)))
        and not found & path_cves
    )
    stray_cve = re.findall(r"CVE-\d{4}-\d+", stray.text)[0]

    def respond(system: str, prompt: str) -> str:
        return f"Step 1 also involves {stray_cve} [cite:{path.path_id}] [cite:{stray.doc_id}]."

    narration = narrate_path(
        path=path,
        nodes=graph.nodes,
        evidence=[*_evidence_for(path), stray],
        client=FakeModelClient(responses=respond),
        engagement_id=ENGAGEMENT,
    )
    assert stray_cve in narration.grounding.unsupported_entities


def test_evidence_from_another_engagement_is_rejected() -> None:
    graph = lab_graph()
    path = graph.paths[0]
    foreign = AssistantDocument(
        doc_id="obs:x", kind="observation", engagement_id="eng-other", title="x", text="x"
    )
    with pytest.raises(ValueError, match="another engagement"):
        narrate_path(
            path=path,
            nodes=graph.nodes,
            evidence=[foreign],
            client=FakeModelClient(),
            engagement_id=ENGAGEMENT,
        )


def test_near_miss_path_citation_is_repaired_and_recorded() -> None:
    graph = lab_graph()
    path = graph.paths[0]
    before = path.model_dump_json()

    def respond(system: str, prompt: str) -> str:
        return f"Step 1: entry [cite:{path.path_id}#Step 1]."

    narration = narrate_path(
        path=path,
        nodes=graph.nodes,
        evidence=_evidence_for(path),
        client=FakeModelClient(responses=respond),
        engagement_id=ENGAGEMENT,
    )
    assert path.model_dump_json() == before
    assert [c.ref_id for c in narration.citations] == [path.path_id]
    assert narration.grounding.invalid_citations == ()
    assert [(r.cited, r.resolved) for r in narration.grounding.repaired_citations] == [
        (f"{path.path_id}#Step", path.path_id)
    ]
