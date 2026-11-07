"""Layer 4 answers: refusal policy, citations, grounding check."""

from __future__ import annotations

import re

from packages.schema.models.assistant import AssistantDocument
from services.assistant.answer import REFUSAL_TEXT, answer_question
from services.assistant.citations import (
    build_citations,
    check_grounding,
    parse_citation_ids,
)
from services.assistant.client import FakeModelClient
from services.assistant.retrieval import InMemoryVectorStore, Retriever
from tests.unit.test_assistant_documents import ENGAGEMENT, lab_documents

QUESTION = "What was found on 172.20.1.13 for CVE-2022-22947?"


def _setup(client: FakeModelClient) -> Retriever:
    retriever = Retriever(InMemoryVectorStore(), client)
    retriever.index(lab_documents())
    client.generate_calls.clear()
    return retriever


def _ids_in_prompt(prompt: str) -> list[str]:
    return re.findall(r'<document n="\d+" id="([^"]+)"', prompt)


def test_grounded_answer_cites_supplied_documents() -> None:
    client = FakeModelClient()
    answer = answer_question(
        question=QUESTION, engagement_id=ENGAGEMENT, retriever=_setup(client), client=client
    )
    assert not answer.refused
    assert answer.model == "fake-model"
    assert answer.citations
    supplied = {r.document.doc_id for r in answer.retrieved}
    assert {c.ref_id for c in answer.citations} <= supplied
    assert answer.grounding.grounded, answer.grounding
    # The prompt carried exactly the retrieved documents, framed with their ids.
    _, prompt = client.generate_calls[0]
    assert _ids_in_prompt(prompt) == [r.document.doc_id for r in answer.retrieved]
    assert QUESTION in prompt


def test_system_prompt_forbids_inventing_paths() -> None:
    client = FakeModelClient()
    answer_question(
        question=QUESTION, engagement_id=ENGAGEMENT, retriever=_setup(client), client=client
    )
    system, _ = client.generate_calls[0]
    assert REFUSAL_TEXT in system
    assert '"path"' in system
    assert "Never invent CVE ids" in system


def test_nothing_retrieved_refuses_without_calling_the_model() -> None:
    client = FakeModelClient()
    retriever = _setup(client)
    answer = answer_question(
        question=QUESTION, engagement_id="eng-nothing-indexed", retriever=retriever, client=client
    )
    assert answer.refused
    assert answer.text == REFUSAL_TEXT
    assert answer.refusal_reason == "nothing relevant retrieved"
    assert answer.citations == ()
    assert client.generate_calls == []


def test_model_refusal_is_detected() -> None:
    client = FakeModelClient(responses=lambda s, p: "I don’t have that data for this engagement.")
    answer = answer_question(
        question="Who is the system owner of 172.20.1.13?",
        engagement_id=ENGAGEMENT,
        retriever=_setup(client),
        client=client,
    )
    assert answer.refused
    assert answer.text == REFUSAL_TEXT
    assert answer.citations == ()
    assert answer.refusal_reason
    assert len(client.generate_calls) == 1


def test_invalid_citation_is_flagged() -> None:
    def respond(system: str, prompt: str) -> str:
        real = _ids_in_prompt(prompt)[0]
        return f"See [cite:{real}] and [cite:finding:fnd-does-not-exist]."

    client = FakeModelClient(responses=respond)
    answer = answer_question(
        question=QUESTION, engagement_id=ENGAGEMENT, retriever=_setup(client), client=client
    )
    assert answer.grounding.invalid_citations == ("finding:fnd-does-not-exist",)
    assert not answer.grounding.grounded
    # The bogus id never becomes a Citation.
    assert all(c.ref_id != "finding:fnd-does-not-exist" for c in answer.citations)
    assert len(answer.citations) == 1


def test_unsupported_entity_is_flagged() -> None:
    def respond(system: str, prompt: str) -> str:
        real = _ids_in_prompt(prompt)[0]
        return f"172.20.1.13 is also vulnerable to CVE-1999-0001 [cite:{real}]."

    client = FakeModelClient(responses=respond)
    answer = answer_question(
        question=QUESTION, engagement_id=ENGAGEMENT, retriever=_setup(client), client=client
    )
    assert "CVE-1999-0001" in answer.grounding.unsupported_entities
    assert "172.20.1.13" not in answer.grounding.unsupported_entities
    assert not answer.grounding.grounded


def test_entities_need_a_citation_to_count_as_supported() -> None:
    """Mentioning a real CVE without citing the document that holds it is unsupported."""
    client = FakeModelClient(responses=lambda s, p: "CVE-2022-22947 is present.")
    answer = answer_question(
        question="What is on the gateway?",
        engagement_id=ENGAGEMENT,
        retriever=_setup(client),
        client=client,
    )
    assert answer.grounding.unsupported_entities == ("CVE-2022-22947",)


# ------------------------------------------------------------------------- citations


def _doc(doc_id: str, text: str) -> AssistantDocument:
    return AssistantDocument(
        doc_id=doc_id, kind="observation", engagement_id=ENGAGEMENT, title=doc_id, text=text
    )


def test_parse_citation_ids_order_unique_and_variants() -> None:
    text = "a [cite:obs:1] b [cite:path:2, cite:obs:1] c [CITE:finding:3] [cite: ]"
    assert parse_citation_ids(text) == ["obs:1", "path:2", "finding:3"]
    # A model that pastes the document frame into the marker still resolves to the id.
    framed = '[cite:<document n="8" id="path:238976c1cc8061e1" kind="path">]'
    assert parse_citation_ids(framed) == ["path:238976c1cc8061e1"]


def test_build_citations_keeps_only_supplied_and_truncates() -> None:
    docs = [_doc("obs:1", "x" * 500), _doc("obs:2", "short")]
    cites = build_citations(["obs:2", "obs:9", "obs:1", "obs:2"], docs)
    assert [c.ref_id for c in cites] == ["obs:2", "obs:1"]
    assert cites[0].excerpt == "short"
    assert cites[1].excerpt is not None and len(cites[1].excerpt) <= 203
    assert cites[1].kind == "observation"


def test_check_grounding_uses_question_as_support() -> None:
    check = check_grounding(
        text="Nothing about 10.9.9.9 here [cite:obs:1].",
        cited=[_doc("obs:1", "host 172.20.1.10")],
        supplied_ids={"obs:1"},
        question="Is 10.9.9.9 in scope?",
    )
    assert check.checked_entities == ("10.9.9.9",)
    assert check.unsupported_entities == ()
    assert check.grounded
