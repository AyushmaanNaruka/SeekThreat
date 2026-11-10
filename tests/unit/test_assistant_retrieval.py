"""Layer 4 retrieval: exact-term extraction, engagement scoping, lexical-first hybrid."""

from __future__ import annotations

from packages.schema.models.assistant import AssistantDocument
from services.assistant.client import FakeModelClient
from services.assistant.retrieval import (
    InMemoryVectorStore,
    Retriever,
    contains_term,
    extract_terms,
)
from tests.unit.test_assistant_documents import ENGAGEMENT, lab_documents


def _doc(doc_id: str, text: str, engagement: str = ENGAGEMENT) -> AssistantDocument:
    return AssistantDocument(
        doc_id=doc_id, kind="finding", engagement_id=engagement, title=doc_id, text=text
    )


def _retriever(docs: list[AssistantDocument]) -> tuple[Retriever, FakeModelClient]:
    client = FakeModelClient()
    retriever = Retriever(InMemoryVectorStore(), client)
    assert retriever.index(docs) == len(docs)
    return retriever, client


# --------------------------------------------------------------------------- terms


def test_extract_terms_finds_identifiers_in_order() -> None:
    text = (
        "Is cve-2021-41773 on 172.20.1.13:8080/tcp or fe80::1, port 22, "
        "lab-dvwa-1.lab_dmz? Also CVE-2021-41773 again, nginx 1.18.0, e.g. index.php."
    )
    assert extract_terms(text) == [
        "CVE-2021-41773",
        "172.20.1.13",
        "8080/tcp",
        "fe80::1",
        "22",
        "lab-dvwa-1.lab_dmz",
    ]


def test_extract_terms_ignores_timestamps_hashes_and_bad_values() -> None:
    text = "observed 2026-09-17T18:28:19+00:00 obs:sha256:bb66 999.1.1.1 port 70000 path:abc"
    assert extract_terms(text) == []


def test_contains_term_respects_identifier_boundaries() -> None:
    assert contains_term("host 172.20.1.13 up", "172.20.1.13")
    assert not contains_term("host 172.20.1.13 up", "172.20.1.1")
    assert not contains_term("CVE-2021-41773", "CVE-2021-4177")
    assert contains_term("172.20.1.13:22/tcp", "22")
    assert not contains_term("172.20.1.22", "22")
    assert contains_term("found cve-2021-41773", "CVE-2021-41773")


# ------------------------------------------------------------------------ retrieval


def test_retrieval_is_scoped_to_the_engagement() -> None:
    docs = [
        _doc("finding:a", "CVE-2021-41773 on 172.20.1.10"),
        _doc("finding:b", "CVE-2021-41773 on 10.0.0.5", engagement="eng-other"),
    ]
    retriever, _ = _retriever(docs)
    hits = retriever.retrieve(engagement_id=ENGAGEMENT, question="Where is CVE-2021-41773?")
    assert [h.document.doc_id for h in hits] == ["finding:a"]
    other = retriever.retrieve(engagement_id="eng-other", question="Where is CVE-2021-41773?")
    assert [h.document.doc_id for h in other] == ["finding:b"]
    assert retriever.retrieve(engagement_id="eng-empty", question="CVE-2021-41773") == []

    retriever.store.delete_engagement("eng-other")
    assert retriever.retrieve(engagement_id="eng-other", question="CVE-2021-41773") == []
    assert retriever.store.get(engagement_id=ENGAGEMENT, doc_id="finding:a") is not None
    assert retriever.store.get(engagement_id=ENGAGEMENT, doc_id="finding:b") is None


def test_lexical_hits_rank_first_on_the_lab_corpus() -> None:
    docs = lab_documents()
    retriever, _ = _retriever(docs)
    question = "What is wrong with 172.20.1.13 and CVE-2022-22947?"
    hits = retriever.retrieve(engagement_id=ENGAGEMENT, question=question, limit=8)
    assert hits
    lexical_methods = {"lexical", "hybrid"}
    methods = [h.method for h in hits]
    # Every lexical/hybrid hit precedes every vector-only hit.
    first_vector = next((i for i, m in enumerate(methods) if m == "vector"), len(methods))
    assert all(m in lexical_methods for m in methods[:first_vector])
    assert all(m == "vector" for m in methods[first_vector:])
    top = hits[0].document.text
    assert contains_term(top, "CVE-2022-22947") and contains_term(top, "172.20.1.13")
    assert hits[0].score == 1.0


def test_lexical_term_beats_a_near_identical_cve() -> None:
    docs = [
        _doc("finding:a", "Apache path traversal CVE-2021-42013 on 172.20.1.10"),
        _doc("finding:b", "Apache path traversal CVE-2021-41773 on 172.20.1.10"),
    ]
    retriever, _ = _retriever(docs)
    hits = retriever.retrieve(engagement_id=ENGAGEMENT, question="Tell me about CVE-2021-41773")
    assert hits[0].document.doc_id == "finding:b"
    assert hits[0].method in {"lexical", "hybrid"}


def test_retrieval_is_deterministic_and_capped() -> None:
    docs = lab_documents()
    retriever, _ = _retriever(docs)
    q = "Which attack paths reach the data zone through port 5432?"
    first = retriever.retrieve(engagement_id=ENGAGEMENT, question=q, limit=5)
    second = retriever.retrieve(engagement_id=ENGAGEMENT, question=q, limit=5)
    assert [h.model_dump_json() for h in first] == [h.model_dump_json() for h in second]
    assert len(first) <= 5
    assert len({h.document.doc_id for h in first}) == len(first)


def test_vector_hits_below_threshold_are_dropped() -> None:
    retriever, _ = _retriever([_doc("finding:a", "nginx heap overflow")])
    hits = retriever.retrieve(
        engagement_id=ENGAGEMENT, question="nginx heap overflow", min_vector_score=1.01
    )
    assert hits == []


def test_fake_embeddings_are_stable() -> None:
    a = FakeModelClient().embed(["CVE-2021-41773 on 172.20.1.10"])
    b = FakeModelClient().embed(["CVE-2021-41773 on 172.20.1.10"])
    assert a == b
    assert len(a[0]) == 64


def test_extract_terms_includes_cwe_ids() -> None:
    from services.assistant.retrieval import extract_terms

    assert extract_terms("weakness cwe-94 and CWE-22, not CWE-") == ["CWE-94", "CWE-22"]
