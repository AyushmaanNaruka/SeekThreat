"""Layer 4 deterministic quality fixes, one test per failure mode seen in the first eval
run (evals/results/assistant_eval_qwen2_5_7b.md). Every model reply here is scripted
through FakeModelClient; nothing is measured."""

from __future__ import annotations

import logging

import pytest

from packages.schema.models.assistant import AssistantDocument
from packages.schema.models.citation import CitationKind
from services.assistant.answer import (
    REFUSAL_TEXT,
    answer_question,
    build_answer_prompt,
    is_substantive_partial_answer,
)
from services.assistant.citations import (
    check_grounding,
    parse_citation_ids,
    resolve_citation,
    resolve_citations,
)
from services.assistant.client import FakeModelClient
from services.assistant.prompts import ANSWER_SYSTEM
from services.assistant.retrieval import (
    InMemoryVectorStore,
    Retriever,
    extract_doc_ids,
    extract_host_names,
    host_aliases,
    rank_terms,
)

ENG = "eng-quality"
OBS_A = "obs:sha256:1e1773838a21e6f6e409f6a59d6546e18453622a6e818e91b7e0e4facad984fe"
OBS_B = "obs:sha256:5fb6d5dba8bf29154a294e43c885cb4a3b581d849a653faf7795556252b00d58"
PATH_A = "path:0fea8d14814606ae"
PATH_B = "path:096cb4fb98f61033"
PATH_C = "path:456a860ed4f55b66"


def _doc(
    doc_id: str,
    text: str,
    kind: CitationKind = "observation",
    metadata: dict[str, str] | None = None,
) -> AssistantDocument:
    return AssistantDocument(
        doc_id=doc_id,
        kind=kind,
        engagement_id=ENG,
        title=doc_id,
        text=text,
        metadata=metadata or {},
    )


# ------------------------------------------------------------------- citation parsing


def test_annotation_words_inside_a_marker_are_not_ids() -> None:
    # attack_paths-001: [cite:path:e5a10ed4e3a51500, step 2] gave invalid ids "step", "2".
    assert parse_citation_ids("x [cite:path:e5a10ed4e3a51500, step 2]") == ["path:e5a10ed4e3a51500"]
    # attack_paths-008: [cite:path:...#Step 5] gave "path:...#Step" and "5".
    assert parse_citation_ids(f"x [cite:{PATH_B}#Step 5]") == [f"{PATH_B}#Step"]


def test_pasted_step_text_in_a_marker_is_one_invalid_id_not_nine() -> None:
    # cve_lookups-018 pasted a whole path step into the marker.
    text = (
        "[cite:chokepoint:Step 4: Network access to 172.20.2.40:8090/tcp (http) "
        "-[exploit_grants_code_execution, high]"
    )
    assert parse_citation_ids(text) == ["chokepoint:Step"]


def test_space_separated_ids_in_one_marker_are_all_kept() -> None:
    assert parse_citation_ids(f"[cite:{PATH_A} {PATH_B}]") == [PATH_A, PATH_B]


# -------------------------------------------------------------------- citation repair


@pytest.mark.parametrize(
    ("cited", "supplied", "resolved", "rule"),
    [
        # cve_lookups-005: one character inserted.
        ("path:08fea8d14814606ae", [PATH_A, PATH_B], PATH_A, "edit_distance_1"),
        # remediation-003: one character dropped from a 64-hex observation id.
        (OBS_A.replace("6e818e9", "6818e9"), [OBS_A, OBS_B], OBS_A, "edit_distance_1"),
        # cve_lookups-002: the kind written twice.
        ("chokepoint:path:456a860ed4f55b66", [PATH_C, PATH_A], PATH_C, "extra_prefix"),
        # cve_lookups-028: a spelled-out kind prefix.
        ("observation:" + OBS_A, [OBS_A, OBS_B], OBS_A, "extra_prefix"),
        # attack_paths-008: a "#Step" fragment.
        (f"{PATH_B}#Step", [PATH_A, PATH_B], PATH_B, "normalised"),
        # multi_hop-008 shape: the kind prefix dropped.
        (OBS_B.removeprefix("obs:"), [OBS_A, OBS_B], OBS_B, "missing_prefix"),
        ("path:456a860ed4f5...", [PATH_C, PATH_A], PATH_C, "truncated"),
        (PATH_A.upper(), [PATH_A], PATH_A, "case"),
    ],
)
def test_near_miss_resolves_to_the_one_supplied_id(
    cited: str, supplied: list[str], resolved: str, rule: str
) -> None:
    assert resolve_citation(cited, supplied) == (resolved, rule)


@pytest.mark.parametrize(
    ("cited", "supplied"),
    [
        # Not supplied in this context: multi_hop-008's obs ids were not retrieved.
        (OBS_B.removeprefix("obs:"), [PATH_A, PATH_B]),
        # Ambiguous: both supplied ids are one edit away.
        ("path:0fea8d14814606a0", ["path:0fea8d14814606a1", "path:0fea8d14814606a2"]),
        # Ambiguous: a bare finding id names both the finding and its chokepoint.
        (
            "fnd-103129260b2f1a5740feabc1",
            ["finding:fnd-103129260b2f1a5740feabc1", "chokepoint:fnd-103129260b2f1a5740feabc1"],
        ),
        # A different kind prefix is a different record: never swapped (multi_hop-003).
        ("exploit_grants_code_execution:fnd-1031", ["chokepoint:fnd-1031"]),
        # Document numbers are not ids (remediation-001, cve_lookups-014).
        ("doc:6", [PATH_A, PATH_B, PATH_C]),
        ("chokepoint:doc-8", [PATH_A, PATH_B, PATH_C]),
        # cve_lookups-020: a fragment of an id that was not supplied.
        ("chokepoint:581f6d5c38e90add221be337e4aa9e95", [PATH_A, OBS_A]),
        # Too short to guess at.
        ("path:0fe", [PATH_A]),
        ("path:1", ["path:2"]),
    ],
)
def test_unresolvable_or_ambiguous_ids_stay_invalid(cited: str, supplied: list[str]) -> None:
    assert resolve_citation(cited, supplied) == (None, None)


def test_resolve_citations_rewrites_only_repaired_markers_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    text = f"Gateway RCE [cite:path:08fea8d14814606ae]. Seen [cite:{OBS_A}]. Bogus [cite:doc:6]."
    with caplog.at_level(logging.INFO, logger="services.assistant.citations"):
        rewritten, repairs = resolve_citations(text, {PATH_A, OBS_A})
    assert rewritten == f"Gateway RCE [cite:{PATH_A}]. Seen [cite:{OBS_A}]. Bogus [cite:doc:6]."
    assert [(r.cited, r.resolved, r.rule) for r in repairs] == [
        ("path:08fea8d14814606ae", PATH_A, "edit_distance_1")
    ]
    assert any(rec.getMessage() == "citation repaired" for rec in caplog.records)


# ----------------------------------------------------------------------- grounding


def test_port_proto_form_matches_an_endpoint_in_the_document() -> None:
    """The eval's unsupported `80/tcp` entities were checked: the endpoint form
    `ip:80/tcp` in a cited document already supports `80/tcp`."""
    check = check_grounding(
        text="nginx on 172.20.1.12, 80/tcp [cite:obs:1].",
        cited=[_doc("obs:1", "endpoint: 172.20.1.12:80/tcp")],
        supplied_ids={"obs:1"},
    )
    assert check.unsupported_entities == ()


def test_entity_in_a_supplied_but_uncited_document_stays_unsupported() -> None:
    # Strictness kept: cve_lookups-008 cited the chokepoint, CWE-94 is only in the finding.
    check = check_grounding(
        text="CVE-2022-22947 is CWE-94 [cite:chokepoint:fnd-1].",
        cited=[_doc("chokepoint:fnd-1", "Chokepoint rank 1: CVE-2022-22947", "finding")],
        supplied_ids={"chokepoint:fnd-1", "finding:fnd-1"},
    )
    assert check.unsupported_entities == ("CWE-94",)


# --------------------------------------------------------------- answer, end to end


def _lab_retriever(client: FakeModelClient) -> Retriever:
    docs = [
        _doc(
            OBS_A,
            "Observation: scanner nuclei reported vuln_candidate for http://172.20.1.13:8080/.\n"
            "endpoint: 172.20.1.13:8080/tcp\ncve_ids: CVE-2022-22947\ncwe_ids: CWE-94\n"
            "cvss_score: 10.0",
        ),
        _doc(
            OBS_B,
            "Observation: scanner nmap reported service for 172.20.1.13:8080/tcp.\n"
            "product: Spring Cloud Gateway\nversion: 3.1.0",
        ),
        _doc(
            "obs:sha256:" + "c" * 64,
            "Observation: scanner nmap reported host_up for 172.20.2.40.\n"
            "hostname: lab-internal-wiki-1.lab_internal",
        ),
        _doc(
            "finding:fnd-1031",
            f"Finding fnd-1031 on asset host:172.20.1.13.\nCVEs: CVE-2022-22947.\n"
            f"Observations: {OBS_A}.",
            "finding",
        ),
        _doc(
            "chokepoint:fnd-1031",
            "Chokepoint rank 1: finding fnd-1031 (CVE-2022-22947) on host:172.20.1.13.\n"
            "Fixing it breaks 11 of the enumerated attack paths.",
            "finding",
            {"rank": "1"},
        ),
        _doc(
            PATH_A,
            f"Attack path {PATH_A}, proven by the deterministic rules engine.\n"
            "Rank: 1. high confidence.\nConfidence: high (the weakest step).\n"
            "Step 1: Attacker foothold in zone dmz -[entry_zone_service_access, high]-> "
            "Network access to 172.20.1.13:8080/tcp (http)\n"
            f"  Evidence: {OBS_B}\n"
            "Step 2: Network access to 172.20.1.13:8080/tcp (http) "
            "-[exploit_grants_code_execution, high]-> Code execution on spring-gateway "
            "(172.20.1.13, 172.20.2.13): CVE-2022-22947\n"
            f"  Evidence: finding:fnd-1031, {OBS_A}\n  Findings: fnd-1031",
            "path",
            {"rank": "1"},
        ),
        _doc(
            PATH_B,
            f"Attack path {PATH_B}, proven by the deterministic rules engine.\n"
            "Rank: 2. high confidence.\n"
            "Step 1: Code execution on spring-gateway (172.20.1.13, 172.20.2.13) "
            "-[intra_zone_service_access, high]-> Network access to 172.20.2.40:8090/tcp: "
            "CVE-2022-26134 on 172.20.2.40:8090/tcp",
            "path",
            {"rank": "2"},
        ),
        _doc(
            "topology:sha256:71f6",
            "Declared network topology.\nMulti-homed host spring-gateway: 172.20.1.13, "
            "172.20.2.13.",
            "topology",
        ),
    ]
    retriever = Retriever(InMemoryVectorStore(), client)
    retriever.index(docs)
    return retriever


def test_repaired_citation_becomes_a_citation_and_grounds_its_entities() -> None:
    client = FakeModelClient(
        responses=lambda s, p: "CVE-2022-22947 on 172.20.1.13 [cite:observation:" + OBS_A + "]."
    )
    answer = answer_question(
        question="Which CVE did nuclei report on 172.20.1.13?",
        engagement_id=ENG,
        retriever=_lab_retriever(client),
        client=client,
    )
    assert not answer.refused
    assert [c.ref_id for c in answer.citations] == [OBS_A]
    assert f"[cite:{OBS_A}]" in answer.text
    assert answer.grounding.invalid_citations == ()
    assert answer.grounding.unsupported_entities == ()
    assert [r.rule for r in answer.grounding.repaired_citations] == ["extra_prefix"]
    assert answer.grounding.grounded


def test_repair_does_not_ground_an_entity_the_resolved_document_lacks() -> None:
    client = FakeModelClient(
        responses=lambda s, p: "CVE-2022-26134 on 172.20.1.13 [cite:observation:" + OBS_A + "]."
    )
    answer = answer_question(
        question="Which CVE did nuclei report on 172.20.1.13?",
        engagement_id=ENG,
        retriever=_lab_retriever(client),
        client=client,
    )
    assert answer.grounding.unsupported_entities == ("CVE-2022-26134",)
    assert not answer.grounding.grounded


def test_partial_answer_with_a_valid_citation_is_not_a_refusal() -> None:
    reply = f"The scanner records CVSS 10.0 [cite:{OBS_A}]. {REFUSAL_TEXT}"
    client = FakeModelClient(responses=lambda s, p: reply)
    answer = answer_question(
        question="What CVSS and EPSS does CVE-2022-22947 have on 172.20.1.13?",
        engagement_id=ENG,
        retriever=_lab_retriever(client),
        client=client,
    )
    assert not answer.refused
    assert answer.text == reply
    assert [c.ref_id for c in answer.citations] == [OBS_A]


@pytest.mark.parametrize(
    "reply",
    [
        REFUSAL_TEXT,
        f"{REFUSAL_TEXT} [cite:{OBS_A}]",
        f"The documents talk about other hosts. {REFUSAL_TEXT}",
        f"The documents talk about other hosts [cite:doc:6]. {REFUSAL_TEXT}",
    ],
)
def test_refusal_without_a_cited_partial_answer_is_still_a_refusal(reply: str) -> None:
    client = FakeModelClient(responses=lambda s, p: reply)
    answer = answer_question(
        question="Who owns 172.20.1.13?",
        engagement_id=ENG,
        retriever=_lab_retriever(client),
        client=client,
    )
    assert answer.refused
    assert answer.text == REFUSAL_TEXT
    assert answer.citations == ()


def test_partial_answer_needs_words_besides_the_refusal() -> None:
    assert not is_substantive_partial_answer(f"[cite:{OBS_A}] {REFUSAL_TEXT}", {OBS_A})
    assert is_substantive_partial_answer(f"CVSS is 10.0 [cite:{OBS_A}]. {REFUSAL_TEXT}", {OBS_A})


def test_prompt_lists_citable_ids_and_asks_for_partial_answers() -> None:
    docs = [_doc(OBS_A, "x"), _doc(PATH_A, "y", "path")]
    prompt = build_answer_prompt("Which CVE?", docs)
    assert f"- {OBS_A}\n- {PATH_A}" in prompt
    assert prompt.count("Question: Which CVE?") == 2
    assert "Never cite a document number" in prompt
    assert "partial" in ANSWER_SYSTEM
    assert REFUSAL_TEXT in ANSWER_SYSTEM


# ------------------------------------------------------------------------ retrieval


def test_question_terms_extraction() -> None:
    q = f"Walk me through {PATH_A} and finding:fnd-1031 on dmz-proxy, the best-ranked one"
    assert extract_doc_ids(q) == [PATH_A, "finding:fnd-1031"]
    assert extract_host_names(q) == ["dmz-proxy", "best-ranked"]
    assert extract_host_names("CVE-2021-23017 and CWE-94 and fnd-1031") == []
    assert extract_host_names("On spring-gateway: which port?") == ["spring-gateway"]


def test_host_aliases_come_only_from_explicit_document_forms() -> None:
    docs = [
        _doc("topology:1", "Multi-homed host dmz-proxy: 172.20.1.12, 172.20.2.12.", "topology"),
        _doc("path:1", "Code execution on dmz-proxy (172.20.1.12, 172.20.2.12)", "path"),
        _doc(
            "obs:1",
            "Observation: nmap reported host_up for 172.20.2.40.\n"
            "hostname: lab-internal-wiki-1.lab_internal",
        ),
        _doc("obs:2", "dmz-proxy was mentioned near 10.0.0.9 in prose"),
    ]
    assert host_aliases("dmz-proxy", docs) == ["172.20.1.12", "172.20.2.12"]
    assert host_aliases("internal-wiki", docs) == ["172.20.2.40"]


def test_rank_terms() -> None:
    assert rank_terms("The rank 2 chokepoint: which service?") == ["Chokepoint rank 2:"]
    assert rank_terms("Which attack path is ranked first, and why?") == ["Rank: 1."]
    assert rank_terms("the best-ranked attack path to db-primary") == []
    assert rank_terms("Which is the rank 1 attack path?") == ["Rank: 1."]
    assert rank_terms("List the chokepoints in rank order") == ["Chokepoint rank"]


def test_named_path_id_is_fetched_even_when_nothing_else_matches() -> None:
    # attack_paths-014..028: the path named in the question was not retrieved at all.
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG,
        question=f"Walk me through attack path {PATH_B} and say how confident the engine is.",
    )
    assert [h.document.doc_id for h in hits] == [PATH_B]
    assert hits[0].score == 1.0


def test_named_id_from_another_engagement_is_not_fetched() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    assert retriever.retrieve(engagement_id="eng-other", question=f"Walk me through {PATH_B}") == []


def test_host_name_question_reaches_documents_that_only_hold_its_address() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG, question="What CVSS does the scanner record on spring-gateway?"
    )
    ids = [h.document.doc_id for h in hits]
    assert OBS_A in ids
    # Not a path question: path documents do not lead.
    assert retriever.store.get(engagement_id=ENG, doc_id=ids[0]).kind != "path"  # type: ignore[union-attr]


def test_focused_context_when_a_document_holds_every_identifier() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG, question="Which CVE did nuclei report on 172.20.1.13?", limit=8
    )
    assert 0 < len(hits) <= 4
    assert all(h.method in {"lexical", "hybrid"} for h in hits)
    assert hits[0].document.doc_id == OBS_A  # nuclei observation: kind, coverage, wording


def test_path_question_ranks_paths_first_by_engine_rank() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG, question="Is there an attack path to spring-gateway?"
    )
    assert [h.document.doc_id for h in hits][:2] == [PATH_A, PATH_B]


def test_dash_word_that_no_document_holds_is_not_an_identifier() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    groups = retriever.term_groups(
        engagement_id=ENG, question="the best-ranked attack path to spring-gateway"
    )
    assert groups == [("spring-gateway", "172.20.1.13", "172.20.2.13")]


def test_service_question_on_a_chokepoint_follows_stored_links_to_the_endpoint() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG,
        question="The rank 1 chokepoint: which service and version does it sit on?",
    )
    ids = [h.document.doc_id for h in hits]
    assert ids[0] == "chokepoint:fnd-1031"
    # chokepoint -> finding -> its observation -> same-endpoint nmap service observation
    assert {"finding:fnd-1031", OBS_A, OBS_B} <= set(ids)


def test_service_question_on_a_path_adds_that_paths_evidence() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    hits = retriever.retrieve(
        engagement_id=ENG,
        question="On the best-ranked attack path to spring-gateway, which product version?",
    )
    ids = [h.document.doc_id for h in hits]
    assert ids[0] == PATH_A
    assert {OBS_B, "finding:fnd-1031", OBS_A} <= set(ids)


def test_retrieval_with_new_rules_is_deterministic() -> None:
    client = FakeModelClient()
    retriever = _lab_retriever(client)
    q = "The rank 1 chokepoint on spring-gateway: which service and version?"
    a = retriever.retrieve(engagement_id=ENG, question=q)
    b = retriever.retrieve(engagement_id=ENG, question=q)
    assert [h.model_dump_json() for h in a] == [h.model_dump_json() for h in b]
    assert len({h.document.doc_id for h in a}) == len(a)
