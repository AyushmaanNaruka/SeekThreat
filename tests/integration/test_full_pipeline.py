"""The whole platform, end to end, through the real API over the test database.

One engagement goes through every layer in the order a demo shows them:

1. **Authorization** — the engagement is created with a named authorizer and a lab
   allowlist. A scan of a lab host is accepted (the Celery dispatch is stubbed: nothing
   is scanned); a scan of a host outside the allowlist is refused with 403 and leaves
   no scan record.
2. **Collection** — the lab observation fixtures are written with `save_scan_result`,
   the call the scan worker makes after a real scan, by `scripts/seed_fixture_demo.py`
   (the demo's fixture mode), so this test also covers the seed script.
3. **Understanding** — the interim bridge's findings are enriched through
   `POST /findings/enrich/batch`, offline (empty mirror directory).
4. **Reasoning** — topology declared, attack graph read: paths, ordinal ranking,
   chokepoints. Every edge's evidence id and finding id is resolved through the API by
   `scripts/verify_attack_graph_evidence.py`, the same checker run against a live API.
   Remediation simulation removes exactly the paths the top chokepoint breaks.
5. **Conversation** — index, ask and narrate with `FakeModelClient` and an in-memory
   vector store. Every citation and every retrieved document id resolves to a stored
   record; narration cites only the path and its own evidence, and does not change the
   graph.

No network, no Docker, no Ollama, no scanner binary.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

import scripts.verify_attack_graph_evidence as evidence_verifier
from apps.api.assistant_runtime import (
    ServicesAssistantCore,
    get_assistant_core,
    get_model_client,
    get_vector_store,
)
from apps.api.core.audit import get_audit_log
from apps.api.core.config import settings
from apps.api.db.repositories import save_scan_result
from apps.api.main import app
from packages.schema.models.assistant import AssistantDocument, PathNarration
from packages.schema.models.observation import ScanResult
from scripts.seed_fixture_demo import ENGAGEMENT_ID, LAB_ALLOWLIST, fixture_scan_results, seed
from services.assistant.client import FakeModelClient
from services.assistant.retrieval import InMemoryVectorStore

AUTHORIZER = "lab-operator"
DETECTED_AT = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)
LAB_HOST = "172.20.1.13"  # spring-gateway, inside the allowlist
OFF_ALLOWLIST_HOST = "10.20.30.40"  # private, not in the lab, not in the allowlist
SPRING_GATEWAY_CVE = "CVE-2022-22947"


class InMemoryIndex(InMemoryVectorStore):
    """The reference in-memory store, plus the two calls the API makes on its store
    (`replace_engagement`, `count`) and the `embed_model` label it reads."""

    def __init__(self, embed_model: str) -> None:
        super().__init__()
        self.embed_model = embed_model
        self._counts: dict[str, int] = {}

    def replace_engagement(
        self,
        engagement_id: str,
        documents: Sequence[AssistantDocument],
        vectors: Sequence[Sequence[float]],
    ) -> int:
        self.delete_engagement(engagement_id)
        self.upsert(documents, vectors)
        self._counts[engagement_id] = len(documents)
        return len(documents)

    def count(self, engagement_id: str) -> int:
        return self._counts.get(engagement_id, 0)


@pytest.fixture
def assistant() -> Iterator[FakeModelClient]:
    client = FakeModelClient()
    store = InMemoryIndex(client.embed_model_name)
    app.dependency_overrides[get_model_client] = lambda: client
    app.dependency_overrides[get_vector_store] = lambda: store
    app.dependency_overrides[get_assistant_core] = ServicesAssistantCore
    yield client
    for dependency in (get_model_client, get_vector_store, get_assistant_core):
        app.dependency_overrides.pop(dependency, None)


@pytest.fixture
def offline_enrichment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No feed mirrors: enrichment runs fully offline on its fallback chain."""
    cache = tmp_path / "enrichment_cache"
    cache.mkdir()
    monkeypatch.setattr(settings, "enrichment_cache_dir", cache)
    return cache


@pytest.fixture
def scan_dispatch(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Accepted scans are queued on Celery; record the call instead of scanning."""
    import apps.api.tasks.scans as tasks_module

    mock = MagicMock(name="execute_scan.delay")
    monkeypatch.setattr(tasks_module.execute_scan, "delay", mock)
    return mock


# -- resolution helpers -----------------------------------------------------------------


def _scope() -> str:
    return f"engagement_id={quote(ENGAGEMENT_ID, safe='')}"


def _finding_resolves(client: TestClient, finding_id: str) -> bool:
    resp = client.get(f"/findings/{quote(finding_id, safe='')}?{_scope()}")
    return resp.status_code == 200 and resp.json()["finding"]["finding_id"] == finding_id


def _doc_resolves(client: TestClient, graph: dict[str, Any], doc_id: str) -> bool:
    """Does an assistant document id (= citation id) name a record the API serves?"""
    if doc_id.startswith("obs:"):
        resp = client.get(f"/observations/{quote(doc_id, safe='')}?{_scope()}")
        return resp.status_code == 200 and resp.json()["observation_id"] == doc_id
    if doc_id.startswith("finding:"):
        return _finding_resolves(client, doc_id.removeprefix("finding:"))
    if doc_id.startswith("chokepoint:"):
        finding_id = doc_id.removeprefix("chokepoint:")
        listed = {cp["finding_id"] for cp in graph["chokepoints"]}
        return finding_id in listed and _finding_resolves(client, finding_id)
    if doc_id.startswith("path:"):
        return doc_id in {p["path_id"] for p in graph["paths"]}
    if doc_id.startswith("topology:"):
        resp = client.get(f"/engagements/{ENGAGEMENT_ID}/topology")
        return resp.status_code == 200 and resp.json()["topology_id"] == doc_id
    return False


def _path_evidence(path: dict[str, Any]) -> set[str]:
    cited: set[str] = set()
    for edge in path["edges"]:
        cited.update(edge["evidence"])
        cited.update(f if f.startswith("finding:") else f"finding:{f}" for f in edge["finding_ids"])
    return cited


# -- the test ---------------------------------------------------------------------------


def test_full_pipeline_through_the_api(
    api_client: TestClient,
    db_session: Session,
    assistant: FakeModelClient,
    offline_enrichment: Path,
    scan_dispatch: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1-3. Engagement + authorization, fixture observations, enriched findings, topology,
    # all through the demo seed script, driving this API and this database.
    def persist(results: list[ScanResult]) -> None:
        for result in results:
            save_scan_result(db_session, result)
        db_session.commit()

    summary = seed(api_client, persist, authorized_by=AUTHORIZER, detected_at=DETECTED_AT)
    assert summary.engagement_created
    fixtures = fixture_scan_results()
    assert summary.observations == sum(len(r.observations) for r in fixtures) > 0
    assert summary.findings > 0

    engagement = api_client.get(f"/engagements/{ENGAGEMENT_ID}").json()
    assert engagement["authorized_by"] == AUTHORIZER
    assert engagement["allowlist"] == list(LAB_ALLOWLIST)

    # Authorization gate: a lab host is accepted and queued...
    accepted = api_client.post(
        "/scans", json={"engagement_id": ENGAGEMENT_ID, "scanner": "nmap", "target": LAB_HOST}
    )
    assert accepted.status_code == 202, accepted.text
    scan_dispatch.assert_called_once()
    assert scan_dispatch.call_args.args[3] == LAB_HOST
    assert scan_dispatch.call_args.args[5]["authorized_by"] == AUTHORIZER

    # ...a host outside the allowlist is refused at the API, never queued, never recorded.
    refused = api_client.post(
        "/scans",
        json={"engagement_id": ENGAGEMENT_ID, "scanner": "nmap", "target": OFF_ALLOWLIST_HOST},
    )
    assert refused.status_code == 403, refused.text
    assert "not authorized" in refused.json()["detail"].lower()
    scan_dispatch.assert_called_once()
    scans = api_client.get(f"/scans?{_scope()}").json()
    assert [s["target"] for s in scans] == [LAB_HOST]
    rejected = [e for e in get_audit_log() if e["event"] == "scan.rejected"]
    assert [e["target"] for e in rejected] == [OFF_ALLOWLIST_HOST]
    assert rejected[0]["actor"] == AUTHORIZER
    plan = api_client.post(
        "/scans/plan",
        json={"engagement_id": ENGAGEMENT_ID, "scanner": "nmap", "targets": [OFF_ALLOWLIST_HOST]},
    )
    assert plan.status_code == 200, plan.text
    assert plan.json()["planned"] == []
    assert [r["target"] for r in plan.json()["rejected"]] == [OFF_ALLOWLIST_HOST]

    # Findings: every one enriched and stored, every stored risk score explains itself.
    listed = api_client.get(f"/findings?{_scope()}&limit=1000").json()
    assert listed["total"] == summary.findings
    for item in listed["items"]:
        assert item["finding"]["observation_ids"], "a finding must trace to observations"
        if item.get("ers") is not None:
            assert item["ers"]["components"], "an ERS must carry its components"

    # 4. Attack graph: deterministic, ranked, every edge resolves to its evidence.
    graph_resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
    assert graph_resp.status_code == 200, graph_resp.text
    graph = graph_resp.json()
    assert graph["topology_id"] == summary.topology_id
    assert graph["paths"] and graph["chokepoints"]
    assert not graph["truncated"]
    assert sorted(p["rank"] for p in graph["paths"]) == list(range(1, len(graph["paths"]) + 1))
    assert all(p["rank_explanation"] and p["score"] is None for p in graph["paths"])
    assert sorted(cp["rank"] for cp in graph["chokepoints"]) == list(
        range(1, len(graph["chokepoints"]) + 1)
    )
    for edge in graph["edges"]:
        assert edge["rule_name"] and edge["evidence"], edge

    def _get_via_test_client(url: str, timeout: float) -> tuple[int, Any]:
        resp = api_client.get(url)
        return resp.status_code, resp.json()

    monkeypatch.setattr(evidence_verifier, "_get", _get_via_test_client)
    assert evidence_verifier.main(["--engagement-id", ENGAGEMENT_ID, "--api", "http://x"]) == 0

    # Remediation simulation: fixing the top chokepoint removes exactly its paths.
    top = min(graph["chokepoints"], key=lambda cp: cp["rank"])
    assert _finding_resolves(api_client, top["finding_id"])
    sim_resp = api_client.post(
        f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate",
        json={"fixed_finding_ids": [top["finding_id"]]},
    )
    assert sim_resp.status_code == 200, sim_resp.text
    sim = sim_resp.json()
    path_ids = {p["path_id"] for p in graph["paths"]}
    assert sim["baseline_path_count"] == len(path_ids)
    assert set(sim["removed_path_ids"]) == set(top["paths_broken"])
    assert set(sim["removed_path_ids"]) <= path_ids
    assert sim["remaining_path_count"] == len(path_ids) - len(sim["removed_path_ids"])
    assert {p["path_id"] for p in sim["after"]["paths"]} == path_ids - set(sim["removed_path_ids"])
    unknown = api_client.post(
        f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate",
        json={"fixed_finding_ids": ["fnd-not-recorded"]},
    )
    assert unknown.status_code == 422

    # 5. Assistant: index, ask, narrate. Every id the model saw or cited resolves.
    index = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
    assert index.status_code == 200, index.text
    by_kind = index.json()["by_kind"]
    assert {"observation", "finding", "path", "topology"} <= set(by_kind)

    for question in (
        f"Which hosts are affected by {SPRING_GATEWAY_CVE}?",
        f"What services are open on {LAB_HOST}?",
        "Which attack path should I fix first?",
    ):
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask", json={"question": question}
        )
        assert resp.status_code == 200, resp.text
        answer = resp.json()
        assert answer["engagement_id"] == ENGAGEMENT_ID
        assert answer["model"] == assistant.model_name
        assert not answer["refused"], answer
        assert answer["citations"], "an answer must cite what it used"
        assert answer["grounding"]["invalid_citations"] == []
        retrieved = {r["document"]["doc_id"] for r in answer["retrieved"]}
        for citation in answer["citations"]:
            assert citation["ref_id"] in retrieved
        for doc_id in retrieved:
            assert _doc_resolves(api_client, graph, doc_id), doc_id

    best = min(graph["paths"], key=lambda p: p["rank"])
    narrate = api_client.post(
        f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/{quote(best['path_id'], safe='')}/narrate"
    )
    assert narrate.status_code == 200, narrate.text
    narration = PathNarration.model_validate(narrate.json())
    assert narration.path_id == best["path_id"]
    assert narration.citations
    # The path itself, or a record one of its edges cites; nothing else.
    evidence = _path_evidence(best) | {best["path_id"]}
    for citation in narration.citations:
        assert citation.ref_id in evidence, citation.ref_id
        assert _doc_resolves(api_client, graph, citation.ref_id), citation.ref_id

    # Narration is never written back: the graph is byte-identical afterwards.
    again = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
    assert again.content == graph_resp.content
    assert all(p["narration"] is None for p in again.json()["paths"])

    # Every layer left an audit trail naming the authorizer.
    events = {e["event"]: e for e in get_audit_log()}
    for name in (
        "engagement.created",
        "enrichment.complete",
        "topology.declared",
        "attack_graph.read",
        "attack_graph.simulated",
        "assistant.indexed",
        "assistant.asked",
        "attack_graph.narrated",
    ):
        assert name in events, name
        assert events[name]["engagement_id"] == ENGAGEMENT_ID


def test_fixture_seed_is_rerunnable(
    api_client: TestClient,
    db_session: Session,
    offline_enrichment: Path,
) -> None:
    """Running the fixture-mode seed twice reuses the engagement and changes no fact."""

    def persist(results: list[ScanResult]) -> None:
        for result in results:
            save_scan_result(db_session, result)
        db_session.commit()

    first = seed(api_client, persist, authorized_by=AUTHORIZER, detected_at=DETECTED_AT)
    graph_before = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").content
    second = seed(api_client, persist, authorized_by=AUTHORIZER, detected_at=DETECTED_AT)

    assert first.engagement_created and not second.engagement_created
    assert second.notes and "reused" in second.notes[0]
    assert (second.observations, second.findings) == (first.observations, first.findings)
    assert api_client.get(f"/observations?{_scope()}").json()["total"] == first.observations
    assert api_client.get(f"/findings?{_scope()}").json()["total"] == first.findings
    assert api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").content == graph_before


def test_unknown_engagement_is_rejected_before_any_layer_runs(api_client: TestClient) -> None:
    now = datetime.now(UTC)
    assert (
        api_client.post(
            "/scans", json={"engagement_id": "eng-missing", "scanner": "nmap", "target": LAB_HOST}
        ).status_code
        == 404
    )
    assert api_client.get("/engagements/eng-missing/attack-graph").status_code == 404
    assert api_client.post("/engagements/eng-missing/assistant/index").status_code == 404
    # And an engagement cannot be re-created to widen its allowlist.
    payload = {
        "engagement_id": "eng-once",
        "name": "once",
        "authorized_by": AUTHORIZER,
        "allowlist": list(LAB_ALLOWLIST),
        "granted_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    assert api_client.post("/engagements", json=payload).status_code == 201
    wider = {**payload, "allowlist": ["0.0.0.0/0"]}
    assert api_client.post("/engagements", json=wider).status_code == 409
