"""Unit tests for the Layer 4 API: index, ask, narrate and status.

The routing, persistence, scoping, error mapping and audit behaviour are tested with
local doubles for the model client and for the assistant core (`StubCore`), so these
tests do not depend on `services.assistant`'s implementation. `TestRealCore` runs the
same flow through the real `services.assistant` modules and is skipped until they exist.

Facts are the lab observation fixtures plus lab/topology.yaml, loaded as in
test_attack_graph_api.py. Nothing here contacts Ollama.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.assistant_runtime import (
    AssistantModelUnavailable,
    ServicesAssistantCore,
    get_assistant_core,
    get_model_client,
    get_vector_store,
)
from apps.api.assistant_store import PgVectorStore
from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.core.config import settings
from apps.api.db import models as _models  # noqa: F401 – registers all tables
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    RawArtifactRepository,
)
from apps.api.db.session import get_db
from apps.api.main import app
from apps.api.routers.assistant import get_assistant_settings, get_status_http_client
from packages.schema.models.assistant import (
    Answer,
    AssistantDocument,
    PathNarration,
)
from packages.schema.models.citation import Citation
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.graph import AttackGraphResult, AttackPath, GraphNode
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.topology import NetworkTopology
from services.assistant.interfaces import ModelClient, VectorStore
from services.normalize import findings_from_observations

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "observations"
LAB_TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"
ENGAGEMENT_ID = "eng-lab-baseline"
OTHER_ENGAGEMENT_ID = "eng-other"
AUTHORIZER = "lab-operator"
DETECTED_AT = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)
SPRING_GATEWAY_CVE = "CVE-2022-22947"
EMBED_MODEL = "fake-embed"


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class LocalFakeClient:
    """Deterministic ModelClient: bag-of-words hashing embeddings, canned generation."""

    def __init__(self, *, dim: int = 64, unavailable: bool = False) -> None:
        self.dim = dim
        self.unavailable = unavailable
        self.embed_calls = 0

    @property
    def model_name(self) -> str:
        return "fake-model"

    @property
    def embed_model_name(self) -> str:
        return EMBED_MODEL

    def generate(self, *, system: str, prompt: str) -> str:
        return "generated"

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.embed_calls += 1
        vectors = []
        for text in texts:
            vec = [0.0] * self.dim
            for token in re.findall(r"[a-z0-9.\-]+", text.lower()):
                vec[int(hashlib.sha256(token.encode()).hexdigest(), 16) % self.dim] += 1.0
            vectors.append(vec)
        return vectors


_TERM = re.compile(r"CVE-\d{4}-\d{4,7}|\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE)


class StubCore:
    """Minimal AssistantCore: one document per record, retrieval through the store,
    an answer that cites what was retrieved. Not the real assistant, just enough to
    drive the API."""

    def __init__(self) -> None:
        self.narrate_calls: list[dict[str, Any]] = []

    def documents_for_engagement(
        self,
        *,
        engagement_id: str,
        observations: Sequence[Observation],
        enriched_findings: Sequence[EnrichedFinding],
        graph: AttackGraphResult | None,
        topology: NetworkTopology | None,
    ) -> list[AssistantDocument]:
        docs = [
            AssistantDocument(
                doc_id=o.observation_id,
                kind="observation",
                engagement_id=engagement_id,
                title=f"{o.kind.value} {o.subject}",
                text=f"{o.kind.value} {o.subject} {sorted(o.attributes.items())}",
            )
            for o in observations
        ]
        docs += [
            AssistantDocument(
                doc_id=f"finding:{e.finding.finding_id}",
                kind="finding",
                engagement_id=engagement_id,
                title=e.finding.title or e.finding.finding_id,
                text=f"{' '.join(e.finding.cve_ids)} on {e.finding.asset_id}",
            )
            for e in enriched_findings
        ]
        if topology is not None:
            docs.append(
                AssistantDocument(
                    doc_id=topology.topology_id,
                    kind="topology",
                    engagement_id=engagement_id,
                    title="topology",
                    text=" ".join(z.name for z in topology.zones),
                )
            )
        if graph is not None:
            docs += [
                AssistantDocument(
                    doc_id=p.path_id,
                    kind="path",
                    engagement_id=engagement_id,
                    title=p.path_id,
                    text=" -> ".join([p.entry_node, *(e.to_node for e in p.edges)]),
                )
                for p in graph.paths
            ]
        return docs

    def index(
        self, *, store: VectorStore, client: ModelClient, documents: Sequence[AssistantDocument]
    ) -> int:
        if getattr(client, "unavailable", False):
            raise AssistantModelUnavailable("connection refused")
        store.upsert(documents, client.embed([d.text for d in documents]))
        return len(documents)

    def answer(
        self,
        *,
        question: str,
        engagement_id: str,
        store: VectorStore,
        client: ModelClient,
        limit: int,
    ) -> Answer:
        if getattr(client, "unavailable", False):
            raise AssistantModelUnavailable("connection refused")
        terms = _TERM.findall(question)
        hits = store.lexical(engagement_id=engagement_id, terms=terms, limit=limit)
        if not hits:
            return Answer(
                question=question,
                engagement_id=engagement_id,
                text="I don't have that data.",
                refused=True,
                refusal_reason="nothing retrieved",
                model=client.model_name,
            )
        return Answer(
            question=question,
            engagement_id=engagement_id,
            text=f"See [cite:{hits[0].document.doc_id}]",
            citations=tuple(Citation(kind=h.document.kind, ref_id=h.document.doc_id) for h in hits),
            retrieved=tuple(hits),
            model=client.model_name,
        )

    def narrate(
        self,
        *,
        path: AttackPath,
        nodes: Sequence[GraphNode],
        evidence: Sequence[AssistantDocument],
        client: ModelClient,
        engagement_id: str,
    ) -> PathNarration:
        if getattr(client, "unavailable", False):
            raise AssistantModelUnavailable("connection refused")
        self.narrate_calls.append({"path": path, "nodes": nodes, "evidence": evidence})
        return PathNarration(
            path_id=path.path_id,
            engagement_id=engagement_id,
            text=f"Narration of {len(path.edges)} steps.",
            citations=tuple(Citation(kind=d.kind, ref_id=d.doc_id) for d in evidence),
            model=client.model_name,
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db_session(session_factory):
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def fake_client() -> LocalFakeClient:
    return LocalFakeClient()


@pytest.fixture
def stub_core() -> StubCore:
    return StubCore()


@pytest.fixture
def store(session_factory) -> PgVectorStore:
    return PgVectorStore(session_factory, embed_model=EMBED_MODEL)


@pytest.fixture
def api_client(db_session, fake_client, stub_core, store):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_model_client] = lambda: fake_client
    app.dependency_overrides[get_vector_store] = lambda: store
    app.dependency_overrides[get_assistant_core] = lambda: stub_core
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_audit_log():
    clear_audit_log()
    yield
    clear_audit_log()


def _seed_engagement(db: Session, engagement_id: str = ENGAGEMENT_ID) -> None:
    now = datetime.now(UTC)
    EngagementRepository(db).save(
        Engagement(
            engagement_id=engagement_id,
            name="Lab engagement",
            authorization=Authorization(
                engagement_id=engagement_id,
                authorized_by=AUTHORIZER,
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db.commit()


def _seed_facts(db: Session) -> None:
    observations: list[Observation] = []
    for path in sorted(FIXTURES.glob("*.json")):
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        RawArtifactRepository(db).save(result.artifact)
        ObservationRepository(db).save_all(result.observations)
        observations.extend(result.observations)
    findings = findings_from_observations(observations, detected_at=DETECTED_AT)
    EnrichedFindingRepository(db).upsert_all(
        [EnrichedFinding(finding=f) for f in findings], enriched_at=DETECTED_AT
    )
    db.commit()


def _put_topology(client: TestClient) -> None:
    document = yaml.safe_load(LAB_TOPOLOGY.read_text(encoding="utf-8"))
    document["engagement_id"] = ENGAGEMENT_ID
    resp = client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=document)
    assert resp.status_code == 200, resp.text


def _seed_lab(db: Session, client: TestClient, *, topology: bool = True) -> None:
    _seed_engagement(db)
    _seed_facts(db)
    if topology:
        _put_topology(client)


def _events(name: str) -> list[dict[str, Any]]:
    return [e for e in get_audit_log() if e["event"] == name]


def _first_path(client: TestClient) -> dict[str, Any]:
    graph = client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").json()
    assert graph["paths"], "the lab fixtures should yield at least one path"
    return dict(graph["paths"][0])


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------


class TestIndex:
    def test_indexes_all_kinds(
        self, api_client: TestClient, db_session: Session, store: PgVectorStore
    ) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert set(body) == {"engagement_id", "indexed", "by_kind", "embed_model"}
        assert body["engagement_id"] == ENGAGEMENT_ID
        assert body["embed_model"] == EMBED_MODEL
        assert set(body["by_kind"]) == {"observation", "finding", "topology", "path"}
        assert body["indexed"] == sum(body["by_kind"].values()) == store.count(ENGAGEMENT_ID)

        audit = _events("assistant.indexed")
        assert len(audit) == 1
        assert audit[0]["actor"] == AUTHORIZER
        assert audit[0]["details"]["indexed"] == body["indexed"]
        assert audit[0]["details"]["graph"]["paths"] == body["by_kind"]["path"]

    def test_without_topology_has_no_graph_documents(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client, topology=False)
        body = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index").json()
        assert set(body["by_kind"]) == {"observation", "finding"}

    def test_reindex_replaces(
        self, api_client: TestClient, db_session: Session, store: PgVectorStore
    ) -> None:
        _seed_lab(db_session, api_client)
        stale = AssistantDocument(
            doc_id="obs:stale", kind="observation", engagement_id=ENGAGEMENT_ID, title="s", text="s"
        )
        store.upsert([stale], [[1.0] * 64])
        first = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index").json()
        second = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index").json()
        assert first == second
        assert store.get(engagement_id=ENGAGEMENT_ID, doc_id="obs:stale") is None
        assert store.count(ENGAGEMENT_ID) == second["indexed"]

    def test_unavailable_model_is_503_and_keeps_old_index(
        self,
        api_client: TestClient,
        db_session: Session,
        store: PgVectorStore,
        fake_client: LocalFakeClient,
    ) -> None:
        _seed_lab(db_session, api_client)
        indexed = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index").json()
        fake_client.unavailable = True
        resp = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        assert resp.status_code == 503
        detail = resp.json()["detail"]
        assert "ollama serve" in detail and "--profile model" in detail
        assert "ollama pull fake-model" in detail
        assert store.count(ENGAGEMENT_ID) == indexed["indexed"]
        assert _events("assistant.index_rejected")[0]["status"] == "model_unavailable"

    def test_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        assert api_client.post("/engagements/eng-missing/assistant/index").status_code == 404


# ---------------------------------------------------------------------------
# Ask
# ---------------------------------------------------------------------------


class TestAsk:
    def test_ask_before_index_is_409(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask", json={"question": "What is open?"}
        )
        assert resp.status_code == 409
        assert f"/engagements/{ENGAGEMENT_ID}/assistant/index" in resp.json()["detail"]
        assert _events("assistant.ask_rejected")[0]["status"] == "not_indexed"

    def test_index_then_ask_cites_records(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        question = f"Which hosts are affected by {SPRING_GATEWAY_CVE}?"
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask", json={"question": question, "limit": 5}
        )
        assert resp.status_code == 200, resp.text
        answer = Answer.model_validate(resp.json())
        assert not answer.refused
        assert answer.engagement_id == ENGAGEMENT_ID
        assert answer.citations
        assert any(c.ref_id.startswith("finding:") for c in answer.citations)
        assert all(r.document.engagement_id == ENGAGEMENT_ID for r in answer.retrieved)
        assert len(answer.retrieved) <= 5

        audit = _events("assistant.asked")[0]
        assert audit["actor"] == AUTHORIZER
        assert audit["details"]["question_length"] == len(question)
        assert audit["details"]["question_sha256"] == hashlib.sha256(question.encode()).hexdigest()
        assert question not in str(audit)

    def test_unsupported_question_is_refused_not_error(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask",
            json={"question": "Is CVE-1999-0001 present?"},
        )
        assert resp.status_code == 200
        assert resp.json()["refused"] is True
        assert _events("assistant.asked")[0]["status"] == "refused"

    def test_ask_is_engagement_scoped(
        self, api_client: TestClient, db_session: Session, store: PgVectorStore
    ) -> None:
        _seed_lab(db_session, api_client)
        _seed_engagement(db_session, OTHER_ENGAGEMENT_ID)
        store.upsert(
            [
                AssistantDocument(
                    doc_id="finding:other",
                    kind="finding",
                    engagement_id=OTHER_ENGAGEMENT_ID,
                    title="other",
                    text=f"{SPRING_GATEWAY_CVE} on 10.9.9.9",
                )
            ],
            [[1.0] * 64],
        )
        # The other engagement has documents, this one has none: still 409 here.
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask",
            json={"question": f"{SPRING_GATEWAY_CVE}?"},
        )
        assert resp.status_code == 409
        api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        body = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask",
            json={"question": f"{SPRING_GATEWAY_CVE}?"},
        ).json()
        assert "finding:other" not in {c["ref_id"] for c in body["citations"]}

    def test_unavailable_model_is_503(
        self, api_client: TestClient, db_session: Session, fake_client: LocalFakeClient
    ) -> None:
        _seed_lab(db_session, api_client)
        api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        fake_client.unavailable = True
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask", json={"question": "anything"}
        )
        assert resp.status_code == 503
        assert "ollama pull fake-embed" in resp.json()["detail"]

    @pytest.mark.parametrize(
        "body",
        [
            {"question": ""},
            {"question": "   "},
            {"question": "x" * 2001},
            {"question": "ok", "limit": 0},
            {"question": "ok", "limit": 21},
            {},
        ],
    )
    def test_invalid_body_is_422(
        self, api_client: TestClient, db_session: Session, body: dict[str, Any]
    ) -> None:
        _seed_engagement(db_session)
        resp = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/ask", json=body)
        assert resp.status_code == 422

    def test_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        resp = api_client.post("/engagements/eng-missing/assistant/ask", json={"question": "q"})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Narrate
# ---------------------------------------------------------------------------


class TestNarrate:
    def test_narrates_with_only_the_paths_evidence(
        self, api_client: TestClient, db_session: Session, stub_core: StubCore
    ) -> None:
        _seed_lab(db_session, api_client)
        path = _first_path(api_client)
        before = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").content

        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/{path['path_id']}/narrate"
        )
        assert resp.status_code == 200, resp.text
        narration = PathNarration.model_validate(resp.json())
        assert narration.path_id == path["path_id"]

        call = stub_core.narrate_calls[0]
        assert call["path"].path_id == path["path_id"]
        cited = {ev for e in path["edges"] for ev in e["evidence"]} | {
            f"finding:{f}" for e in path["edges"] for f in e["finding_ids"]
        }
        evidence_ids = {d.doc_id for d in call["evidence"]}
        assert evidence_ids and evidence_ids <= cited
        node_ids = {n.node_id for n in call["nodes"]}
        assert node_ids == {path["edges"][0]["from_node"]} | {e["to_node"] for e in path["edges"]}

        # Narration is never written back into the graph.
        after = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
        assert after.content == before
        assert all(p["narration"] is None for p in after.json()["paths"])
        assert _events("attack_graph.narrated")[0]["actor"] == AUTHORIZER

    def test_unknown_path_is_404(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/path:0000000000000000/narrate"
        )
        assert resp.status_code == 404
        assert _events("attack_graph.narrate_rejected")[0]["status"] == "not_found"

    def test_no_topology_is_409(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client, topology=False)
        resp = api_client.post(f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/path:x/narrate")
        assert resp.status_code == 409

    def test_unavailable_model_is_503(
        self, api_client: TestClient, db_session: Session, fake_client: LocalFakeClient
    ) -> None:
        _seed_lab(db_session, api_client)
        path = _first_path(api_client)
        fake_client.unavailable = True
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/{path['path_id']}/narrate"
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _status_client(handler: Any) -> TestClient:
    def _http() -> Any:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            yield client

    app.dependency_overrides[get_status_http_client] = _http
    app.dependency_overrides[get_assistant_settings] = lambda: settings.model_copy(
        update={"ollama_base_url": "http://ollama.test:11434"}
    )
    return TestClient(app, raise_server_exceptions=True)


class TestStatus:
    def teardown_method(self) -> None:
        app.dependency_overrides.clear()

    def test_unreachable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        resp = _status_client(handler).get("/assistant/status")
        assert resp.status_code == 200
        assert resp.json() == {
            "ollama_base_url": "http://ollama.test:11434",
            "model": settings.assistant_model,
            "embed_model": settings.assistant_embed_model,
            "reachable": False,
            "models_available": None,
        }
        assert _events("assistant.status_read")[0]["status"] == "unreachable"

    def test_reachable_lists_models(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/tags"
            return httpx.Response(
                200, json={"models": [{"name": "qwen2.5:7b"}, {"name": "nomic-embed-text:latest"}]}
            )

        body = _status_client(handler).get("/assistant/status").json()
        assert body["reachable"] is True
        assert body["models_available"] == ["nomic-embed-text:latest", "qwen2.5:7b"]

    @pytest.mark.parametrize(
        "response",
        [httpx.Response(500, text="boom"), httpx.Response(200, text="not json")],
    )
    def test_bad_responses_are_unreachable_not_500(self, response: httpx.Response) -> None:
        resp = _status_client(lambda request: response).get("/assistant/status")
        assert resp.status_code == 200
        assert resp.json()["reachable"] is False


# ---------------------------------------------------------------------------
# The real services.assistant (skipped until the core modules are merged)
# ---------------------------------------------------------------------------

_CORE_MODULES = ("client", "documents", "retrieval", "answer", "narration")
_HAVE_CORE = all(
    importlib.util.find_spec(f"services.assistant.{m}") is not None for m in _CORE_MODULES
)


@pytest.mark.skipif(not _HAVE_CORE, reason="services.assistant core modules not present yet")
class TestRealCore:
    @pytest.fixture
    def real_client(self, session_factory):
        from services.assistant.client import FakeModelClient

        client = FakeModelClient()
        real_store = PgVectorStore(session_factory, embed_model=client.embed_model_name)
        app.dependency_overrides[get_model_client] = lambda: client
        app.dependency_overrides[get_vector_store] = lambda: real_store
        app.dependency_overrides[get_assistant_core] = ServicesAssistantCore
        return client

    def test_index_ask_narrate(
        self, api_client: TestClient, db_session: Session, real_client: Any
    ) -> None:
        _seed_lab(db_session, api_client)
        index = api_client.post(f"/engagements/{ENGAGEMENT_ID}/assistant/index")
        assert index.status_code == 200, index.text
        assert index.json()["indexed"] > 0

        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/assistant/ask",
            json={"question": f"Which hosts are affected by {SPRING_GATEWAY_CVE}?"},
        )
        assert resp.status_code == 200, resp.text
        answer = Answer.model_validate(resp.json())
        assert all(r.document.engagement_id == ENGAGEMENT_ID for r in answer.retrieved)

        path = _first_path(api_client)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/paths/{path['path_id']}/narrate"
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["path_id"] == path["path_id"]

    def test_model_unavailable_maps_to_503(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from services.assistant import retrieval
        from services.assistant.client import FakeModelClient, ModelUnavailableError

        def boom(self: Any, documents: Any) -> int:
            raise ModelUnavailableError("down")

        monkeypatch.setattr(retrieval.Retriever, "index", boom)
        with pytest.raises(AssistantModelUnavailable):
            ServicesAssistantCore().index(
                store=retrieval.InMemoryVectorStore(), client=FakeModelClient(), documents=[]
            )
