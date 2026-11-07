"""Layer 4 endpoints: the retrieval index, grounded questions, and path narration.

- POST /engagements/{engagement_id}/assistant/index                    (re)build the index
- POST /engagements/{engagement_id}/assistant/ask                      answer a question
- POST /engagements/{engagement_id}/attack-graph/paths/{path_id}/narrate  narrate one path
- GET  /assistant/status                                               is Ollama reachable?

Hard Rule 1: nothing here creates, edits or filters graph edges. The graph is rebuilt
by `services.graph.analyze` exactly as GET .../attack-graph builds it, and the model is
handed one proven path plus the records it cites, to narrate. Narration is returned to
the caller and never written back into a graph result.

Every engagement call writes an audit event with the engagement's authorizer as actor
and the engagement ID as the authorization reference. Questions are audited by length
and SHA-256, not by their text.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterator
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from apps.api.assistant_runtime import (
    AssistantCore,
    AssistantModelUnavailable,
    StagingStore,
    get_assistant_core,
    get_model_client,
    get_vector_store,
)
from apps.api.assistant_store import PgVectorStore
from apps.api.core.audit import log_audit_event
from apps.api.core.config import Settings, settings
from apps.api.db.repositories import (
    EnrichedFindingRepository,
    ObservationRepository,
    TopologyRepository,
)
from apps.api.db.session import get_db
from apps.api.routers.attack_graph import (
    MAX_DEPTH_LIMIT,
    MAX_PATHS_LIMIT,
    _graph_summary,
    _load_facts,
    _require_engagement,
)
from packages.schema.models.assistant import Answer, PathNarration
from packages.schema.models.engagement import Engagement
from packages.schema.models.graph import AttackGraphResult
from services.assistant.interfaces import ModelClient
from services.graph import analyze
from services.graph.engine import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATHS

router = APIRouter()

AUDIT_SCANNER = "assistant"
MAX_QUESTION_CHARS = 2000
MAX_ANSWER_LIMIT = 20
DEFAULT_ANSWER_LIMIT = 8


class AskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=MAX_QUESTION_CHARS)
    limit: int = Field(DEFAULT_ANSWER_LIMIT, ge=1, le=MAX_ANSWER_LIMIT)

    @field_validator("question")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("question must not be blank")
        return value


class IndexResponse(BaseModel):
    engagement_id: str
    indexed: int
    by_kind: dict[str, int]
    embed_model: str


class AssistantStatus(BaseModel):
    ollama_base_url: str
    model: str
    embed_model: str
    reachable: bool
    # Model tags Ollama reports as pulled; null when Ollama could not be asked.
    models_available: list[str] | None


# -- dependencies used only here ---------------------------------------------------


def get_assistant_settings() -> Settings:
    return settings


def get_status_http_client(
    config: Settings = Depends(get_assistant_settings),
) -> Iterator[httpx.Client]:
    with httpx.Client(timeout=config.assistant_status_timeout_seconds) as client:
        yield client


# -- helpers -------------------------------------------------------------------------


def _audit(
    engagement: Engagement, event: str, target: str, result: str, details: dict[str, Any]
) -> None:
    log_audit_event(
        event=event,
        actor=engagement.authorization.authorized_by,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=AUDIT_SCANNER,
        status=result,
        details=details,
    )


def _unavailable(
    engagement: Engagement,
    event: str,
    target: str,
    exc: AssistantModelUnavailable,
    client: ModelClient,
    details: dict[str, Any] | None = None,
) -> HTTPException:
    _audit(
        engagement,
        event,
        target,
        "model_unavailable",
        {**(details or {}), "reason": str(exc), "model": client.model_name},
    )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            f"The assistant model is unavailable: {exc}. Start Ollama (`ollama serve`, or "
            "`docker compose -f infra/docker-compose.yml --profile model up -d ollama`) "
            f"at {settings.ollama_base_url}, then pull the models: "
            f"`ollama pull {client.model_name}` and `ollama pull {client.embed_model_name}`. "
            "GET /assistant/status shows what Ollama reports."
        ),
    )


def _question_details(question: str) -> dict[str, Any]:
    return {
        "question_length": len(question),
        "question_sha256": hashlib.sha256(question.encode("utf-8")).hexdigest(),
    }


# -- endpoints -----------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/assistant/index",
    response_model=IndexResponse,
    summary="Build (or rebuild) the assistant's retrieval index for an engagement",
)
def index_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    client: ModelClient = Depends(get_model_client),
    store: PgVectorStore = Depends(get_vector_store),
    core: AssistantCore = Depends(get_assistant_core),
) -> IndexResponse:
    """Turns the engagement's observations, enriched findings, declared topology and
    (when a topology is declared) attack graph into documents, embeds them and replaces
    the engagement's index for the current embedding model. Everything is embedded
    before anything is replaced, so a failure leaves the previous index intact."""
    event_rejected = "assistant.index_rejected"
    engagement = _require_engagement(db, engagement_id, event=event_rejected)
    target = f"engagement:{engagement_id}/assistant/index"

    observations = ObservationRepository(db).get_by_engagement(engagement_id)
    enriched = EnrichedFindingRepository(db).get_by_engagement(engagement_id)
    topology = TopologyRepository(db).get(engagement_id)
    graph: AttackGraphResult | None = None
    if topology is not None:
        graph = analyze(
            engagement_id=engagement_id,
            observations=observations,
            findings=[e.finding for e in enriched],
            topology=topology,
            enriched=enriched,
        )

    documents = core.documents_for_engagement(
        engagement_id=engagement_id,
        observations=observations,
        enriched_findings=enriched,
        graph=graph,
        topology=topology,
    )
    staging = StagingStore()
    try:
        core.index(store=staging, client=client, documents=documents)
    except AssistantModelUnavailable as exc:
        raise _unavailable(
            engagement, event_rejected, target, exc, client, {"documents": len(documents)}
        ) from exc
    indexed = store.replace_engagement(engagement_id, staging.documents, staging.vectors)
    by_kind = dict(sorted(Counter(d.kind for d in staging.documents).items()))

    _audit(
        engagement,
        "assistant.indexed",
        target,
        "success",
        {
            "indexed": indexed,
            "by_kind": by_kind,
            "embed_model": store.embed_model,
            "topology_id": topology.topology_id if topology else None,
            "graph": _graph_summary(graph) if graph else None,
        },
    )
    return IndexResponse(
        engagement_id=engagement_id,
        indexed=indexed,
        by_kind=by_kind,
        embed_model=store.embed_model,
    )


@router.post(
    "/engagements/{engagement_id}/assistant/ask",
    response_model=Answer,
    summary="Ask a question; the answer cites the indexed facts it used",
)
def ask(
    engagement_id: str,
    request: AskRequest,
    db: Session = Depends(get_db),
    client: ModelClient = Depends(get_model_client),
    store: PgVectorStore = Depends(get_vector_store),
    core: AssistantCore = Depends(get_assistant_core),
) -> Answer:
    """Answers only from this engagement's indexed documents. `refused: true` with a
    reason is a correct answer when the data does not support one. 409 until the
    engagement has been indexed; 503 when the model cannot be reached."""
    event_rejected = "assistant.ask_rejected"
    engagement = _require_engagement(db, engagement_id, event=event_rejected)
    target = f"engagement:{engagement_id}/assistant"
    question = _question_details(request.question)

    if store.count(engagement_id) == 0:
        _audit(engagement, event_rejected, target, "not_indexed", question)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Engagement {engagement_id!r} has no assistant index for embedding model "
                f"{store.embed_model!r}. Build it first with "
                f"POST /engagements/{engagement_id}/assistant/index (and again after new "
                "scans, findings or a topology change)."
            ),
        )

    try:
        answer = core.answer(
            question=request.question,
            engagement_id=engagement_id,
            store=store,
            client=client,
            limit=request.limit,
        )
    except AssistantModelUnavailable as exc:
        raise _unavailable(engagement, event_rejected, target, exc, client, question) from exc

    _audit(
        engagement,
        "assistant.asked",
        target,
        "refused" if answer.refused else "success",
        {
            **question,
            "limit": request.limit,
            "model": answer.model,
            "retrieved": len(answer.retrieved),
            "citations": [c.ref_id for c in answer.citations],
            "refusal_reason": answer.refusal_reason,
            "grounded": answer.grounding.grounded,
        },
    )
    return answer


@router.post(
    "/engagements/{engagement_id}/attack-graph/paths/{path_id}/narrate",
    response_model=PathNarration,
    summary="Narrate one proven attack path from its own edges and evidence",
)
def narrate(
    engagement_id: str,
    path_id: str,
    max_depth: int = Query(DEFAULT_MAX_DEPTH, ge=1, le=MAX_DEPTH_LIMIT),
    max_paths: int = Query(DEFAULT_MAX_PATHS, ge=1, le=MAX_PATHS_LIMIT),
    db: Session = Depends(get_db),
    client: ModelClient = Depends(get_model_client),
    core: AssistantCore = Depends(get_assistant_core),
) -> PathNarration:
    """Rebuilds the graph exactly as GET .../attack-graph does (pass the same
    `max_depth`/`max_paths`), finds `path_id`, and hands the model that path, its nodes
    and the records its edges cite. The narration is not stored anywhere."""
    event_rejected = "attack_graph.narrate_rejected"
    engagement = _require_engagement(db, engagement_id, event=event_rejected)
    target = f"engagement:{engagement_id}/attack-graph/paths/{path_id}"
    facts = _load_facts(db, engagement, event_rejected, target)
    result = analyze(
        engagement_id=engagement_id,
        observations=facts.observations,
        findings=facts.findings,
        topology=facts.topology,
        enriched=facts.enriched,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    path = next((p for p in result.paths if p.path_id == path_id), None)
    if path is None:
        reason = f"Path {path_id!r} is not in the attack graph of engagement {engagement_id!r}"
        if result.truncated:
            reason += f" (enumeration was truncated at max_paths={max_paths}; try a larger one)"
        _audit(engagement, event_rejected, target, "not_found", {"reason": reason})
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=reason)

    # The records this path's edges cite, and nothing else.
    cited: set[str] = set()
    for edge in path.edges:
        cited.update(edge.evidence)
        cited.update(f if f.startswith("finding:") else f"finding:{f}" for f in edge.finding_ids)
    observations = [o for o in facts.observations if o.observation_id in cited]
    enriched = [e for e in facts.enriched if f"finding:{e.finding.finding_id}" in cited]
    topology = facts.topology if facts.topology.topology_id in cited else None
    evidence = core.documents_for_engagement(
        engagement_id=engagement_id,
        observations=observations,
        enriched_findings=enriched,
        graph=None,
        topology=topology,
    )
    on_path = {path.entry_node} | {e.to_node for e in path.edges}
    nodes = [n for n in result.nodes if n.node_id in on_path]

    details: dict[str, Any] = {
        "path_id": path_id,
        "edges": len(path.edges),
        "evidence_documents": len(evidence),
        "rules_digest": result.rules_digest,
        "topology_id": result.topology_id,
    }
    try:
        narration = core.narrate(
            path=path, nodes=nodes, evidence=evidence, client=client, engagement_id=engagement_id
        )
    except AssistantModelUnavailable as exc:
        raise _unavailable(engagement, event_rejected, target, exc, client, details) from exc

    _audit(
        engagement,
        "attack_graph.narrated",
        target,
        "success",
        {
            **details,
            "model": narration.model,
            "citations": [c.ref_id for c in narration.citations],
            "grounded": narration.grounding.grounded,
        },
    )
    return narration


@router.get(
    "/assistant/status",
    response_model=AssistantStatus,
    summary="Is the model server reachable, and which models does it have?",
)
def assistant_status(
    config: Settings = Depends(get_assistant_settings),
    http: httpx.Client = Depends(get_status_http_client),
) -> AssistantStatus:
    """One cheap GET {OLLAMA_BASE_URL}/api/tags. Never fails: an unreachable or
    misbehaving server is reported as `reachable: false`, `models_available: null`."""
    reachable = False
    models: list[str] | None = None
    error: str | None = None
    try:
        response = http.get(config.ollama_base_url.rstrip("/") + "/api/tags")
        response.raise_for_status()
        payload = response.json()
        entries = payload.get("models", []) if isinstance(payload, dict) else []
        models = sorted(
            {
                str(m.get("name") or m.get("model"))
                for m in entries
                if isinstance(m, dict) and (m.get("name") or m.get("model"))
            }
        )
        reachable = True
    except Exception as exc:  # noqa: BLE001 — status must never 500
        error = f"{type(exc).__name__}: {exc}"

    log_audit_event(
        event="assistant.status_read",
        actor="system:api",
        target="assistant",
        engagement_id="n/a",
        scanner=AUDIT_SCANNER,
        status="success" if reachable else "unreachable",
        details={"ollama_base_url": config.ollama_base_url, "error": error},
    )
    return AssistantStatus(
        ollama_base_url=config.ollama_base_url,
        model=config.assistant_model,
        embed_model=config.assistant_embed_model,
        reachable=reachable,
        models_available=models,
    )
