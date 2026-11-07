"""Wiring between the API and the Layer 4 assistant package (`services.assistant`).

The API reaches the assistant through three FastAPI dependencies, so tests can swap
each one:

- `get_model_client`  the ModelClient (Ollama in every environment, D-006)
- `get_vector_store`  the pgvector store for the client's embedding model (D-005)
- `get_assistant_core` the assistant's pure functions (document building, retrieval,
  answering, narration) behind one small object

`ServicesAssistantCore` imports `services.assistant` lazily, inside each method, so the
API process starts (and every non-assistant endpoint works) even if the assistant
package is incomplete. It also turns the package's `ModelUnavailableError` into this
module's `AssistantModelUnavailable`, so the router has one exception to map to 503.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from fastapi import Depends

from apps.api.assistant_store import PgVectorStore
from apps.api.core.config import settings
from apps.api.db.session import get_session_factory
from packages.schema.models.assistant import (
    Answer,
    AssistantDocument,
    PathNarration,
    RetrievedDocument,
)
from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.graph import AttackGraphResult, AttackPath, GraphNode
from packages.schema.models.observation import Observation
from packages.schema.models.topology import NetworkTopology
from services.assistant.interfaces import ModelClient, VectorStore


class AssistantModelUnavailable(RuntimeError):
    """The text or embedding model could not be reached (Ollama down, model not pulled)."""


class AssistantCore(Protocol):
    """What the API needs from `services.assistant`."""

    def documents_for_engagement(
        self,
        *,
        engagement_id: str,
        observations: Sequence[Observation],
        enriched_findings: Sequence[EnrichedFinding],
        graph: AttackGraphResult | None,
        topology: NetworkTopology | None,
    ) -> list[AssistantDocument]: ...

    def index(
        self, *, store: VectorStore, client: ModelClient, documents: Sequence[AssistantDocument]
    ) -> int:
        """Embed `documents` and upsert them into `store`."""
        ...

    def answer(
        self,
        *,
        question: str,
        engagement_id: str,
        store: VectorStore,
        client: ModelClient,
        limit: int,
    ) -> Answer: ...

    def narrate(
        self,
        *,
        path: AttackPath,
        nodes: Sequence[GraphNode],
        evidence: Sequence[AssistantDocument],
        client: ModelClient,
        engagement_id: str,
    ) -> PathNarration: ...


class ServicesAssistantCore:
    """`AssistantCore` backed by the real `services.assistant` modules."""

    @staticmethod
    def _unavailable() -> type[Exception]:
        from services.assistant.client import ModelUnavailableError

        error: type[Exception] = ModelUnavailableError
        return error

    def documents_for_engagement(
        self,
        *,
        engagement_id: str,
        observations: Sequence[Observation],
        enriched_findings: Sequence[EnrichedFinding],
        graph: AttackGraphResult | None,
        topology: NetworkTopology | None,
    ) -> list[AssistantDocument]:
        from services.assistant.documents import documents_for_engagement

        documents: list[AssistantDocument] = documents_for_engagement(
            engagement_id=engagement_id,
            observations=tuple(observations),
            enriched_findings=tuple(enriched_findings),
            graph=graph,
            topology=topology,
        )
        return documents

    def index(
        self, *, store: VectorStore, client: ModelClient, documents: Sequence[AssistantDocument]
    ) -> int:
        from services.assistant.retrieval import Retriever

        try:
            indexed: int = Retriever(store, client).index(documents)
        except self._unavailable() as exc:
            raise AssistantModelUnavailable(str(exc)) from exc
        return indexed

    def answer(
        self,
        *,
        question: str,
        engagement_id: str,
        store: VectorStore,
        client: ModelClient,
        limit: int,
    ) -> Answer:
        from services.assistant.answer import answer_question
        from services.assistant.retrieval import Retriever

        try:
            result: Answer = answer_question(
                question=question,
                engagement_id=engagement_id,
                retriever=Retriever(store, client),
                client=client,
                limit=limit,
            )
        except self._unavailable() as exc:
            raise AssistantModelUnavailable(str(exc)) from exc
        return result

    def narrate(
        self,
        *,
        path: AttackPath,
        nodes: Sequence[GraphNode],
        evidence: Sequence[AssistantDocument],
        client: ModelClient,
        engagement_id: str,
    ) -> PathNarration:
        from services.assistant.narration import narrate_path

        try:
            narration: PathNarration = narrate_path(
                path=path,
                nodes=nodes,
                evidence=evidence,
                client=client,
                engagement_id=engagement_id,
            )
        except self._unavailable() as exc:
            raise AssistantModelUnavailable(str(exc)) from exc
        return narration


class StagingStore:
    """Collects what an indexing run would write, so the API can embed everything
    first and then replace the engagement's rows in one transaction. A failed embed
    therefore leaves the previous index untouched."""

    def __init__(self) -> None:
        self.documents: list[AssistantDocument] = []
        self.vectors: list[list[float]] = []

    def upsert(
        self, documents: Sequence[AssistantDocument], vectors: Sequence[Sequence[float]]
    ) -> None:
        if len(documents) != len(vectors):
            raise ValueError(f"{len(documents)} documents but {len(vectors)} vectors")
        self.documents.extend(documents)
        self.vectors.extend([float(v) for v in vector] for vector in vectors)

    def search(
        self, *, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        return []

    def lexical(
        self, *, engagement_id: str, terms: Sequence[str], limit: int
    ) -> list[RetrievedDocument]:
        return []

    def get(self, *, engagement_id: str, doc_id: str) -> AssistantDocument | None:
        return next(
            (d for d in self.documents if d.engagement_id == engagement_id and d.doc_id == doc_id),
            None,
        )

    def delete_engagement(self, engagement_id: str) -> None:
        keep = [
            (d, v)
            for d, v in zip(self.documents, self.vectors, strict=True)
            if d.engagement_id != engagement_id
        ]
        self.documents = [d for d, _ in keep]
        self.vectors = [v for _, v in keep]


# -- FastAPI dependencies ---------------------------------------------------------


def get_model_client() -> ModelClient:
    from services.assistant.client import OllamaModelClient

    client: ModelClient = OllamaModelClient(
        base_url=settings.ollama_base_url,
        model=settings.assistant_model,
        embed_model=settings.assistant_embed_model,
        timeout_s=settings.assistant_timeout_seconds,
    )
    return client


def get_vector_store(client: ModelClient = Depends(get_model_client)) -> PgVectorStore:
    """The store for the client's embedding model, so stored vectors are always
    labelled with the model that produced them."""
    return PgVectorStore(get_session_factory(), embed_model=client.embed_model_name)


def get_assistant_core() -> AssistantCore:
    return ServicesAssistantCore()
