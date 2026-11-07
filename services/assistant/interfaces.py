"""The contracts every Layer 4 component codes against.

Implementations:
- `client.py`     OllamaModelClient, FakeModelClient (deterministic, for tests/CI)
- `retrieval.py`  InMemoryVectorStore, Retriever (hybrid: vector + exact lexical match)
- `documents.py`  pure builders turning schema records into AssistantDocument
- `citations.py`  parse `[cite:<doc_id>]` markers, validate, grounding check
- `narration.py`  narrate_path(...)
- `answer.py`     answer_question(...)

The pgvector-backed VectorStore lives in apps/api (it needs the database); this package
imports nothing from this repository except packages.schema (import firewall).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from packages.schema.models.assistant import AssistantDocument, RetrievedDocument


@runtime_checkable
class ModelClient(Protocol):
    """A text model plus an embedding model (DECISIONS.md D-006)."""

    @property
    def model_name(self) -> str: ...

    @property
    def embed_model_name(self) -> str: ...

    def generate(self, *, system: str, prompt: str) -> str:
        """One completion. Implementations use temperature 0 and a fixed seed where the
        backend supports it, so the same prompt gives the same text."""
        ...

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """One vector per text, same order."""
        ...


@runtime_checkable
class VectorStore(Protocol):
    """Engagement-scoped document store with vector search."""

    def upsert(
        self, documents: Sequence[AssistantDocument], vectors: Sequence[Sequence[float]]
    ) -> None: ...

    def search(
        self, *, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        """Nearest documents by cosine similarity, only from `engagement_id`."""
        ...

    def lexical(
        self, *, engagement_id: str, terms: Sequence[str], limit: int
    ) -> list[RetrievedDocument]:
        """Documents whose text contains any exact term (CVE ids, IPs, ports, host names).
        Score = number of distinct terms matched."""
        ...

    def get(self, *, engagement_id: str, doc_id: str) -> AssistantDocument | None: ...

    def delete_engagement(self, engagement_id: str) -> None: ...
