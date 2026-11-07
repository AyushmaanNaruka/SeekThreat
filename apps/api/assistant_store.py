"""pgvector-backed VectorStore for the Layer 4 assistant (D-005).

Implements `services.assistant.interfaces.VectorStore` over the `assistant_documents`
table. Lives in apps/api, not services/assistant, because it needs the database and the
assistant package may import nothing but packages.schema (import firewall).

- Every operation is scoped to one engagement and to this store's embedding model.
- PostgreSQL: cosine search in SQL with pgvector's `<=>` (cosine distance).
- SQLite (unit tests): the engagement's rows are loaded and cosine is computed in
  Python. Same scores, same order.
- Ties are broken by `doc_id` ascending, so equal scores always come back in the same
  order on both backends.
"""

from __future__ import annotations

import hashlib
import logging
import math
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, delete, func, or_, select, text
from sqlalchemy.orm import Session, sessionmaker

from apps.api.db.models import AssistantDocumentModel
from apps.api.db.types import vector_literal
from packages.schema.models.assistant import AssistantDocument, RetrievedDocument

logger = logging.getLogger(__name__)


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity; 0.0 when either vector has zero length."""
    if len(a) != len(b):
        raise ValueError(f"vector dimensions differ: {len(a)} != {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


def _to_document(row: AssistantDocumentModel) -> AssistantDocument:
    return AssistantDocument(
        doc_id=row.doc_id,
        kind=row.kind,  # validated by pydantic
        engagement_id=row.engagement_id,
        title=row.title,
        text=row.text,
        metadata={str(k): str(v) for k, v in (row.metadata_ or {}).items()},
    )


class PgVectorStore:
    """Engagement-scoped document store with vector and exact-term search."""

    def __init__(self, session_factory: sessionmaker[Session], *, embed_model: str) -> None:
        if not embed_model.strip():
            raise ValueError("embed_model must name the embedding model")
        self._session_factory = session_factory
        self.embed_model = embed_model

    # -- helpers -----------------------------------------------------------------

    def _scoped(self, engagement_id: str) -> Select[tuple[AssistantDocumentModel]]:
        return select(AssistantDocumentModel).where(
            AssistantDocumentModel.engagement_id == engagement_id,
            AssistantDocumentModel.embed_model == self.embed_model,
        )

    def _rows(
        self, documents: Sequence[AssistantDocument], vectors: Sequence[Sequence[float]]
    ) -> list[AssistantDocumentModel]:
        if len(documents) != len(vectors):
            raise ValueError(f"{len(documents)} documents but {len(vectors)} vectors")
        now = datetime.now(UTC)
        rows: dict[tuple[str, str], AssistantDocumentModel] = {}
        for document, vector in zip(documents, vectors, strict=True):
            if not vector:
                raise ValueError(f"empty embedding for {document.doc_id!r}")
            vector_literal(vector)  # rejects NaN/inf before anything is written
            # A duplicate doc_id within one batch: the last one wins, as in a dict.
            rows[(document.engagement_id, document.doc_id)] = AssistantDocumentModel(
                engagement_id=document.engagement_id,
                doc_id=document.doc_id,
                embed_model=self.embed_model,
                kind=document.kind,
                title=document.title,
                text=document.text,
                metadata_=dict(document.metadata),
                content_sha256=hashlib.sha256(document.text.encode("utf-8")).hexdigest(),
                embedding=[float(v) for v in vector],
                indexed_at=now,
            )
        return list(rows.values())

    # -- VectorStore -------------------------------------------------------------

    def upsert(
        self, documents: Sequence[AssistantDocument], vectors: Sequence[Sequence[float]]
    ) -> None:
        rows = self._rows(documents, vectors)
        with self._session_factory() as session, session.begin():
            for row in rows:
                session.merge(row)

    def replace_engagement(
        self,
        engagement_id: str,
        documents: Sequence[AssistantDocument],
        vectors: Sequence[Sequence[float]],
    ) -> int:
        """Atomically replace this engagement's documents (for this embedding model)
        with `documents`. Returns how many rows are stored."""
        stray = sorted({d.engagement_id for d in documents} - {engagement_id})
        if stray:
            raise ValueError(f"documents from other engagements: {stray}")
        rows = self._rows(documents, vectors)
        with self._session_factory() as session, session.begin():
            session.execute(
                delete(AssistantDocumentModel).where(
                    AssistantDocumentModel.engagement_id == engagement_id,
                    AssistantDocumentModel.embed_model == self.embed_model,
                )
            )
            session.add_all(rows)
        return len(rows)

    def search(
        self, *, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        if limit <= 0 or not vector:
            return []
        with self._session_factory() as session:
            if session.get_bind().dialect.name == "postgresql":
                return self._search_pg(session, engagement_id, vector, limit)
            return self._search_python(session, engagement_id, vector, limit)

    def _search_pg(
        self, session: Session, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        # Rows embedded at another dimension cannot be compared (pgvector raises), so
        # they are filtered out, matching the Python fallback.
        stmt = text(
            "SELECT doc_id, 1 - (embedding <=> CAST(:q AS vector)) AS score "
            "FROM assistant_documents "
            "WHERE engagement_id = :eid AND embed_model = :model "
            "AND vector_dims(embedding) = :dim "
            "ORDER BY embedding <=> CAST(:q AS vector), doc_id "
            "LIMIT :limit"
        )
        hits = session.execute(
            stmt,
            {
                "q": vector_literal(vector),
                "eid": engagement_id,
                "model": self.embed_model,
                "dim": len(vector),
                "limit": limit,
            },
        ).all()
        if not hits:
            return []
        scores = {str(h.doc_id): float(h.score) for h in hits}
        rows = session.scalars(
            self._scoped(engagement_id).where(AssistantDocumentModel.doc_id.in_(list(scores)))
        ).all()
        by_id = {r.doc_id: r for r in rows}
        return [
            RetrievedDocument(document=_to_document(by_id[d]), score=s, method="vector")
            for d, s in scores.items()
            if d in by_id
        ]

    def _search_python(
        self, session: Session, engagement_id: str, vector: Sequence[float], limit: int
    ) -> list[RetrievedDocument]:
        scored: list[tuple[float, AssistantDocumentModel]] = []
        skipped = 0
        for row in session.scalars(self._scoped(engagement_id)):
            embedding = list(row.embedding)
            if len(embedding) != len(vector):
                skipped += 1
                continue
            scored.append((cosine_similarity(vector, embedding), row))
        if skipped:
            logger.warning(
                "skipped %d assistant documents embedded at another dimension "
                "(engagement=%s, model=%s)",
                skipped,
                engagement_id,
                self.embed_model,
            )
        scored.sort(key=lambda item: (-item[0], item[1].doc_id))
        return [
            RetrievedDocument(document=_to_document(row), score=score, method="vector")
            for score, row in scored[:limit]
        ]

    def lexical(
        self, *, engagement_id: str, terms: Sequence[str], limit: int
    ) -> list[RetrievedDocument]:
        wanted = sorted({t.strip() for t in terms if t.strip()})
        if limit <= 0 or not wanted:
            return []
        # Case-insensitive substring match: ILIKE on PostgreSQL, lower() LIKE on SQLite.
        # Wildcards in a term are escaped, so `%` or `_` match only themselves.
        match_any = or_(
            *(AssistantDocumentModel.text.icontains(term, autoescape=True) for term in wanted)
        )
        with self._session_factory() as session:
            rows = session.scalars(self._scoped(engagement_id).where(match_any)).all()
        lowered = [t.lower() for t in wanted]
        scored: list[tuple[int, AssistantDocumentModel]] = []
        for row in rows:
            body = row.text.lower()
            matched = len({t for t in lowered if t in body})
            if matched:
                scored.append((matched, row))
        scored.sort(key=lambda item: (-item[0], item[1].doc_id))
        return [
            RetrievedDocument(document=_to_document(row), score=float(score), method="lexical")
            for score, row in scored[:limit]
        ]

    def get(self, *, engagement_id: str, doc_id: str) -> AssistantDocument | None:
        with self._session_factory() as session:
            row = session.get(AssistantDocumentModel, (engagement_id, doc_id, self.embed_model))
            return _to_document(row) if row is not None else None

    def delete_engagement(self, engagement_id: str) -> None:
        with self._session_factory() as session, session.begin():
            session.execute(
                delete(AssistantDocumentModel).where(
                    AssistantDocumentModel.engagement_id == engagement_id,
                    AssistantDocumentModel.embed_model == self.embed_model,
                )
            )

    # -- extras (not part of the VectorStore protocol) ----------------------------

    def count(self, engagement_id: str) -> int:
        """How many documents this engagement has indexed under this embedding model."""
        with self._session_factory() as session:
            total: Any = session.scalar(
                select(func.count())
                .select_from(AssistantDocumentModel)
                .where(
                    AssistantDocumentModel.engagement_id == engagement_id,
                    AssistantDocumentModel.embed_model == self.embed_model,
                )
            )
        return int(total or 0)
