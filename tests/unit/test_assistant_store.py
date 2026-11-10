"""PgVectorStore on SQLite (the Python cosine fallback), the embedding column type, and
ORM/migration parity for `assistant_documents`.

The PostgreSQL path (pgvector `<=>`) is not exercised here: unit tests run on SQLite
and never start containers.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from alembic import command
from apps.api.assistant_store import PgVectorStore, cosine_similarity
from apps.api.db import models as _models  # noqa: F401 – registers tables
from apps.api.db.base import Base
from apps.api.db.models import AssistantDocumentModel
from apps.api.db.repositories import EngagementRepository
from apps.api.db.types import PgVector, parse_vector, vector_literal
from packages.schema.models.assistant import AssistantDocument
from packages.schema.models.engagement import Authorization, Engagement
from services.assistant.interfaces import VectorStore

REPO_ROOT = Path(__file__).resolve().parents[2]
EMBED = "test-embed"
ENG_A = "eng-a"
ENG_B = "eng-b"


@pytest.fixture
def factory():
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
    session_factory = sessionmaker(bind=eng, expire_on_commit=False)
    with session_factory() as session:
        for eid in (ENG_A, ENG_B):
            now = datetime.now(UTC)
            EngagementRepository(session).save(
                Engagement(
                    engagement_id=eid,
                    name=eid,
                    authorization=Authorization(
                        engagement_id=eid,
                        authorized_by="tester",
                        allowlist=("172.20.0.0/16",),
                        granted_at=now - timedelta(hours=1),
                        expires_at=now + timedelta(hours=1),
                    ),
                    created_at=now,
                )
            )
        session.commit()
    yield session_factory
    eng.dispose()


def _doc(doc_id: str, text: str, engagement_id: str = ENG_A, kind: str = "observation"):
    return AssistantDocument(
        doc_id=doc_id,
        kind=kind,  # type: ignore[arg-type]
        engagement_id=engagement_id,
        title=doc_id,
        text=text,
        metadata={"host": "172.20.1.10"},
    )


def test_is_a_vector_store(factory: sessionmaker[Session]) -> None:
    assert isinstance(PgVectorStore(factory, embed_model=EMBED), VectorStore)


def test_upsert_get_and_overwrite(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    store.upsert([_doc("obs:1", "nginx 1.18 on 172.20.1.10:80")], [[1.0, 0.0]])
    got = store.get(engagement_id=ENG_A, doc_id="obs:1")
    assert got == _doc("obs:1", "nginx 1.18 on 172.20.1.10:80")

    store.upsert([_doc("obs:1", "nginx 1.20 on 172.20.1.10:80")], [[0.0, 1.0]])
    assert store.count(ENG_A) == 1
    got = store.get(engagement_id=ENG_A, doc_id="obs:1")
    assert got is not None and "1.20" in got.text
    with factory() as session:
        row = session.get(AssistantDocumentModel, (ENG_A, "obs:1", EMBED))
        assert row is not None
        assert row.embedding == [0.0, 1.0]
        assert len(row.content_sha256) == 64


def test_get_is_engagement_and_model_scoped(factory: sessionmaker[Session]) -> None:
    PgVectorStore(factory, embed_model=EMBED).upsert([_doc("obs:1", "x")], [[1.0]])
    assert (
        PgVectorStore(factory, embed_model=EMBED).get(engagement_id=ENG_B, doc_id="obs:1") is None
    )
    other_model = PgVectorStore(factory, embed_model="other-embed")
    assert other_model.get(engagement_id=ENG_A, doc_id="obs:1") is None


def test_search_cosine_order_and_tie_break(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    store.upsert(
        [_doc("obs:c", "c"), _doc("obs:b", "b"), _doc("obs:a", "a"), _doc("obs:far", "far")],
        [[1.0, 0.0], [2.0, 0.0], [1.0, 0.0], [0.0, 1.0]],
    )
    hits = store.search(engagement_id=ENG_A, vector=[1.0, 0.0], limit=3)
    # Three identical similarities (1.0) ordered by doc_id; the orthogonal one is cut.
    assert [h.document.doc_id for h in hits] == ["obs:a", "obs:b", "obs:c"]
    assert all(h.method == "vector" for h in hits)
    assert all(math.isclose(h.score, 1.0) for h in hits)

    hits = store.search(engagement_id=ENG_A, vector=[0.0, 1.0], limit=10)
    assert hits[0].document.doc_id == "obs:far"
    assert math.isclose(hits[0].score, 1.0)


def test_search_is_engagement_scoped(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    store.upsert([_doc("obs:a", "a"), _doc("obs:b", "b", ENG_B)], [[1.0], [1.0]])
    hits = store.search(engagement_id=ENG_A, vector=[1.0], limit=10)
    assert [h.document.doc_id for h in hits] == ["obs:a"]
    assert store.search(engagement_id="eng-none", vector=[1.0], limit=10) == []


def test_search_skips_other_dimensions(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    store.upsert([_doc("obs:a", "a"), _doc("obs:b", "b")], [[1.0, 0.0], [1.0, 0.0, 0.0]])
    hits = store.search(engagement_id=ENG_A, vector=[1.0, 0.0], limit=10)
    assert [h.document.doc_id for h in hits] == ["obs:a"]


def test_lexical_counts_distinct_terms(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    store.upsert(
        [
            _doc("finding:2", "CVE-2022-22947 on 172.20.2.10 port 8080"),
            _doc("finding:1", "cve-2022-22947 spring gateway"),
            _doc("obs:1", "nothing relevant 100%"),
            _doc("obs:other", "CVE-2022-22947 172.20.2.10", ENG_B),
        ],
        [[1.0], [1.0], [1.0], [1.0]],
    )
    hits = store.lexical(engagement_id=ENG_A, terms=["CVE-2022-22947", "172.20.2.10"], limit=10)
    assert [(h.document.doc_id, h.score) for h in hits] == [("finding:2", 2.0), ("finding:1", 1.0)]
    assert all(h.method == "lexical" for h in hits)
    # LIKE wildcards in a term match only themselves.
    assert store.lexical(engagement_id=ENG_A, terms=["_"], limit=10) == []
    assert [
        h.document.doc_id for h in store.lexical(engagement_id=ENG_A, terms=["0%"], limit=10)
    ] == ["obs:1"]
    assert store.lexical(engagement_id=ENG_A, terms=[], limit=10) == []
    assert len(store.lexical(engagement_id=ENG_A, terms=["CVE-2022-22947"], limit=1)) == 1


def test_delete_and_replace_engagement(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    other_model = PgVectorStore(factory, embed_model="other-embed")
    store.upsert([_doc("obs:a", "a"), _doc("obs:b", "b"), _doc("obs:x", "x", ENG_B)], [[1.0]] * 3)
    other_model.upsert([_doc("obs:a", "a")], [[1.0, 2.0]])

    assert store.replace_engagement(ENG_A, [_doc("obs:new", "n")], [[0.5]]) == 1
    assert store.count(ENG_A) == 1
    assert store.get(engagement_id=ENG_A, doc_id="obs:a") is None
    assert store.count(ENG_B) == 1
    assert other_model.count(ENG_A) == 1  # other embedding model untouched

    with pytest.raises(ValueError, match="other engagements"):
        store.replace_engagement(ENG_A, [_doc("obs:z", "z", ENG_B)], [[1.0]])
    assert store.count(ENG_A) == 1  # rejected before anything was deleted

    store.delete_engagement(ENG_A)
    assert store.count(ENG_A) == 0
    assert store.count(ENG_B) == 1
    assert other_model.count(ENG_A) == 1


def test_rejects_bad_vectors(factory: sessionmaker[Session]) -> None:
    store = PgVectorStore(factory, embed_model=EMBED)
    with pytest.raises(ValueError):
        store.upsert([_doc("obs:a", "a")], [])
    with pytest.raises(ValueError):
        store.upsert([_doc("obs:a", "a")], [[float("nan")]])
    with pytest.raises(ValueError):
        store.upsert([_doc("obs:a", "a")], [[]])
    assert store.count(ENG_A) == 0


def test_cosine_similarity() -> None:
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == 0.0
    assert math.isclose(cosine_similarity([1.0, 1.0], [2.0, 2.0]), 1.0)
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0
    with pytest.raises(ValueError):
        cosine_similarity([1.0], [1.0, 2.0])


def test_vector_text_form_roundtrip() -> None:
    literal = vector_literal([1, 0.5, -2.25])
    assert literal == "[1.0,0.5,-2.25]"
    assert parse_vector(literal) == [1.0, 0.5, -2.25]
    with pytest.raises(ValueError):
        vector_literal([float("inf")])


def test_postgres_column_is_pgvector() -> None:
    column = AssistantDocumentModel.__table__.c.embedding
    compiled = column.type.dialect_impl(postgresql.dialect())
    assert isinstance(compiled, PgVector)
    assert compiled.get_col_spec() == "vector"
    bind = compiled.bind_processor(postgresql.dialect())
    assert bind([1.0, 2.0]) == "[1.0,2.0]"
    result = compiled.result_processor(postgresql.dialect(), None)
    assert result("[1,2]") == [1.0, 2.0]


def test_migration_matches_orm(tmp_path: Path) -> None:
    """`alembic upgrade head` and `create_all` agree on assistant_documents' columns,
    primary key and foreign keys (indexes are covered by test_alembic.py)."""
    migrated_url = f"sqlite:///{(tmp_path / 'm.db').as_posix()}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", migrated_url)
    command.upgrade(cfg, "head")
    migrated_engine = create_engine(migrated_url)
    created_engine = create_engine(f"sqlite:///{(tmp_path / 'c.db').as_posix()}")
    Base.metadata.create_all(bind=created_engine)
    try:
        migrated, created = inspect(migrated_engine), inspect(created_engine)
        table = "assistant_documents"

        def cols(insp):  # type: ignore[no-untyped-def]
            return {(c["name"], c["nullable"]) for c in insp.get_columns(table)}

        assert cols(migrated) == cols(created)
        assert migrated.get_pk_constraint(table)["constrained_columns"] == [
            "engagement_id",
            "doc_id",
            "embed_model",
        ]
        assert created.get_pk_constraint(table)["constrained_columns"] == [
            "engagement_id",
            "doc_id",
            "embed_model",
        ]
        fks = migrated.get_foreign_keys(table)
        assert [(fk["referred_table"], fk["constrained_columns"]) for fk in fks] == [
            ("engagements", ["engagement_id"])
        ]
    finally:
        migrated_engine.dispose()
        created_engine.dispose()
    command.downgrade(cfg, "0005")
    engine = create_engine(migrated_url)
    assert "assistant_documents" not in inspect(engine).get_table_names()
    engine.dispose()
