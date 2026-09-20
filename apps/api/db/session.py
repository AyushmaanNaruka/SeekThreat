"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from apps.api.core.config import settings

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine(url: str | None = None) -> Engine:
    """Return or initialize the global SQLAlchemy Engine."""
    global _engine
    if _engine is None or url is not None:
        db_url = url or settings.database_url
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        eng = create_engine(
            db_url,
            echo=False,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        if url is None:
            _engine = eng
        return eng
    return _engine


def get_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    """Return or initialize the global SessionLocal factory."""
    global _session_factory
    eng = engine or get_engine()
    if _session_factory is None or engine is not None:
        factory = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=eng,
            expire_on_commit=False,
        )
        if engine is None:
            _session_factory = factory
        return factory
    return _session_factory


def SessionLocal() -> Session:
    """Convenience callable returning a new Session instance."""
    return get_session_factory()()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a transactional session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
