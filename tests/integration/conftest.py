"""Shared fixtures for tests/integration: an in-memory SQLite database with every
table, a session on it, and a TestClient whose `get_db` is that session.

`test_e2e_flow.py` keeps its own differently named fixtures (it gives each request a
fresh session); the modules that use these names get them from here.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log
from apps.api.db import models as _models  # noqa: F401 - side effect: registers all tables
from apps.api.db.base import Base
from apps.api.db.session import get_db
from apps.api.main import app


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(eng, "connect")
    def set_pragma(dbapi_conn, _):  # type: ignore[no-untyped-def]
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


@pytest.fixture
def db_session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def api_client(db_session: Session) -> Iterator[TestClient]:
    def _override_get_db():  # type: ignore[no-untyped-def]
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_audit_log() -> Iterator[None]:
    clear_audit_log()
    yield
    clear_audit_log()
