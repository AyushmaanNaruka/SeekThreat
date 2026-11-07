"""Custom column types.

`EMBEDDING_TYPE` stores an embedding vector: pgvector's `vector` on PostgreSQL (D-005),
a JSON list of floats on SQLite (unit tests). Written without the `pgvector` Python
package, which is not a dependency of this project: on PostgreSQL the value travels as
pgvector's text form `[1,2,3]`, which psycopg 3 sends untyped so the server casts it to
`vector` on insert (the same way pgvector-python's own SQLAlchemy type does), and comes
back as the same text form, parsed here.

The column has no fixed dimension, so different embedding models can share the table.
That rules out an HNSW/IVFFlat index (both need a dimension); at our corpus size an
exact scan per engagement is fine (D-005).
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Sequence
from typing import Any

from sqlalchemy import JSON
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeEngine, UserDefinedType


def vector_literal(values: Sequence[float]) -> str:
    """pgvector's text form. Rejects NaN/inf, which pgvector rejects too."""
    parts: list[str] = []
    for value in values:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("embedding values must be finite")
        parts.append(repr(number))
    return "[" + ",".join(parts) + "]"


def parse_vector(value: Any) -> list[float]:
    """Parse pgvector's text form (or an already-decoded list) into floats."""
    if isinstance(value, str):
        value = json.loads(value)
    return [float(v) for v in value]


class PgVector(UserDefinedType[list[float]]):
    """pgvector `vector` with no fixed dimension."""

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "vector"

    def bind_processor(self, dialect: Dialect) -> Callable[[Any], str | None]:
        def process(value: Any) -> str | None:
            return None if value is None else vector_literal(value)

        return process

    def result_processor(
        self, dialect: Dialect, coltype: object
    ) -> Callable[[Any], list[float] | None]:
        def process(value: Any) -> list[float] | None:
            return None if value is None else parse_vector(value)

        return process


EMBEDDING_TYPE: TypeEngine[Any] = JSON().with_variant(PgVector(), "postgresql")
