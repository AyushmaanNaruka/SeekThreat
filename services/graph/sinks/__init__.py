"""Pure output adapters for the attack graph.

A sink turns an `AttackGraphResult` into a representation for some other system. It
performs no I/O and nothing it produces is ever read back by the engine: the code that
talks to the outside world lives in `apps/api`.
"""

from services.graph.sinks.neo4j_projection import (
    PROJECTION_LABELS,
    projection_statements,
    schema_statements,
)

__all__ = ["PROJECTION_LABELS", "projection_statements", "schema_statements"]
