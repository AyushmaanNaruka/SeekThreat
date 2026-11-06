"""Write an attack graph into the read-only Neo4j projection (DECISIONS.md D-003).

`services/graph` stays pure: it only builds the Cypher (`services.graph.sinks`). This
module owns the driver. Neo4j is written only from here and never read back by the
engine; the projection is disposable and can be rebuilt from Postgres facts at any time.

Neo4j runs only under the `viz` compose profile. When it is not configured or not
reachable, `ProjectionUnavailable` carries a message telling the operator how to start
it; the API maps that to 503.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from neo4j import GraphDatabase
from neo4j.exceptions import (
    AuthError,
    ConfigurationError,
    DriverError,
    Neo4jError,
    ServiceUnavailable,
    SessionExpired,
)
from pydantic import BaseModel

from apps.api.core.config import Settings, settings
from packages.schema.models.graph import AttackGraphResult
from services.graph.sinks import projection_statements, schema_statements
from services.graph.sinks.neo4j_projection import Statement

START_VIZ_HINT = (
    "Start it with `docker compose -f infra/docker-compose.yml --profile viz up -d neo4j` "
    "and set NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD (see .env.example)."
)

DriverFactory = Callable[..., Any]


class ProjectionUnavailable(Exception):
    """Neo4j is not configured or cannot be reached. Maps to 503."""


class ProjectionFailed(Exception):
    """Neo4j was reached but rejected the projection. Maps to 502."""


class Neo4jConfig(BaseModel):
    uri: str
    user: str
    password: str
    connection_timeout_seconds: float = 5.0


class ProjectionSummary(BaseModel):
    """What was written. Counts come from the result, not from reading Neo4j back."""

    engagement_id: str
    topology_id: str
    rules_digest: str
    nodes: int
    relationships: int
    paths: int
    truncated: bool
    statements: int
    neo4j_uri: str


def redact_uri(uri: str) -> str:
    """Drop any user:password@ from a URI before it is logged or returned."""
    parts = urlsplit(uri)
    if "@" not in parts.netloc:
        return uri
    host = parts.netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _run_all(tx: Any, statements: list[Statement]) -> None:
    for query, parameters in statements:
        tx.run(query, parameters).consume()


class Neo4jProjector:
    """Replaces one engagement's projection with a freshly computed attack graph."""

    def __init__(
        self,
        config: Neo4jConfig | None,
        driver_factory: DriverFactory = GraphDatabase.driver,
    ) -> None:
        self.config = config
        self._driver_factory = driver_factory

    @classmethod
    def from_settings(cls, source: Settings = settings) -> Neo4jProjector:
        if not source.neo4j_uri or not source.neo4j_password:
            return cls(None)
        return cls(
            Neo4jConfig(
                uri=source.neo4j_uri,
                user=source.neo4j_user,
                password=source.neo4j_password,
                connection_timeout_seconds=source.neo4j_connection_timeout_seconds,
            )
        )

    @property
    def target(self) -> str:
        return redact_uri(self.config.uri) if self.config else "neo4j:unconfigured"

    def require_configured(self) -> Neo4jConfig:
        if self.config is None:
            raise ProjectionUnavailable(
                "Neo4j projection is not configured: NEO4J_URI and NEO4J_PASSWORD must be "
                "set. Neo4j is optional and runs only under the `viz` compose profile. "
                + START_VIZ_HINT
            )
        return self.config

    def project(self, result: AttackGraphResult) -> ProjectionSummary:
        """Delete the engagement's previous projection and write `result`, atomically."""
        config = self.require_configured()
        statements = projection_statements(result)
        target = redact_uri(config.uri)
        try:
            driver = self._driver_factory(
                config.uri,
                auth=(config.user, config.password),
                connection_timeout=config.connection_timeout_seconds,
            )
            with driver:
                driver.verify_connectivity()
                with driver.session() as session:
                    for query, parameters in schema_statements():
                        session.run(query, parameters).consume()
                    session.execute_write(_run_all, statements)
        except AuthError as exc:
            raise ProjectionUnavailable(
                f"Neo4j at {target} rejected the credentials ({exc.__class__.__name__}). "
                "Check NEO4J_USER and NEO4J_PASSWORD against the compose NEO4J_AUTH."
            ) from exc
        except (ServiceUnavailable, SessionExpired, ConfigurationError, ValueError) as exc:
            raise ProjectionUnavailable(
                f"Neo4j is not reachable at {target} ({exc.__class__.__name__}). " + START_VIZ_HINT
            ) from exc
        except (DriverError, Neo4jError) as exc:
            raise ProjectionFailed(
                f"Neo4j at {target} rejected the projection: {exc.__class__.__name__}: {exc}"
            ) from exc
        return ProjectionSummary(
            engagement_id=result.engagement_id,
            topology_id=result.topology_id,
            rules_digest=result.rules_digest,
            nodes=len(result.nodes),
            relationships=len(result.edges),
            paths=len(result.paths),
            truncated=result.truncated,
            statements=len(statements),
            neo4j_uri=target,
        )


def get_projector() -> Neo4jProjector:
    """FastAPI dependency; tests override it with a projector over a fake driver."""
    return Neo4jProjector.from_settings()
