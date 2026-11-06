"""Unit tests for the Layer 3 API: declared topology, attack graph, remediation
simulation, single-evidence lookups, the topology loader CLI, and the Neo4j projection
(endpoint and CLI, over a fake driver: no Neo4j is needed or contacted).

The attack-graph tests run the real engine over the lab observation fixtures
(tests/fixtures/observations/*.json), with findings built by the interim bridge exactly
as a completed scan builds them, and the topology from lab/topology.yaml.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from neo4j.exceptions import AuthError, ClientError, ServiceUnavailable
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.cli.load_topology import TopologyLoadError, load_topology
from apps.api.cli.project_graph import ProjectGraphError, project_graph
from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.core.config import Settings
from apps.api.db import models as _models  # noqa: F401 – side-effect: registers all tables
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    RawArtifactRepository,
    TopologyRepository,
)
from apps.api.db.session import get_db
from apps.api.graph_projection import Neo4jConfig, Neo4jProjector, get_projector
from apps.api.main import app
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import AttackGraphResult
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.topology import NetworkTopology
from services.graph.sinks import projection_statements, schema_statements
from services.normalize import findings_from_observations

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "observations"
LAB_TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"

# The engagement the lab observation fixtures were recorded under.
ENGAGEMENT_ID = "eng-lab-baseline"
OTHER_ENGAGEMENT_ID = "eng-other"
AUTHORIZER = "lab-operator"
DETECTED_AT = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)
SPRING_GATEWAY_CVE = "CVE-2022-22947"


# ---------------------------------------------------------------------------
# Fixtures (duplicated per test module, as in test_findings_api.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )

    @event.listens_for(eng, "connect")
    def set_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture
def db_session(engine):
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture
def api_client(db_session: Session):
    def _override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_audit_log():
    clear_audit_log()
    yield
    clear_audit_log()


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _seed_engagement(db_session: Session, engagement_id: str = ENGAGEMENT_ID) -> None:
    now = datetime.now(UTC)
    EngagementRepository(db_session).save(
        Engagement(
            engagement_id=engagement_id,
            name="Lab engagement",
            authorization=Authorization(
                engagement_id=engagement_id,
                authorized_by=AUTHORIZER,
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db_session.commit()


def _seed_lab_facts(db_session: Session) -> tuple[list[Observation], list[Finding]]:
    """Persist every lab fixture scan and the findings the interim bridge derives."""
    observations: list[Observation] = []
    for path in sorted(FIXTURES.glob("*.json")):
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        RawArtifactRepository(db_session).save(result.artifact)
        ObservationRepository(db_session).save_all(result.observations)
        observations.extend(result.observations)
    findings = findings_from_observations(observations, detected_at=DETECTED_AT)
    EnrichedFindingRepository(db_session).upsert_all(
        [EnrichedFinding(finding=f) for f in findings], enriched_at=DETECTED_AT
    )
    db_session.commit()
    return observations, findings


def _lab_topology_payload(engagement_id: str = ENGAGEMENT_ID) -> dict[str, Any]:
    document = yaml.safe_load(LAB_TOPOLOGY.read_text(encoding="utf-8"))
    document["engagement_id"] = engagement_id
    return dict(document)


def _seed_lab(db_session: Session, api_client: TestClient) -> list[Finding]:
    _seed_engagement(db_session)
    _, findings = _seed_lab_facts(db_session)
    resp = api_client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=_lab_topology_payload())
    assert resp.status_code == 200, resp.text
    return findings


def _events(name: str) -> list[dict[str, Any]]:
    return [e for e in get_audit_log() if e["event"] == name]


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


class TestTopology:
    def test_put_then_get_roundtrip(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        payload = _lab_topology_payload()
        expected = NetworkTopology.model_validate(payload)

        put = api_client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=payload)
        assert put.status_code == 200, put.text
        assert put.json()["topology_id"] == expected.topology_id
        assert put.json()["topology_id"].startswith("topology:sha256:")

        got = api_client.get(f"/engagements/{ENGAGEMENT_ID}/topology")
        assert got.status_code == 200
        assert got.json() == put.json()
        assert NetworkTopology.model_validate(got.json()) == expected

        declared = _events("topology.declared")
        assert len(declared) == 1
        assert declared[0]["actor"] == expected.declared_by
        assert declared[0]["engagement_id"] == ENGAGEMENT_ID
        assert declared[0]["details"]["topology_id"] == expected.topology_id
        assert _events("topology.read")[0]["actor"] == AUTHORIZER

    def test_put_replaces_previous_declaration(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        first = api_client.put(
            f"/engagements/{ENGAGEMENT_ID}/topology", json=_lab_topology_payload()
        ).json()
        changed = _lab_topology_payload()
        changed["intra_zone_reachable"] = False
        second = api_client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=changed)
        assert second.status_code == 200
        assert second.json()["topology_id"] != first["topology_id"]
        got = api_client.get(f"/engagements/{ENGAGEMENT_ID}/topology").json()
        assert got["topology_id"] == second.json()["topology_id"]
        latest = _events("topology.declared")[-1]
        assert latest["details"]["previous_topology_id"] == first["topology_id"]

    def test_client_supplied_topology_id_is_ignored(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        payload = _lab_topology_payload()
        payload["topology_id"] = "topology:sha256:forged"
        resp = api_client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=payload)
        assert resp.status_code == 200
        assert resp.json()["topology_id"] != "topology:sha256:forged"

    def test_engagement_mismatch_is_422(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        resp = api_client.put(
            f"/engagements/{ENGAGEMENT_ID}/topology",
            json=_lab_topology_payload(engagement_id=OTHER_ENGAGEMENT_ID),
        )
        assert resp.status_code == 422
        assert OTHER_ENGAGEMENT_ID in resp.json()["detail"]
        assert TopologyRepository(db_session).get(ENGAGEMENT_ID) is None
        assert _events("topology.declare_rejected")[0]["status"] == "rejected"

    def test_invalid_topology_is_422(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        payload = _lab_topology_payload()
        for zone in payload["zones"]:
            zone["attacker_entry"] = False
        resp = api_client.put(f"/engagements/{ENGAGEMENT_ID}/topology", json=payload)
        assert resp.status_code == 422

    def test_put_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        resp = api_client.put("/engagements/eng-missing/topology", json=_lab_topology_payload())
        assert resp.status_code == 404
        assert _events("topology.declare_rejected")[0]["status"] == "not_found"

    def test_get_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        assert api_client.get("/engagements/eng-missing/topology").status_code == 404

    def test_get_without_declaration_is_404(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/topology")
        assert resp.status_code == 404
        assert "No network topology is declared" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Attack graph
# ---------------------------------------------------------------------------


class TestAttackGraph:
    def test_returns_paths_for_lab_fixtures(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["engagement_id"] == ENGAGEMENT_ID
        assert body["paths"], "the lab fixtures should yield at least one attack path"
        assert body["chokepoints"]
        topology_id = api_client.get(f"/engagements/{ENGAGEMENT_ID}/topology").json()["topology_id"]
        assert body["topology_id"] == topology_id
        edge = body["paths"][0]["edges"][0]
        assert {"edge_id", "rule_name", "evidence", "confidence", "finding_ids"} <= edge.keys()

        audit = _events("attack_graph.read")
        assert len(audit) == 1
        assert audit[0]["actor"] == AUTHORIZER
        assert audit[0]["details"]["paths"] == len(body["paths"])

    def test_two_reads_are_byte_identical(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        first = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
        second = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
        assert first.status_code == second.status_code == 200
        assert first.content == second.content

    def test_limits_are_applied(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.get(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph", params={"max_depth": 3, "max_paths": 2}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["max_depth"] == 3
        assert body["max_paths"] == 2
        assert len(body["paths"]) <= 2
        assert all(len(p["edges"]) <= 3 for p in body["paths"])

    @pytest.mark.parametrize(
        "params",
        [{"max_depth": 0}, {"max_depth": 21}, {"max_paths": 0}, {"max_paths": 5001}],
    )
    def test_out_of_range_limits_are_422(
        self, api_client: TestClient, db_session: Session, params: dict[str, int]
    ) -> None:
        _seed_engagement(db_session)
        resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph", params=params)
        assert resp.status_code == 422

    def test_missing_topology_is_409_with_instructions(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        _seed_lab_facts(db_session)
        resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph")
        assert resp.status_code == 409
        detail = resp.json()["detail"]
        assert "No network topology is declared" in detail
        assert f"PUT /engagements/{ENGAGEMENT_ID}/topology" in detail
        assert _events("attack_graph.read_rejected")[0]["status"] == "no_topology"

    def test_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        assert api_client.get("/engagements/eng-missing/attack-graph").status_code == 404

    def test_other_engagements_facts_are_not_used(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        _seed_engagement(db_session, OTHER_ENGAGEMENT_ID)
        api_client.put(
            f"/engagements/{OTHER_ENGAGEMENT_ID}/topology",
            json=_lab_topology_payload(OTHER_ENGAGEMENT_ID),
        )
        resp = api_client.get(f"/engagements/{OTHER_ENGAGEMENT_ID}/attack-graph")
        assert resp.status_code == 200
        assert resp.json()["paths"] == []


# ---------------------------------------------------------------------------
# Remediation simulation
# ---------------------------------------------------------------------------


class TestSimulate:
    def test_fixing_spring_gateway_removes_paths(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        findings = _seed_lab(db_session, api_client)
        spring = [f.finding_id for f in findings if SPRING_GATEWAY_CVE in f.cve_ids]
        assert len(spring) == 1

        baseline = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").json()
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate",
            json={"fixed_finding_ids": spring},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["fixed_finding_ids"] == spring
        assert body["baseline_path_count"] == len(baseline["paths"])
        assert body["remaining_path_count"] < body["baseline_path_count"]
        assert body["removed_path_ids"]
        baseline_ids = {p["path_id"] for p in baseline["paths"]}
        assert set(body["removed_path_ids"]) <= baseline_ids
        after_edges = body["after"]["edges"]
        assert all(spring[0] not in e["finding_ids"] for e in after_edges)
        assert len(body["after"]["paths"]) == body["remaining_path_count"]

        audit = _events("attack_graph.simulated")
        assert len(audit) == 1
        assert audit[0]["details"]["fixed_finding_ids"] == spring

    def test_unknown_finding_ids_are_422(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate",
            json={"fixed_finding_ids": ["fnd-does-not-exist"]},
        )
        assert resp.status_code == 422
        assert "fnd-does-not-exist" in resp.json()["detail"]
        assert _events("attack_graph.simulate_rejected")[0]["status"] == "rejected"

    def test_empty_fix_list_is_422(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate", json={"fixed_finding_ids": []}
        )
        assert resp.status_code == 422

    def test_missing_topology_is_409(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        resp = api_client.post(
            f"/engagements/{ENGAGEMENT_ID}/attack-graph/simulate",
            json={"fixed_finding_ids": ["fnd-x"]},
        )
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Evidence lookups
# ---------------------------------------------------------------------------


class TestEvidenceLookups:
    def test_every_edge_evidence_id_resolves(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        graph = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").json()
        evidence = sorted({ev for e in graph["edges"] for ev in e["evidence"]})
        topology_id = graph["topology_id"]
        assert any(ev.startswith("obs:") for ev in evidence)
        assert any(ev.startswith("finding:") for ev in evidence)
        for ev in evidence:
            if ev.startswith("obs:"):
                resp = api_client.get(
                    f"/observations/{ev}", params={"engagement_id": ENGAGEMENT_ID}
                )
                assert resp.status_code == 200, ev
                assert resp.json()["observation_id"] == ev
            elif ev.startswith("finding:"):
                finding_id = ev.removeprefix("finding:")
                resp = api_client.get(
                    f"/findings/{finding_id}", params={"engagement_id": ENGAGEMENT_ID}
                )
                assert resp.status_code == 200, ev
                assert resp.json()["finding"]["finding_id"] == finding_id
            else:
                assert ev == topology_id

    def test_observation_from_other_engagement_is_404(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_engagement(db_session)
        _seed_engagement(db_session, OTHER_ENGAGEMENT_ID)
        observations, _ = _seed_lab_facts(db_session)
        obs_id = observations[0].observation_id
        assert (
            api_client.get(
                f"/observations/{obs_id}", params={"engagement_id": ENGAGEMENT_ID}
            ).status_code
            == 200
        )
        resp = api_client.get(
            f"/observations/{obs_id}", params={"engagement_id": OTHER_ENGAGEMENT_ID}
        )
        assert resp.status_code == 404

    def test_unknown_observation_is_404(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        resp = api_client.get(
            "/observations/obs:sha256:missing", params={"engagement_id": ENGAGEMENT_ID}
        )
        assert resp.status_code == 404
        assert _events("observations.queried")[0]["details"] == {"found": False}

    def test_observation_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        resp = api_client.get("/observations/obs:x", params={"engagement_id": "eng-missing"})
        assert resp.status_code == 404

    def test_observation_requires_engagement(self, api_client: TestClient) -> None:
        assert api_client.get("/observations/obs:x").status_code == 422


# ---------------------------------------------------------------------------
# CLI loader
# ---------------------------------------------------------------------------


class TestLoadTopologyCli:
    def test_loads_lab_topology_overriding_engagement(self, db_session: Session) -> None:
        _seed_engagement(db_session, "eng-lab-demo")
        stored = load_topology(db_session, LAB_TOPOLOGY, "eng-lab-demo")
        assert stored.engagement_id == "eng-lab-demo"
        assert TopologyRepository(db_session).get("eng-lab-demo") == stored
        assert _events("topology.declared")[0]["details"]["via"] == "cli"

    def test_unknown_engagement_is_rejected(self, db_session: Session) -> None:
        with pytest.raises(TopologyLoadError, match="not found"):
            load_topology(db_session, LAB_TOPOLOGY, "eng-missing")

    def test_invalid_file_is_rejected(self, db_session: Session, tmp_path: Path) -> None:
        _seed_engagement(db_session)
        bad = tmp_path / "bad.yaml"
        bad.write_text("zones: []\ndeclared_by: x\ndeclared_at: 2026-01-01T00:00:00Z\n")
        with pytest.raises(TopologyLoadError, match="not a valid topology"):
            load_topology(db_session, bad, ENGAGEMENT_ID)


# ---------------------------------------------------------------------------
# Neo4j projection (fake driver)
# ---------------------------------------------------------------------------

NEO4J_PASSWORD = "test-only-not-a-secret"


class _FakeResult:
    def consume(self) -> None:
        return None


class _FakeTx:
    def __init__(self, driver: _FakeDriver) -> None:
        self.driver = driver

    def run(self, query: str, parameters: dict[str, Any]) -> _FakeResult:
        if self.driver.fail_on_write is not None:
            raise self.driver.fail_on_write
        self.driver.writes.append((query, parameters))
        return _FakeResult()


class _FakeSession:
    def __init__(self, driver: _FakeDriver) -> None:
        self.driver = driver

    def __enter__(self) -> _FakeSession:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def run(self, query: str, parameters: dict[str, Any]) -> _FakeResult:
        self.driver.schema.append((query, parameters))
        return _FakeResult()

    def execute_write(self, fn: Any, *args: Any) -> Any:
        self.driver.transactions += 1
        return fn(_FakeTx(self.driver), *args)


class _FakeDriver:
    def __init__(
        self,
        fail_on_connect: Exception | None = None,
        fail_on_write: Exception | None = None,
    ) -> None:
        self.fail_on_connect = fail_on_connect
        self.fail_on_write = fail_on_write
        self.opened: list[tuple[str, dict[str, Any]]] = []
        self.schema: list[tuple[str, dict[str, Any]]] = []
        self.writes: list[tuple[str, dict[str, Any]]] = []
        self.transactions = 0
        self.closed = False

    def factory(self, uri: str, **config: Any) -> _FakeDriver:
        self.opened.append((uri, config))
        return self

    def __enter__(self) -> _FakeDriver:
        return self

    def __exit__(self, *exc: object) -> None:
        self.closed = True

    def verify_connectivity(self) -> None:
        if self.fail_on_connect is not None:
            raise self.fail_on_connect

    def session(self) -> _FakeSession:
        return _FakeSession(self)


def _projector(driver: _FakeDriver) -> Neo4jProjector:
    config = Neo4jConfig(uri="bolt://neo4j.test:7687", user="neo4j", password=NEO4J_PASSWORD)
    return Neo4jProjector(config, driver_factory=driver.factory)


def _use_projector(projector: Neo4jProjector) -> None:
    app.dependency_overrides[get_projector] = lambda: projector


PROJECT_URL = f"/engagements/{ENGAGEMENT_ID}/attack-graph/project"


class TestProjection:
    def test_writes_the_same_graph_as_get(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver()
        _use_projector(_projector(driver))

        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 200, resp.text
        graph = AttackGraphResult.model_validate(
            api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").json()
        )
        body = resp.json()
        assert body["engagement_id"] == ENGAGEMENT_ID
        assert body["topology_id"] == graph.topology_id
        assert (body["nodes"], body["relationships"], body["paths"]) == (
            len(graph.nodes),
            len(graph.edges),
            len(graph.paths),
        )
        assert body["neo4j_uri"] == "bolt://neo4j.test:7687"

        assert driver.opened == [
            (
                "bolt://neo4j.test:7687",
                {"auth": ("neo4j", NEO4J_PASSWORD), "connection_timeout": 5.0},
            )
        ]
        assert driver.schema == schema_statements()
        assert driver.transactions == 1, "delete + rewrite must be one transaction"
        assert driver.writes == projection_statements(graph)
        assert driver.closed

        audit = _events("attack_graph.projected")
        assert len(audit) == 1
        assert audit[0]["actor"] == AUTHORIZER
        assert audit[0]["engagement_id"] == ENGAGEMENT_ID
        assert audit[0]["details"]["paths"] == len(graph.paths)
        assert NEO4J_PASSWORD not in resp.text
        assert NEO4J_PASSWORD not in repr(get_audit_log())

    def test_limits_are_passed_through(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver()
        _use_projector(_projector(driver))
        resp = api_client.post(PROJECT_URL, params={"max_depth": 3, "max_paths": 2})
        assert resp.status_code == 200
        assert resp.json()["paths"] <= 2

    def test_unconfigured_is_503_and_never_connects(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver()
        _use_projector(Neo4jProjector(None, driver_factory=driver.factory))
        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 503
        detail = resp.json()["detail"]
        assert "not configured" in detail and "--profile viz" in detail
        assert driver.opened == []
        assert _events("attack_graph.project_rejected")[0]["status"] == "neo4j_unconfigured"

    def test_projector_reads_settings(self) -> None:
        unset = Settings(neo4j_uri=None, neo4j_password=None)
        assert Neo4jProjector.from_settings(unset).config is None
        configured = Neo4jProjector.from_settings(
            Settings(neo4j_uri="bolt://localhost:7687", neo4j_password=NEO4J_PASSWORD)
        )
        assert configured.config is not None
        assert configured.config.user == "neo4j"

    def test_unreachable_is_503_with_viz_hint(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver(fail_on_connect=ServiceUnavailable("connection refused"))
        _use_projector(_projector(driver))
        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 503
        assert "not reachable" in resp.json()["detail"]
        assert "--profile viz" in resp.json()["detail"]
        assert driver.writes == []
        rejected = _events("attack_graph.project_rejected")[0]
        assert rejected["status"] == "neo4j_unavailable"
        assert rejected["actor"] == AUTHORIZER

    def test_bad_credentials_are_503(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        _use_projector(_projector(_FakeDriver(fail_on_connect=AuthError("unauthorized"))))
        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 503
        assert "NEO4J_PASSWORD" in resp.json()["detail"]
        assert NEO4J_PASSWORD not in resp.text

    def test_rejected_write_is_502(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        _use_projector(_projector(_FakeDriver(fail_on_write=ClientError("syntax"))))
        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 502
        assert _events("attack_graph.project_rejected")[0]["status"] == "neo4j_failed"

    def test_missing_topology_is_409(self, api_client: TestClient, db_session: Session) -> None:
        _seed_engagement(db_session)
        _seed_lab_facts(db_session)
        driver = _FakeDriver()
        _use_projector(_projector(driver))
        resp = api_client.post(PROJECT_URL)
        assert resp.status_code == 409
        assert "No network topology is declared" in resp.json()["detail"]
        assert driver.opened == []
        assert _events("attack_graph.project_rejected")[0]["status"] == "no_topology"

    def test_unknown_engagement_is_404(self, api_client: TestClient) -> None:
        driver = _FakeDriver()
        _use_projector(_projector(driver))
        assert api_client.post("/engagements/eng-missing/attack-graph/project").status_code == 404
        assert driver.opened == []


class TestProjectGraphCli:
    def test_projects_and_audits(self, api_client: TestClient, db_session: Session) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver()
        summary = project_graph(db_session, ENGAGEMENT_ID, _projector(driver))
        assert summary.paths > 0
        assert driver.writes[0][1] == {"engagement_id": ENGAGEMENT_ID}
        assert _events("attack_graph.projected")[0]["details"]["via"] == "cli"

    def test_unreachable_neo4j_is_an_error(
        self, api_client: TestClient, db_session: Session
    ) -> None:
        _seed_lab(db_session, api_client)
        driver = _FakeDriver(fail_on_connect=ServiceUnavailable("down"))
        with pytest.raises(ProjectGraphError, match="--profile viz"):
            project_graph(db_session, ENGAGEMENT_ID, _projector(driver))
        assert _events("attack_graph.project_rejected")[0]["status"] == "neo4j_unavailable"

    def test_missing_topology_is_an_error(self, db_session: Session) -> None:
        _seed_engagement(db_session)
        with pytest.raises(ProjectGraphError, match="no topology"):
            project_graph(db_session, ENGAGEMENT_ID, _projector(_FakeDriver()))
