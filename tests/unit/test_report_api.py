"""API tests for GET /engagements/{id}/report (D-051).

Same pattern as test_attack_graph_api.py: in-memory SQLite, the lab observation fixtures,
findings from the interim bridge and lab/topology.yaml.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.core.audit import clear_audit_log, get_audit_log
from apps.api.db import models as _models  # noqa: F401 – side-effect: registers all tables
from apps.api.db.base import Base
from apps.api.db.repositories import (
    EngagementRepository,
    EnrichedFindingRepository,
    ObservationRepository,
    RawArtifactRepository,
    ScanRepository,
    TopologyRepository,
)
from apps.api.db.session import get_db
from apps.api.main import app
from packages.schema.models.engagement import Authorization, Engagement
from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.topology import NetworkTopology
from services.normalize import findings_from_observations

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "observations"
LAB_TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"

ENGAGEMENT_ID = "eng-lab-baseline"
AUTHORIZER = "lab-operator"
DETECTED_AT = datetime(2026, 11, 6, 12, 0, 0, tzinfo=UTC)


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


def _seed(db_session: Session, *, topology: bool = True) -> list[Observation]:
    now = datetime.now(UTC)
    EngagementRepository(db_session).save(
        Engagement(
            engagement_id=ENGAGEMENT_ID,
            name="Lab engagement",
            authorization=Authorization(
                engagement_id=ENGAGEMENT_ID,
                authorized_by=AUTHORIZER,
                allowlist=("172.20.0.0/16",),
                granted_at=now - timedelta(hours=1),
                expires_at=now + timedelta(hours=23),
            ),
            created_at=now,
        )
    )
    db_session.commit()
    observations: list[Observation] = []
    for i, path in enumerate(sorted(FIXTURES.glob("*.json"))):
        result = ScanResult.model_validate_json(path.read_text(encoding="utf-8"))
        RawArtifactRepository(db_session).save(result.artifact)
        ObservationRepository(db_session).save_all(result.observations)
        observations.extend(result.observations)
        ScanRepository(db_session).create(
            scan_id=f"scan-{i}", engagement_id=ENGAGEMENT_ID, scanner="nmap", target="172.20.1.0/24"
        )
        ScanRepository(db_session).update_status(
            f"scan-{i}", "completed", artifact_id=result.artifact.artifact_id
        )
    findings = findings_from_observations(observations, detected_at=DETECTED_AT)
    EnrichedFindingRepository(db_session).upsert_all(
        [EnrichedFinding(finding=f) for f in findings], enriched_at=DETECTED_AT
    )
    if topology:
        document: dict[str, Any] = yaml.safe_load(LAB_TOPOLOGY.read_text(encoding="utf-8"))
        document["engagement_id"] = ENGAGEMENT_ID
        TopologyRepository(db_session).upsert(NetworkTopology.model_validate(document))
    db_session.commit()
    return observations


def _events(name: str) -> list[dict[str, Any]]:
    return [e for e in get_audit_log() if e["event"] == name]


def test_markdown_download(api_client: TestClient, db_session: Session) -> None:
    _seed(db_session)
    resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=md")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/markdown")
    assert (
        resp.headers["content-disposition"]
        == 'attachment; filename="seekthreat-report-eng-lab-baseline.md"'
    )
    body = resp.text
    assert body.startswith("# Engagement report: Lab engagement")
    assert "## 5. Attack paths" in body and "### Rank 1:" in body
    assert "## 7. Remediation simulation (top chokepoint)" in body
    assert "**Exposure Risk Score: not scored.**" in body

    (generated,) = _events("report.generated")
    assert generated["actor"] == AUTHORIZER
    assert generated["engagement_id"] == ENGAGEMENT_ID
    assert generated["target"] == f"engagement:{ENGAGEMENT_ID}/report"
    assert generated["details"]["format"] == "md"
    assert generated["details"]["sha256"] == hashlib.sha256(resp.content).hexdigest()
    assert generated["details"]["simulated_finding_ids"]


def test_json_download_is_deterministic_apart_from_generated_at(
    api_client: TestClient, db_session: Session
) -> None:
    _seed(db_session)
    first = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=json")
    second = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=json")
    assert first.status_code == second.status_code == 200
    assert first.headers["content-type"] == "application/json"
    a, b = first.json(), second.json()
    a.pop("generated_at")
    b.pop("generated_at")
    assert a == b
    assert a["report_format"] == "seekthreat.report/1"
    assert a["engagement"]["authorization"]["authorization_reference"] == ENGAGEMENT_ID
    assert len(a["scans"]) == len(list(FIXTURES.glob("*.json")))
    assert all(s["observation_count"] > 0 for s in a["scans"])
    assert a["attack_graph"]["paths"][0]["rank"] == 1
    assert a["simulation"]["fixed_finding_ids"] == [
        a["attack_graph"]["chokepoints"][0]["finding_id"]
    ]


def test_report_matches_attack_graph_endpoint(api_client: TestClient, db_session: Session) -> None:
    _seed(db_session)
    graph = api_client.get(f"/engagements/{ENGAGEMENT_ID}/attack-graph").json()
    report = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=json").json()
    assert [p["path_id"] for p in report["attack_graph"]["paths"]] == [
        p["path_id"] for p in sorted(graph["paths"], key=lambda p: p["rank"])
    ]
    assert report["attack_graph"]["rules_digest"] == graph["rules_digest"]


def test_without_topology_report_still_exports(api_client: TestClient, db_session: Session) -> None:
    _seed(db_session, topology=False)
    resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=json")
    assert resp.status_code == 200, resp.text
    data = json.loads(resp.content)
    assert data["attack_graph"] is None
    assert "no network topology is declared" in data["attack_graph_unavailable"]
    assert data["simulation"] is None
    assert data["findings"]
    assert _events("report.generated")[0]["details"]["topology_id"] is None


def test_unknown_engagement_is_audited_404(api_client: TestClient) -> None:
    resp = api_client.get("/engagements/eng-missing/report")
    assert resp.status_code == 404
    (rejected,) = _events("report.rejected")
    assert rejected["status"] == "not_found"
    assert rejected["engagement_id"] == "eng-missing"


def test_unknown_format_is_rejected(api_client: TestClient, db_session: Session) -> None:
    _seed(db_session)
    resp = api_client.get(f"/engagements/{ENGAGEMENT_ID}/report?format=pdf")
    assert resp.status_code == 422
    assert not _events("report.generated")
