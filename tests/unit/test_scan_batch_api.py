# ruff: noqa: F811  (pytest fixtures imported from test_api)
"""POST /scans/plan and POST /scans/batch: every planned target is gated."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from apps.api.core.audit import get_audit_log
from tests.unit.test_api import (  # noqa: F401 - pytest fixtures
    _past,
    _valid_engagement_payload,
    api_client,
    db_session,
    engine,
    reset_audit_log,
)


def _engagement(client: TestClient, **overrides: Any) -> None:
    resp = client.post("/engagements", json=_valid_engagement_payload(**overrides))
    assert resp.status_code == 201, resp.text


def _body(targets: list[str], scanner: str = "nmap", **extra: Any) -> dict[str, Any]:
    return {"engagement_id": "eng-test-001", "scanner": scanner, "targets": targets, **extra}


def test_plan_splits_in_and_out_of_scope(api_client: TestClient) -> None:
    _engagement(api_client)
    resp = api_client.post(
        "/scans/plan", json=_body(["172.20.1.10, 172.20.1.0/24, 10.0.0.5, *.x.local"])
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert [p["target"] for p in data["planned"]] == ["172.20.1.10", "172.20.1.0/24"]
    reasons = {r["input"]: r["reason"] for r in data["rejected"]}
    assert "allowlist" in reasons["10.0.0.5"]
    assert "wildcard" in reasons["*.x.local"]
    # A dry run creates nothing.
    assert api_client.get("/scans").json() == []


def test_batch_dispatches_only_authorized_targets(api_client: TestClient) -> None:
    _engagement(api_client)
    resp = api_client.post(
        "/scans/batch",
        json=_body(["172.20.1.10\n172.20.2.0/24\n8.8.8.8\nhttp://172.20.1.11:3000"]),
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    accepted = [(s["target"], s["options"]) for s in data["accepted"]]
    assert accepted == [
        ("172.20.1.10", {}),
        ("172.20.2.0/24", {}),
        ("172.20.1.11", {"ports": "3000"}),
    ]
    assert [r["target"] for r in data["rejected"]] == ["8.8.8.8"]
    assert len(api_client.get("/scans").json()) == 3

    events = [(e["event"], e["target"]) for e in get_audit_log()]
    assert ("scan.rejected", "8.8.8.8") in events
    assert ("scan.accepted", "172.20.2.0/24") in events


def test_batch_with_nothing_authorized_is_422_with_reasons(api_client: TestClient) -> None:
    _engagement(api_client)
    resp = api_client.post("/scans/batch", json=_body(["8.8.8.8, google.com"]))
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert {r["input"] for r in detail["rejected"]} == {"8.8.8.8", "google.com"}
    assert api_client.get("/scans").json() == []


def test_batch_range_partly_outside_scope_is_refused(api_client: TestClient) -> None:
    _engagement(api_client, allowlist=["172.20.1.0/24"])
    resp = api_client.post("/scans/batch", json=_body(["172.20.0.0/23"]))
    assert resp.status_code == 422


def test_batch_expired_engagement_is_403(api_client: TestClient) -> None:
    _engagement(api_client, expires_at=_past(1).isoformat(), granted_at=_past(3).isoformat())
    resp = api_client.post("/scans/batch", json=_body(["172.20.1.10"]))
    assert resp.status_code == 403
    assert api_client.get("/scans").json() == []


def test_batch_unknown_engagement_is_404(api_client: TestClient) -> None:
    resp = api_client.post("/scans/batch", json=_body(["172.20.1.10"]))
    assert resp.status_code == 404


def test_batch_too_large_is_422(api_client: TestClient) -> None:
    _engagement(api_client, allowlist=["10.0.0.0/8"])
    resp = api_client.post("/scans/batch", json=_body(["10.0.0.0/8"]))
    assert resp.status_code == 422
    assert api_client.get("/scans").json() == []


def test_batch_per_scanner_options(api_client: TestClient) -> None:
    _engagement(api_client)
    resp = api_client.post(
        "/scans/batch",
        json=_body(
            ["https://172.20.1.10, 172.20.1.11:8080"], scanner="nikto", options={"timeout": 60}
        ),
    )
    assert resp.status_code == 202, resp.text
    assert [s["options"] for s in resp.json()["accepted"]] == [
        {"timeout": 60, "scheme": "https", "port": "443"},
        {"timeout": 60, "scheme": "http", "port": "8080"},
    ]
