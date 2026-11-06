"""Tests for scripts/verify_attack_graph_evidence.py (evidence id -> API lookup mapping)."""

from __future__ import annotations

from typing import Any

import pytest

from scripts import verify_attack_graph_evidence as v

API = "http://api.test"
ENG = "eng-1"


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []
    responses: dict[str, tuple[int, Any]] = {
        f"{API}/observations/obs%3Asha256%3Aabc?engagement_id={ENG}": (
            200,
            {"observation_id": "obs:sha256:abc"},
        ),
        f"{API}/findings/fnd-1?engagement_id={ENG}": (200, {"finding": {"finding_id": "fnd-1"}}),
        f"{API}/engagements/{ENG}/topology": (200, {"topology_id": "topology:sha256:t1"}),
    }

    def fake_get(url: str, timeout: float) -> tuple[int, Any]:
        seen.append(url)
        return responses.get(url, (404, {"detail": "not found"}))

    monkeypatch.setattr(v, "_get", fake_get)
    return seen


def _resolve(evidence_id: str, known: set[str] | None = None) -> v.Resolution:
    return v.resolve(
        API,
        ENG,
        evidence_id,
        known_finding_ids=known or set(),
        topology_id="topology:sha256:t1",
        timeout=1.0,
    )


def test_observation_id_is_url_encoded_and_engagement_scoped(calls: list[str]) -> None:
    r = _resolve("obs:sha256:abc")
    assert r.ok and r.kind == "observation"
    assert calls == [f"{API}/observations/obs%3Asha256%3Aabc?engagement_id={ENG}"]


def test_finding_prefix_is_stripped(calls: list[str]) -> None:
    assert _resolve("finding:fnd-1").ok


def test_plain_finding_id_from_finding_ids_resolves(calls: list[str]) -> None:
    assert _resolve("fnd-1", known={"fnd-1"}).ok


def test_topology_must_match_the_declared_id(calls: list[str]) -> None:
    assert _resolve("topology:sha256:t1").ok
    assert not _resolve("topology:sha256:other").ok


def test_missing_and_unknown_ids_fail(calls: list[str]) -> None:
    assert not _resolve("obs:sha256:missing").ok
    unknown = _resolve("weird:1")
    assert not unknown.ok and unknown.kind == "unknown"
