"""Load the lab observation fixtures into a running API, so the dashboard can be shown
without Docker, the lab, or a scanner (the recorded-fallback "fixture mode" in
docs/04-demo-runbook.md).

What it does, in order:

1. Creates engagement ``eng-lab-baseline`` through ``POST /engagements`` (allowlist
   ``172.20.0.0/16``, the whole lab), or reuses it if it already exists. The fixtures
   were recorded under that id, and their content-addressed observation ids embed it,
   so no other engagement id can hold them.
2. Writes every ``tests/fixtures/observations/*.json`` snapshot to the API's database
   with ``save_scan_result``, the same call the scan worker makes. There is no HTTP
   endpoint that accepts observations, on purpose: in normal operation only a scan
   creates them. This step therefore needs ``--database-url`` (default: the
   ``DATABASE_URL`` the API itself reads). Nothing is scanned.
3. Builds findings from the ``vuln_candidate`` observations with the interim bridge
   (D-044) and enriches them through ``POST /findings/enrich/batch``. With no feed
   mirrors on disk, enrichment falls back to its labelled placeholder fields.
4. Declares ``lab/topology.yaml`` through ``PUT /engagements/{id}/topology``.
5. Reads ``GET /engagements/{id}/attack-graph`` and prints what it holds.
6. With ``--index-assistant``, builds the assistant index. That needs a reachable
   Ollama with the configured models; a 503 is reported, not treated as failure.

Re-running it is safe: every write is an upsert or a replace.

The facts are fixtures: 8 of the 10 lab hosts are synthetic (see
tests/fixtures/observations/README.md). Say so when you demo from them.

Usage (from the repo root):
    python -m scripts.seed_fixture_demo
    python -m scripts.seed_fixture_demo --api http://127.0.0.1:8000 \\
        --database-url sqlite:///data/demo.db --index-assistant

Exit code 0 on success, 1 when a step fails.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from packages.schema.models.observation import ScanResult

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "observations"
LAB_TOPOLOGY = REPO_ROOT / "lab" / "topology.yaml"

# The engagement the observation fixtures were recorded under.
ENGAGEMENT_ID = "eng-lab-baseline"
LAB_ALLOWLIST = ("172.20.0.0/16",)
DEFAULT_AUTHORIZER = "lab-operator"
AUTHORIZATION_DAYS = 7


class SeedError(RuntimeError):
    """A seeding step failed; the message names the step and the API's answer."""


@dataclass
class SeedSummary:
    engagement_id: str
    engagement_created: bool
    observations: int
    findings: int
    topology_id: str
    graph: dict[str, Any]
    assistant_indexed: int | None = None
    notes: list[str] = field(default_factory=list)


def fixture_scan_results(fixtures_dir: Path = FIXTURES_DIR) -> list[ScanResult]:
    """Every observation fixture snapshot, in file-name order."""
    paths = sorted(fixtures_dir.glob("*.json"))
    if not paths:
        raise SeedError(f"no observation fixtures found in {fixtures_dir}")
    return [ScanResult.model_validate_json(p.read_text(encoding="utf-8")) for p in paths]


def engagement_payload(
    authorized_by: str, *, now: datetime, days: int = AUTHORIZATION_DAYS
) -> dict[str, Any]:
    return {
        "engagement_id": ENGAGEMENT_ID,
        "name": "Lab baseline (fixture mode)",
        "authorized_by": authorized_by,
        "allowlist": list(LAB_ALLOWLIST),
        "granted_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
    }


def topology_payload(path: Path = LAB_TOPOLOGY) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SeedError(f"{path} is not a topology mapping")
    document["engagement_id"] = ENGAGEMENT_ID
    return document


def _check(response: httpx.Response, step: str, *ok: int) -> Any:
    if response.status_code not in ok:
        raise SeedError(f"{step}: HTTP {response.status_code}: {response.text[:500]}")
    return response.json()


def seed(
    client: httpx.Client,
    persist: Callable[[list[ScanResult]], None],
    *,
    authorized_by: str = DEFAULT_AUTHORIZER,
    detected_at: datetime | None = None,
    index_assistant: bool = False,
) -> SeedSummary:
    """Run the seeding steps against `client` (an httpx.Client, or a FastAPI TestClient,
    with the API as base URL). `persist` writes the fixture scan results to the API's
    database."""
    # Imported here so `--help` works without the API's dependencies configured.
    from services.normalize import findings_from_observations

    eid = quote(ENGAGEMENT_ID, safe="")
    now = datetime.now(UTC)
    notes: list[str] = []

    existing = client.get(f"/engagements/{eid}")
    created = existing.status_code == 404
    if created:
        _check(
            client.post("/engagements", json=engagement_payload(authorized_by, now=now)),
            "create engagement",
            201,
        )
    else:
        engagement = _check(existing, "read engagement", 200)
        notes.append(
            f"engagement {ENGAGEMENT_ID} already existed (authorized by "
            f"{engagement['authorized_by']}, allowlist {engagement['allowlist']}); reused"
        )

    results = fixture_scan_results()
    persist(results)
    observations = [o for r in results for o in r.observations]

    findings = findings_from_observations(observations, detected_at=detected_at or now)
    if findings:
        _check(
            client.post(
                "/findings/enrich/batch",
                json={
                    "engagement_id": ENGAGEMENT_ID,
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
            ),
            "enrich findings",
            200,
        )

    topology = _check(
        client.put(f"/engagements/{eid}/topology", json=topology_payload()),
        "declare topology",
        200,
    )
    graph = _check(client.get(f"/engagements/{eid}/attack-graph"), "read attack graph", 200)
    summary = SeedSummary(
        engagement_id=ENGAGEMENT_ID,
        engagement_created=created,
        observations=len(observations),
        findings=len(findings),
        topology_id=topology["topology_id"],
        graph={
            "nodes": len(graph["nodes"]),
            "edges": len(graph["edges"]),
            "paths": len(graph["paths"]),
            "chokepoints": len(graph["chokepoints"]),
            "truncated": graph["truncated"],
        },
        notes=notes,
    )

    if index_assistant:
        response = client.post(f"/engagements/{eid}/assistant/index")
        if response.status_code == 200:
            summary.assistant_indexed = int(response.json()["indexed"])
        elif response.status_code == 503:
            notes.append(
                "assistant index not built: the model server is unavailable (HTTP 503). "
                "Start Ollama and pull the models, then press 'Index engagement' in the "
                "Assistant view."
            )
        else:
            _check(response, "index assistant", 200)
    return summary


def database_writer(database_url: str | None) -> Callable[[list[ScanResult]], None]:
    """A `persist` callable that writes scan results to `database_url` (default: the
    API's own DATABASE_URL)."""
    from apps.api.db.repositories import save_scan_result
    from apps.api.db.session import get_engine, get_session_factory

    factory = get_session_factory(get_engine(database_url))

    def persist(results: list[ScanResult]) -> None:
        with factory() as session:
            for result in results:
                save_scan_result(session, result)
            session.commit()

    return persist


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="API base URL")
    parser.add_argument(
        "--database-url",
        help="The API's database (default: DATABASE_URL, as the API reads it)",
    )
    parser.add_argument("--authorized-by", default=DEFAULT_AUTHORIZER)
    parser.add_argument("--index-assistant", action="store_true")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    try:
        persist = database_writer(args.database_url)
        with httpx.Client(base_url=args.api.rstrip("/"), timeout=args.timeout) as client:
            summary = seed(
                client,
                persist,
                authorized_by=args.authorized_by,
                index_assistant=args.index_assistant,
            )
    except (SeedError, httpx.HTTPError) as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1

    action = "created" if summary.engagement_created else "reused"
    print(f"engagement {summary.engagement_id} ({action})")
    print(f"observations written: {summary.observations} (fixtures; 8 of 10 hosts synthetic)")
    print(f"findings enriched: {summary.findings}")
    print(f"topology: {summary.topology_id}")
    g = summary.graph
    print(
        f"attack graph: {g['nodes']} nodes, {g['edges']} edges, {g['paths']} paths, "
        f"{g['chokepoints']} chokepoints, truncated={g['truncated']}"
    )
    if summary.assistant_indexed is not None:
        print(f"assistant documents indexed: {summary.assistant_indexed}")
    for note in summary.notes:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
