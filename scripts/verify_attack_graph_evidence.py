"""Check that every evidence id on every attack-graph edge resolves through the live API.

Layer 3's promise is that every edge clicks through to its evidence. This script asks a
running API for an engagement's attack graph and then looks up each evidence id the
way the dashboard does:

- ``obs:...``      -> GET /observations/{id}?engagement_id=...
- ``finding:...``  -> GET /findings/{id}?engagement_id=...  (prefix stripped, as in
  apps/web/lib/attackGraph.ts, unless the finding's own id already starts with it)
- ``topology:...`` -> GET /engagements/{id}/topology, whose ``topology_id`` must match

It also checks that every id in ``PathEdge.finding_ids`` resolves. Read-only: it never
scans, writes, or changes anything.

Usage:
    python scripts/verify_attack_graph_evidence.py --engagement-id eng-l3-e2e
    python scripts/verify_attack_graph_evidence.py --engagement-id eng-l3-e2e \
        --api http://127.0.0.1:8000 --json-out results.json

Exit code 0 when every id resolves, 1 when any fails, 2 when the graph cannot be read.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote, urlencode


@dataclass(frozen=True)
class Resolution:
    evidence_id: str
    kind: str
    url: str
    status: int
    ok: bool
    detail: str = ""


def _get(url: str, timeout: float) -> tuple[int, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, body


def _finding_lookup_id(raw: str, known_finding_ids: set[str]) -> str:
    """Mirror apps/web/lib/attackGraph.ts: strip ``finding:`` unless the id itself has it."""
    if raw in known_finding_ids:
        return raw
    return raw.removeprefix("finding:")


def resolve(
    api: str,
    engagement_id: str,
    evidence_id: str,
    *,
    known_finding_ids: set[str],
    topology_id: str | None,
    timeout: float,
) -> Resolution:
    scope = urlencode({"engagement_id": engagement_id})
    if evidence_id.startswith("obs:"):
        url = f"{api}/observations/{quote(evidence_id, safe='')}?{scope}"
        status, body = _get(url, timeout)
        ok = status == 200 and isinstance(body, dict) and body.get("observation_id") == evidence_id
        return Resolution(evidence_id, "observation", url, status, ok, "" if ok else str(body))
    if evidence_id.startswith("finding:") or evidence_id in known_finding_ids:
        lookup = _finding_lookup_id(evidence_id, known_finding_ids)
        url = f"{api}/findings/{quote(lookup, safe='')}?{scope}"
        status, body = _get(url, timeout)
        finding = body.get("finding", {}) if isinstance(body, dict) else {}
        ok = status == 200 and finding.get("finding_id") == lookup
        return Resolution(evidence_id, "finding", url, status, ok, "" if ok else str(body))
    if evidence_id.startswith("topology:"):
        url = f"{api}/engagements/{quote(engagement_id, safe='')}/topology"
        status, body = _get(url, timeout)
        got = body.get("topology_id") if isinstance(body, dict) else None
        ok = status == 200 and got == evidence_id
        detail = "" if ok else f"topology_id {got!r} (graph cites {topology_id!r}): {body}"
        return Resolution(evidence_id, "topology", url, status, ok, detail)
    return Resolution(evidence_id, "unknown", "", 0, False, "unrecognised evidence prefix")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--max-depth", type=int)
    parser.add_argument("--max-paths", type=int)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json-out", help="Write every resolution to this JSON file")
    args = parser.parse_args(argv)

    api = args.api.rstrip("/")
    params = {
        k: v
        for k, v in (("max_depth", args.max_depth), ("max_paths", args.max_paths))
        if v is not None
    }
    graph_url = f"{api}/engagements/{quote(args.engagement_id, safe='')}/attack-graph"
    if params:
        graph_url += "?" + urlencode(params)
    status, graph = _get(graph_url, args.timeout)
    if status != 200 or not isinstance(graph, dict):
        print(f"cannot read attack graph ({status}): {graph}", file=sys.stderr)
        return 2

    edges: list[dict[str, Any]] = list(graph.get("edges", []))
    for path in graph.get("paths", []):
        edges.extend(path.get("edges", []))

    evidence_ids: set[str] = set()
    finding_refs: set[str] = set()
    for edge in edges:
        evidence_ids.update(edge.get("evidence", []))
        finding_refs.update(edge.get("finding_ids", []))
    known_finding_ids = set(finding_refs)

    resolutions: list[Resolution] = []
    cache: dict[str, Resolution] = {}
    for evidence_id in sorted(evidence_ids):
        cache[evidence_id] = resolve(
            api,
            args.engagement_id,
            evidence_id,
            known_finding_ids=known_finding_ids,
            topology_id=graph.get("topology_id"),
            timeout=args.timeout,
        )
        resolutions.append(cache[evidence_id])
    # PathEdge.finding_ids are plain ids (no prefix): check they resolve too.
    for finding_id in sorted(finding_refs - evidence_ids):
        resolutions.append(
            resolve(
                api,
                args.engagement_id,
                finding_id,
                known_finding_ids=known_finding_ids,
                topology_id=graph.get("topology_id"),
                timeout=args.timeout,
            )
        )

    edge_failures = 0
    unique_edges = {
        (e["from_node"], e["to_node"], e["rule_name"], tuple(e.get("evidence", []))): e
        for e in edges
    }
    for edge in unique_edges.values():
        if not edge.get("evidence"):
            edge_failures += 1
            print(f"EDGE WITHOUT EVIDENCE: {edge['from_node']} -> {edge['to_node']}")
        elif not all(cache[e].ok for e in edge["evidence"]):
            edge_failures += 1

    by_kind: dict[str, list[int]] = {}
    for r in resolutions:
        counts = by_kind.setdefault(r.kind, [0, 0])
        counts[0] += int(r.ok)
        counts[1] += 1
    failed = [r for r in resolutions if not r.ok]

    print(f"engagement {args.engagement_id}: topology {graph.get('topology_id')}")
    print(
        f"graph: {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges, "
        f"{len(graph.get('paths', []))} paths, truncated={graph.get('truncated')}"
    )
    for kind, (ok, total) in sorted(by_kind.items()):
        print(f"  {kind}: {ok} of {total} resolved")
    ok_total = len(resolutions) - len(failed)
    print(f"evidence ids resolved: {ok_total} of {len(resolutions)}")
    print(
        f"edges with every evidence id resolved: {len(unique_edges) - edge_failures} of "
        f"{len(unique_edges)}"
    )
    for r in failed:
        print(f"FAILED {r.kind} {r.evidence_id} ({r.status}) {r.url}\n  {r.detail[:300]}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump([asdict(r) for r in resolutions], fh, indent=2)
    return 0 if not failed and edge_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
