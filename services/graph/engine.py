"""Path enumeration, chokepoints and remediation simulation.

Enumeration is exhaustive up to the stated limits and deterministic: shortest paths
first, ties broken by the sequence of edge ids. Only shortcut-free paths are listed: a
path that steps to a node some earlier node on it already has a direct edge to is a
detour around a shorter path (e.g. compromising the proxy to reach a gateway the
attacker could already reach from the entry zone), so it is not listed separately.
Nothing here scores, ranks or prunes by risk (path scoring is pending sign-off,
DECISIONS.md D-039). When a limit is hit the
result says so; it never silently drops paths.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field

from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import (
    AttackGraphResult,
    AttackPath,
    Chokepoint,
    PathEdge,
    SimulationResult,
)
from packages.schema.models.observation import Observation
from packages.schema.models.provenance import Confidence
from packages.schema.models.topology import NetworkTopology
from services.graph.builder import AttackGraph, build_attack_graph
from services.graph.ruleset import RuleSet, load_ruleset

DEFAULT_MAX_DEPTH = 12
DEFAULT_MAX_PATHS = 1000
DEFAULT_MAX_EXPANSIONS = 2_000_000


@dataclass(frozen=True)
class PathEnumeration:
    paths: tuple[AttackPath, ...]
    truncated: bool


@dataclass
class _WalkState:
    max_expansions: int
    expansions: int = 0
    budget_hit: bool = False
    deeper_exists: bool = False
    level: list[tuple[PathEdge, ...]] = field(default_factory=list)
    successors: dict[str, frozenset[str]] = field(default_factory=dict)

    def is_shortcut(self, node: str, target: str, visited: set[str]) -> bool:
        """True when a node on the path other than `node` reaches `target` directly."""
        return any(target in self.successors.get(v, frozenset()) for v in visited if v != node)


def _walk(
    graph: AttackGraph,
    adjacency: dict[str, list[PathEdge]],
    state: _WalkState,
    node: str,
    trail: list[PathEdge],
    visited: set[str],
    depth: int,
) -> None:
    """Depth-limited DFS collecting goal paths of exactly `depth` edges."""
    if state.budget_hit:
        return
    if len(trail) == depth:
        if node in graph.goal_nodes:
            state.level.append(tuple(trail))
        if any(
            e.to_node not in visited and not state.is_shortcut(node, e.to_node, visited)
            for e in adjacency.get(node, [])
        ):
            state.deeper_exists = True
        return
    for edge in adjacency.get(node, []):
        if edge.to_node in visited or state.is_shortcut(node, edge.to_node, visited):
            continue
        state.expansions += 1
        if state.expansions > state.max_expansions:
            state.budget_hit = True
            return
        trail.append(edge)
        visited.add(edge.to_node)
        _walk(graph, adjacency, state, edge.to_node, trail, visited, depth)
        visited.discard(edge.to_node)
        trail.pop()


def path_id_for(edges: Iterable[PathEdge]) -> str:
    material = "\x1f".join(e.edge_id for e in edges)
    return "path:" + hashlib.sha256(material.encode()).hexdigest()[:16]


def enumerate_paths(
    graph: AttackGraph,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_expansions: int = DEFAULT_MAX_EXPANSIONS,
) -> PathEnumeration:
    """Every shortcut-free simple path from an attacker node to a goal node, by iterative
    deepening.

    Level d collects all paths of exactly d edges, sorted by edge ids. Levels are taken
    in order until `max_paths` is reached, so a truncated result is always "every path
    up to length k, then a deterministic prefix of length k+1".
    """
    if max_depth < 1 or max_paths < 1:
        raise ValueError("max_depth and max_paths must be positive")
    adjacency = {node: graph.out_edges(node) for node in graph.nodes}
    collected: list[tuple[PathEdge, ...]] = []
    state = _WalkState(
        max_expansions=max_expansions,
        successors={n: frozenset(e.to_node for e in edges) for n, edges in adjacency.items()},
    )
    truncated = False

    for depth in range(1, max_depth + 1):
        state.level = []
        state.deeper_exists = False
        for start in graph.attacker_nodes:
            _walk(graph, adjacency, state, start, [], {start}, depth)

        level = sorted(state.level, key=lambda edges: tuple(e.edge_id for e in edges))
        collected.extend(level)
        if state.budget_hit:
            truncated = True
            break
        if len(collected) >= max_paths:
            truncated = len(collected) > max_paths or (state.deeper_exists and depth < max_depth)
            collected = collected[:max_paths]
            break
        if not state.deeper_exists:
            break
        if depth == max_depth:
            truncated = True

    paths = tuple(AttackPath(path_id=path_id_for(edges), edges=edges) for edges in collected)
    return PathEnumeration(paths=paths, truncated=truncated)


def reachable_goals(graph: AttackGraph, without_finding: str | None = None) -> set[str]:
    """Goal nodes reachable from any attacker node, optionally ignoring every edge that
    depends on one finding."""
    adjacency: dict[str, list[str]] = {}
    for edge in graph.edges.values():
        if without_finding is not None and without_finding in edge.finding_ids:
            continue
        adjacency.setdefault(edge.from_node, []).append(edge.to_node)
    seen = set(graph.attacker_nodes)
    stack = list(graph.attacker_nodes)
    while stack:
        for nxt in adjacency.get(stack.pop(), []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen & graph.goal_nodes


def find_chokepoints(graph: AttackGraph, paths: Iterable[AttackPath]) -> tuple[Chokepoint, ...]:
    """For each finding on a path: the goals that become unreachable and the paths that
    disappear if it is fixed. A path breaks when any of its steps depends on the finding
    (`PathEdge.finding_ids`). Ranked by goals cut, then paths broken, then finding id."""
    broken: dict[str, list[str]] = {}
    for path in paths:
        for finding_id in sorted({f for e in path.edges for f in e.finding_ids}):
            broken.setdefault(finding_id, []).append(path.path_id)
    baseline = reachable_goals(graph)
    cut = {f: sorted(baseline - reachable_goals(graph, f)) for f in broken}
    ordered = sorted(broken.items(), key=lambda item: (-len(cut[item[0]]), -len(item[1]), item[0]))
    result: list[Chokepoint] = []
    for rank, (finding_id, path_ids) in enumerate(ordered, start=1):
        finding = graph.findings[finding_id]
        what = ", ".join(finding.cve_ids) or finding.title or finding_id
        result.append(
            Chokepoint(
                finding_id=finding_id,
                paths_broken=path_ids,
                remediation=f"Remediate {what} on {finding.asset_id}",
                rank=rank,
                goals_cut=cut[finding_id],
                asset_id=finding.asset_id,
                cve_ids=tuple(finding.cve_ids),
            )
        )
    return tuple(result)


_CONFIDENCE_RANK = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


def rank_paths(
    graph: AttackGraph, paths: Iterable[AttackPath], enriched: Iterable[EnrichedFinding]
) -> tuple[AttackPath, ...]:
    """Order already-enumerated paths for an analyst (DECISIONS.md D-047).

    Lexicographic, no weights: (1) weakest-step confidence, high first, so fully
    observed paths come before ones resting on an assumption; (2) the highest stored ERS
    of any finding the path exploits, unscored last (ERS is read, never recomputed:
    D-028); (3) fewer steps; (4) edge ids. Ranking reorders; it never adds or drops a
    path (Hard Rule 1).
    """
    ers: dict[str, float] = {
        e.finding.finding_id: e.ers.value for e in enriched if e.ers is not None
    }

    def top_ers(path: AttackPath) -> tuple[float, str] | None:
        scored = [(ers[f], f) for edge in path.edges for f in edge.finding_ids if f in ers]
        return max(scored, key=lambda item: (item[0], item[1])) if scored else None

    def key(path: AttackPath) -> tuple[int, int, float, int, tuple[str, ...]]:
        best = top_ers(path)
        return (
            -_CONFIDENCE_RANK[path.confidence],
            0 if best is not None else 1,
            -(best[0] if best is not None else 0.0),
            len(path.edges),
            tuple(e.edge_id for e in path.edges),
        )

    ordered = sorted(paths, key=key)
    result: list[AttackPath] = []
    for rank, path in enumerate(ordered, start=1):
        weakest_edge = min(path.edges, key=lambda e: _CONFIDENCE_RANK[e.confidence])
        best = top_ers(path)
        if best is None:
            ers_text = "no finding on this path has a stored ERS (not scored)"
        else:
            finding = graph.findings[best[1]]
            what = ", ".join(finding.cve_ids) or finding.title or best[1]
            ers_text = f"highest stored ERS on the path is {best[0]:.1f} ({what})"
        explanation = (
            f"Rank {rank}: {path.confidence.value} confidence "
            f"(weakest step: {weakest_edge.rule_name}); {ers_text}; "
            f"{len(path.edges)} steps."
        )
        result.append(path.model_copy(update={"rank": rank, "rank_explanation": explanation}))
    return tuple(result)


def analyze(
    *,
    engagement_id: str,
    observations: Iterable[Observation],
    findings: Iterable[Finding],
    topology: NetworkTopology,
    enriched: Iterable[EnrichedFinding] = (),
    ruleset: RuleSet | None = None,
    exclude_finding_ids: Iterable[str] = (),
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> AttackGraphResult:
    """Build, enumerate and find chokepoints in one call. The single entry point the API
    uses. Pure: the same inputs always serialise to the same bytes."""
    rules = ruleset or load_ruleset()
    enriched = list(enriched)
    graph = build_attack_graph(
        engagement_id=engagement_id,
        observations=observations,
        findings=findings,
        topology=topology,
        ruleset=rules,
        enriched=enriched,
        exclude_finding_ids=exclude_finding_ids,
    )
    enumeration = enumerate_paths(graph, max_depth=max_depth, max_paths=max_paths)
    ranked = rank_paths(graph, enumeration.paths, enriched)
    return AttackGraphResult(
        engagement_id=engagement_id,
        topology_id=topology.topology_id,
        rules_digest=rules.digest,
        nodes=tuple(graph.nodes.values()),
        edges=tuple(graph.edges.values()),
        paths=ranked,
        chokepoints=find_chokepoints(graph, ranked),
        unclassified_findings=graph.unclassified,
        unzoned_addresses=graph.unzoned_addresses,
        max_depth=max_depth,
        max_paths=max_paths,
        truncated=enumeration.truncated,
    )


def simulate_remediation(
    *,
    baseline: AttackGraphResult,
    fixed_finding_ids: Iterable[str],
    engagement_id: str,
    observations: Iterable[Observation],
    findings: Iterable[Finding],
    topology: NetworkTopology,
    enriched: Iterable[EnrichedFinding] = (),
    ruleset: RuleSet | None = None,
) -> SimulationResult:
    """Mark findings fixed, rebuild from the same facts, and report what disappeared.
    A rebuild, not a filter: the new graph is exactly what the engine would build if the
    findings had never been reported."""
    fixed = tuple(sorted(set(fixed_finding_ids)))
    after = analyze(
        engagement_id=engagement_id,
        observations=observations,
        findings=findings,
        topology=topology,
        enriched=enriched,
        ruleset=ruleset,
        exclude_finding_ids=fixed,
        max_depth=baseline.max_depth,
        max_paths=baseline.max_paths,
    )
    after_ids = {p.path_id for p in after.paths}
    before_goals = {p.goal_node for p in baseline.paths}
    after_goals = {p.goal_node for p in after.paths}
    return SimulationResult(
        fixed_finding_ids=fixed,
        baseline_path_count=len(baseline.paths),
        remaining_path_count=len(after.paths),
        removed_path_ids=tuple(p.path_id for p in baseline.paths if p.path_id not in after_ids),
        goals_no_longer_reachable=tuple(sorted(before_goals - after_goals)),
        after=after,
    )
