"""Attack-path validity evaluation for the Layer 3 engine (services/graph).

Runs the deterministic engine (`services.graph.engine.analyze`) over the observation
fixtures in ``tests/fixtures/observations/`` and grades the enumerated paths against
the chains in ``lab/ground_truth.yaml`` (hop lists restated machine-readably in
``evals/golden/attack_paths_expected.yaml``). No network, no model, no clock: the same
inputs always produce byte-identical results.

What this is NOT
----------------
It is not a lab run. Eight of the ten lab hosts are covered only by synthetic fixtures
(hand-authored tool output run through the real parsers, see
``tests/fixtures/observations/README.md``). The verdicts say what the engine does with
those facts, not what it finds in the running lab.

Matching rules
--------------
Each enumerated path is reduced to the sequence of lab hosts it touches: every node's
machine (``host:<ip>`` or a declared multi-homed name) is mapped back to a ground-truth
host by ``ip`` / ``secondary_ip``; the attacker node has no machine and is skipped;
consecutive repeats are collapsed (access -> exec -> creds on one host is one hop).

* **strict**: the path's host sequence equals the expected host list exactly.
* **lenient**: the expected hosts appear in the path's host sequence in order; other
  hosts may appear before, between or after them.

A host counts as visited at any capability, including bare network access. So each
verdict also reports how the final expected host was reached (``network_access``,
``file_read``, ``credentials`` or ``code_execution``) and, for every CVE the steps name,
whether the example path actually exploits it.

Feasibility
-----------
Separately from the engine, every consecutive expected hop is checked against
``lab/topology.yaml`` (transcribed from ``lab/docker-compose.yml``; see
``tests/unit/test_lab_topology.py``): the first host must sit in an attacker-entry zone,
and each later host must share a zone with the previous one or be covered by a declared
flow. An infeasible hop is a ground-truth problem, reported apart from engine misses.
The same check is applied to every ``reachable_from`` entry in ground_truth.yaml.
"""

from __future__ import annotations

# ruff: noqa: E402
import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

# Ensure repository root is on sys.path when script is invoked directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packages.schema.models.finding import Finding
from packages.schema.models.graph import AttackGraphResult, AttackPath, GraphNode, NodeKind
from packages.schema.models.observation import Observation, ScanResult
from packages.schema.models.topology import NetworkTopology
from services.graph.engine import DEFAULT_MAX_DEPTH, DEFAULT_MAX_PATHS, analyze
from services.normalize.interim_bridge import findings_from_observations

_DEFAULT_GROUND_TRUTH = _REPO_ROOT / "lab" / "ground_truth.yaml"
_DEFAULT_TOPOLOGY = _REPO_ROOT / "lab" / "topology.yaml"
_DEFAULT_EXPECTED = _REPO_ROOT / "evals" / "golden" / "attack_paths_expected.yaml"
_DEFAULT_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "observations"
_DEFAULT_OUTPUT_JSON = _REPO_ROOT / "evals" / "results" / "attack_paths_results.json"
_DEFAULT_OUTPUT_MD = _REPO_ROOT / "evals" / "results" / "attack_paths_results.md"

# Fixture files and their provenance, as stated in tests/fixtures/observations/README.md.
FIXTURE_FILES: tuple[tuple[str, str], ...] = (
    ("lab_baseline.json", "real"),
    ("lab_dmz_extended.json", "synthetic"),
    ("lab_internal.json", "synthetic"),
    ("lab_data.json", "synthetic"),
    ("lab_extended_nuclei.json", "synthetic"),
)

# Fixed so the bridge's findings (and therefore the results) are reproducible.
DETECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)

BANNER = (
    "FIXTURE-BASED, NOT A LAB RUN. The engine ran over tests/fixtures/observations/, in "
    "which {synthetic} of {total} lab hosts are covered only by synthetic fixtures "
    "(hand-authored tool output run through the real parsers, per "
    "tests/fixtures/observations/README.md). These verdicts check the engine and the "
    "ground truth against those facts; they are not measurements of the lab."
)

FOUND = "FOUND"
NOT_FOUND = "NOT FOUND"

_KIND_STRENGTH = {
    NodeKind.NETWORK_ACCESS: 0,
    NodeKind.CREDENTIALS: 1,
    NodeKind.FILE_READ: 2,
    NodeKind.CODE_EXECUTION: 3,
}
_FOOTHOLD_KINDS = {NodeKind.CODE_EXECUTION, NodeKind.FILE_READ, NodeKind.CREDENTIALS}
_EXPLOIT_RULES = {"exploit_grants_code_execution", "exploit_grants_file_read"}


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class ExpectedPath:
    path_id: str
    hosts: tuple[str, ...]
    cves: dict[str, tuple[str, ...]]


def _load_yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_expected(path: Path) -> list[ExpectedPath]:
    data = _load_yaml(path)
    out: list[ExpectedPath] = []
    for item in data["paths"]:
        cves = {host: tuple(ids) for host, ids in (item.get("cves") or {}).items()}
        out.append(ExpectedPath(path_id=item["id"], hosts=tuple(item["hosts"]), cves=cves))
    return out


def load_topology(path: Path) -> NetworkTopology:
    return NetworkTopology.model_validate(_load_yaml(path))


def load_observations(
    fixtures_dir: Path, files: tuple[tuple[str, str], ...] = FIXTURE_FILES
) -> tuple[list[Observation], dict[str, str]]:
    """All observations from the fixture files, plus {observation_id: provenance}."""
    observations: list[Observation] = []
    provenance: dict[str, str] = {}
    for name, label in files:
        raw = json.loads((fixtures_dir / name).read_text(encoding="utf-8"))
        result = ScanResult.model_validate(raw)
        for obs in result.observations:
            observations.append(obs)
            provenance[obs.observation_id] = label
    return observations, provenance


def observation_address(obs: Observation) -> str:
    """The IP an observation is about: its nmap-style endpoint, URL host or bare subject."""
    text = (obs.attributes.get("endpoint") or obs.subject).strip()
    if "://" in text:
        return urlsplit(text).hostname or ""
    return text.split("/", 1)[0].rsplit(":", 1)[0] if "/" in text else text


class HostIndex:
    """Ground-truth host names <-> addresses <-> engine machine ids <-> zones."""

    def __init__(self, ground_truth: dict[str, Any], topology: NetworkTopology) -> None:
        self.topology = topology
        self.addresses: dict[str, tuple[str, ...]] = {}
        self.by_address: dict[str, str] = {}
        for host in ground_truth["hosts"]:
            addrs = [host["ip"]]
            if host.get("secondary_ip"):
                addrs.append(host["secondary_ip"])
            self.addresses[host["name"]] = tuple(addrs)
            for addr in addrs:
                self.by_address[addr] = host["name"]
        self.names = tuple(h["name"] for h in ground_truth["hosts"])

    def host_of_machine(self, machine: str | None) -> str | None:
        """Ground-truth name for an engine machine id; `unmapped:<id>` if none matches."""
        if machine is None:
            return None
        if machine.startswith("host:"):
            address = machine.removeprefix("host:")
            return self.by_address.get(address, f"unmapped:{machine}")
        for declared in self.topology.multi_homed_hosts:
            if declared.name == machine:
                names = {self.by_address.get(a) for a in declared.addresses}
                if len(names) == 1 and None not in names:
                    return names.pop()
        return machine if machine in self.addresses else f"unmapped:{machine}"

    def zones(self, host: str) -> tuple[str, ...]:
        found: set[str] = set()
        for address in self.addresses.get(host, ()):
            found.update(self.topology.zones_of(address))
        return tuple(z.name for z in self.topology.zones if z.name in found)


# --------------------------------------------------------------------------- feasibility


def entry_feasible(index: HostIndex, host: str) -> tuple[bool, str]:
    entry = [z for z in index.zones(host) if index.topology.zone(z).attacker_entry]
    if entry:
        return True, f"{host} is in attacker-entry zone {entry[0]}"
    zones = ", ".join(index.zones(host)) or "no declared zone"
    return False, f"{host} ({zones}) is not in an attacker-entry zone"


def hop_feasible(index: HostIndex, source: str, target: str) -> tuple[bool, str]:
    """Can `source` reach `target` under the declared topology (lab/topology.yaml)?"""
    src = index.zones(source)
    dst = index.zones(target)
    shared = [z for z in src if z in dst]
    if shared and index.topology.intra_zone_reachable:
        return True, f"{source} and {target} share zone {shared[0]}"
    for flow in index.topology.flows:
        if flow.from_zone in src and flow.to_zone in dst:
            return True, f"declared flow {flow.from_zone} -> {flow.to_zone}"
    return False, (
        f"{source} ({', '.join(src) or 'no zone'}) and {target} "
        f"({', '.join(dst) or 'no zone'}) share no zone and no flow connects them"
    )


def path_feasibility(index: HostIndex, expected: ExpectedPath) -> dict[str, Any]:
    hops: list[dict[str, Any]] = []
    ok, why = entry_feasible(index, expected.hosts[0])
    hops.append({"from": "attacker", "to": expected.hosts[0], "feasible": ok, "reason": why})
    for source, target in zip(expected.hosts, expected.hosts[1:], strict=False):
        ok, why = hop_feasible(index, source, target)
        hops.append({"from": source, "to": target, "feasible": ok, "reason": why})
    return {"feasible": all(h["feasible"] for h in hops), "hops": hops}


def ground_truth_contradictions(
    ground_truth: dict[str, Any], index: HostIndex
) -> list[dict[str, Any]]:
    """`reachable_from` / `reachable_from_outside` claims the topology does not support."""
    out: list[dict[str, Any]] = []
    for host in ground_truth["hosts"]:
        name = host["name"]
        for source in host.get("reachable_from", []) or []:
            ok, why = hop_feasible(index, source, name)
            if not ok:
                out.append({"host": name, "claim": f"reachable_from {source}", "reason": why})
        if "reachable_from_outside" in host:
            ok, why = entry_feasible(index, name)
            if ok != bool(host["reachable_from_outside"]):
                claim = f"reachable_from_outside: {str(host['reachable_from_outside']).lower()}"
                out.append({"host": name, "claim": claim, "reason": why})
    return out


# --------------------------------------------------------------------------- matching


def host_sequence(
    path: AttackPath, nodes: dict[str, GraphNode], index: HostIndex
) -> tuple[str, ...]:
    """Ground-truth hosts a path touches, in order, consecutive repeats collapsed."""
    seq: list[str] = []
    for node_id in [path.edges[0].from_node, *(e.to_node for e in path.edges)]:
        host = index.host_of_machine(nodes[node_id].machine)
        if host is not None and (not seq or seq[-1] != host):
            seq.append(host)
    return tuple(seq)


def strict_match(expected: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    return sequence == expected


def lenient_match(expected: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    """`expected` is an ordered (not necessarily contiguous) subsequence of `sequence`."""
    remaining = iter(sequence)
    return all(any(h == want for h in remaining) for want in expected)


def _reached_as(path: AttackPath, nodes: dict[str, GraphNode], index: HostIndex, host: str) -> str:
    kinds = [
        nodes[e.to_node].kind
        for e in path.edges
        if index.host_of_machine(nodes[e.to_node].machine) == host
    ]
    return max(kinds, key=lambda k: _KIND_STRENGTH[k]).value if kinds else "not reached"


def _path_summary(
    path: AttackPath, nodes: dict[str, GraphNode], index: HostIndex
) -> dict[str, Any]:
    return {
        "path_id": path.path_id,
        "confidence": path.confidence.value,
        "hosts": list(host_sequence(path, nodes, index)),
        "nodes": [path.edges[0].from_node, *(e.to_node for e in path.edges)],
        "rules": [e.rule_name for e in path.edges],
    }


# --------------------------------------------------------------------------- diagnosis


class _Facts:
    """Lookups over the inputs and the engine result, for explaining verdicts."""

    def __init__(
        self,
        result: AttackGraphResult,
        findings: list[Finding],
        observations: list[Observation],
        index: HostIndex,
    ) -> None:
        self.result = result
        self.index = index
        self.nodes = {n.node_id: n for n in result.nodes}
        self.findings = {f.finding_id: f for f in findings}
        self.unclassified = {u.finding_id: u for u in result.unclassified_findings}
        self.kinds_by_host: dict[str, set[NodeKind]] = {}
        for node in result.nodes:
            host = index.host_of_machine(node.machine)
            if host is not None:
                self.kinds_by_host.setdefault(host, set()).add(node.kind)
        self.findings_by_host: dict[str, list[Finding]] = {}
        for finding in findings:
            host = index.host_of_machine(finding.asset_id)
            if host is not None:
                self.findings_by_host.setdefault(host, []).append(finding)
        self.observed_hosts = {
            h
            for o in observations
            if (h := index.by_address.get(observation_address(o))) is not None
        }

    def has_edge_between(self, source: str, target: str) -> bool:
        for edge in self.result.edges:
            a = self.index.host_of_machine(self.nodes[edge.from_node].machine)
            b = self.index.host_of_machine(self.nodes[edge.to_node].machine)
            if a == source and b == target:
                return True
        return False

    def why_no_foothold(self, host: str) -> str:
        found = self.findings_by_host.get(host, [])
        ips = ", ".join(self.index.addresses.get(host, ()))
        if not found:
            return (
                f"no observed vulnerability on {host} ({ips}) in the fixtures (no "
                "vuln_candidate observation, so no finding), so the engine has no foothold there"
            )
        reasons = []
        for f in sorted(found, key=lambda f: f.finding_id):
            what = ", ".join(f.cve_ids) or f.title
            if f.finding_id in self.unclassified:
                reasons.append(f"{what} unclassified: {self.unclassified[f.finding_id].reason}")
            else:
                reasons.append(f"{what} classified, but its service is unreachable from the entry")
        return f"no foothold on {host}: " + "; ".join(reasons)

    def cve_status(self, host: str, cve: str) -> tuple[bool, bool | None, str]:
        """(finding in fixtures, classified, explanation)."""
        for f in self.findings_by_host.get(host, []):
            if cve in f.cve_ids:
                if f.finding_id in self.unclassified:
                    reason = self.unclassified[f.finding_id].reason
                    return True, False, f"finding is unclassified: {reason}"
                return True, True, "finding is classified"
        return False, None, f"no vuln_candidate observation reports {cve} on {host} in the fixtures"


def diagnose(expected: ExpectedPath, facts: _Facts, feasibility: dict[str, Any]) -> list[str]:
    """Why no enumerated path visits the expected hosts in order. One line per cause."""
    reasons: list[str] = []
    hosts = expected.hosts
    for hop in feasibility["hops"]:
        if not hop["feasible"]:
            reasons.append(
                f"hop {hop['from']} -> {hop['to']} unreachable per lab/topology.yaml "
                f"(ground truth infeasible): {hop['reason']}"
            )
    for i, host in enumerate(hosts):
        kinds = facts.kinds_by_host.get(host, set())
        last = i == len(hosts) - 1
        if not kinds:
            if host not in facts.observed_hosts:
                reasons.append(f"{host} has no observations in the fixtures")
            else:
                reasons.append(f"{host} is not reachable from the attacker in the engine graph")
        if not last and not (kinds & _FOOTHOLD_KINDS):
            reasons.append(facts.why_no_foothold(host))
        if not last:
            nxt = hosts[i + 1]
            if not facts.has_edge_between(host, nxt) and kinds & _FOOTHOLD_KINDS:
                reasons.append(f"engine graph has no edge from {host} to {nxt}")
    return reasons


# --------------------------------------------------------------------------- evaluation


def evaluate_expected(
    expected: ExpectedPath, paths: tuple[AttackPath, ...], facts: _Facts
) -> dict[str, Any]:
    index = facts.index
    nodes = facts.nodes
    feasibility = path_feasibility(index, expected)
    sequences = [host_sequence(p, nodes, index) for p in paths]
    strict = [p for p, s in zip(paths, sequences, strict=True) if strict_match(expected.hosts, s)]
    lenient = [p for p, s in zip(paths, sequences, strict=True) if lenient_match(expected.hosts, s)]
    # Enumeration order is shortest first, then edge ids, so [0] is deterministic.
    example = strict[0] if strict else (lenient[0] if lenient else None)

    cve_checks: list[dict[str, Any]] = []
    exploited: set[str] = set()
    if example is not None:
        for edge in example.edges:
            if edge.rule_name in _EXPLOIT_RULES:
                for fid in edge.finding_ids:
                    exploited.update(facts.findings[fid].cve_ids)
    for host in expected.hosts:
        for cve in expected.cves.get(host, ()):
            in_fixtures, classified, note = facts.cve_status(host, cve)
            cve_checks.append(
                {
                    "host": host,
                    "cve": cve,
                    "finding_in_fixtures": in_fixtures,
                    "classified": classified,
                    "exploited_on_example_path": (cve in exploited) if example else None,
                    "note": note,
                }
            )

    final = expected.hosts[-1]
    reached_as = _reached_as(example, nodes, index, final) if example else None
    diagnosis = [] if lenient else diagnose(expected, facts, feasibility)
    return {
        "id": expected.path_id,
        "hosts": list(expected.hosts),
        "feasibility": feasibility,
        "strict": {"verdict": FOUND if strict else NOT_FOUND, "matching_paths": len(strict)},
        "lenient": {"verdict": FOUND if lenient else NOT_FOUND, "matching_paths": len(lenient)},
        "example_path": _path_summary(example, nodes, index) if example else None,
        "final_host_reached_as": reached_as,
        "cve_checks": cve_checks,
        "diagnosis": diagnosis,
        "summary": verdict_line(
            expected.path_id, len(strict), len(lenient), final, reached_as, cve_checks, diagnosis
        ),
    }


def verdict_line(
    path_id: str,
    strict: int,
    lenient: int,
    final: str,
    reached_as: str | None,
    cve_checks: list[dict[str, Any]],
    diagnosis: list[str],
) -> str:
    """One human-readable line per expected path; also what the CLI prints."""
    head = (
        f"{path_id}: strict {FOUND if strict else NOT_FOUND} ({strict} paths), "
        f"lenient {FOUND if lenient else NOT_FOUND} ({lenient} paths)"
    )
    if not lenient:
        return head + ". Reasons: " + " | ".join(diagnosis)
    parts = [f"final host {final} reached as {reached_as}"]
    for check in cve_checks:
        if check["exploited_on_example_path"]:
            parts.append(f"{check['cve']} on {check['host']} exploited")
        else:
            parts.append(
                f"{check['cve']} on {check['host']} NOT exploited on example path ({check['note']})"
            )
    return head + "; " + "; ".join(parts)


def spurious_analysis(
    paths: tuple[AttackPath, ...], facts: _Facts, expected: list[ExpectedPath]
) -> dict[str, Any]:
    """Enumerated paths and goals that no expected chain accounts for.

    "On route" means the path's host sequence is a prefix of some expected host list
    (the attacker is partway along a ground-truth chain). Off-route paths are not
    necessarily wrong; ground truth lists three chains, not every chain.
    """
    index, nodes = facts.index, facts.nodes
    expected_hosts = {h for e in expected for h in e.hosts}
    goal_hosts: Counter[str] = Counter()
    off_route: Counter[tuple[str, ...]] = Counter()
    on_route = 0
    for path in paths:
        goal_host = index.host_of_machine(nodes[path.goal_node].machine) or "attacker"
        goal_hosts[goal_host] += 1
        seq = host_sequence(path, nodes, index)
        if any(e.hosts[: len(seq)] == seq for e in expected):
            on_route += 1
        else:
            off_route[seq] += 1
    unexpected_goals = sorted(h for h in goal_hosts if h not in expected_hosts)
    return {
        "rule": "on route = path's host sequence is a prefix of some expected host list",
        "on_route_paths": on_route,
        "off_route_paths": sum(off_route.values()),
        "off_route_sequences": [
            {"hosts": list(seq), "paths": n}
            for seq, n in sorted(off_route.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "goal_hosts": dict(sorted(goal_hosts.items())),
        "goal_hosts_not_on_any_expected_path": unexpected_goals,
    }


def run_evaluation(
    *,
    ground_truth_path: Path = _DEFAULT_GROUND_TRUTH,
    topology_path: Path = _DEFAULT_TOPOLOGY,
    expected_path: Path = _DEFAULT_EXPECTED,
    fixtures_dir: Path = _DEFAULT_FIXTURES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
) -> dict[str, Any]:
    ground_truth = _load_yaml(ground_truth_path)
    topology = load_topology(topology_path)
    expected = load_expected(expected_path)
    observations, provenance = load_observations(fixtures_dir)
    findings = findings_from_observations(observations, DETECTED_AT)
    result = analyze(
        engagement_id=topology.engagement_id,
        observations=observations,
        findings=findings,
        topology=topology,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    index = HostIndex(ground_truth, topology)
    facts = _Facts(result, findings, observations, index)

    # Which hosts have only synthetic observations (computed, not copied from the README).
    labels_by_host: dict[str, set[str]] = {}
    for obs in observations:
        host = index.by_address.get(observation_address(obs))
        if host is not None:
            labels_by_host.setdefault(host, set()).add(provenance[obs.observation_id])
    synthetic_only = sorted(h for h, labels in labels_by_host.items() if labels == {"synthetic"})

    by_conf = Counter(p.confidence.value for p in result.paths)
    by_goal_kind = Counter(facts.nodes[p.goal_node].kind.value for p in result.paths)
    crown = sum(
        1
        for p in result.paths
        if any(topology.zone(z).crown_jewel for z in facts.nodes[p.goal_node].zones)
        and facts.nodes[p.goal_node].kind == NodeKind.NETWORK_ACCESS
    )
    per_path = [evaluate_expected(e, result.paths, facts) for e in expected]

    return {
        "metadata": {
            "banner": BANNER.format(synthetic=len(synthetic_only), total=len(index.names)),
            "mode": "fixture-based (not a lab run)",
            "fixtures": [{"file": name, "provenance": label} for name, label in FIXTURE_FILES],
            "hosts_with_only_synthetic_observations": synthetic_only,
            "hosts_total": len(index.names),
            "ground_truth": "lab/ground_truth.yaml",
            "expected": "evals/golden/attack_paths_expected.yaml",
            "topology": "lab/topology.yaml",
            "topology_id": result.topology_id,
            "rules_digest": result.rules_digest,
            "engagement_id": result.engagement_id,
            "max_depth": result.max_depth,
            "max_paths": result.max_paths,
            "findings_detected_at": DETECTED_AT.isoformat(),
            "observations": len(observations),
            "findings": len(findings),
            "matching_rules": {
                "host_sequence": (
                    "engine machines mapped to ground-truth hosts by ip/secondary_ip; attacker "
                    "node skipped; consecutive repeats collapsed"
                ),
                "strict": "host sequence equals the expected host list exactly",
                "lenient": "expected hosts appear in order; other hosts may appear anywhere",
                "visited": "a host counts as visited at any capability, network access included",
            },
        },
        "engine": {
            "total_paths": len(result.paths),
            "truncated": result.truncated,
            "paths_by_confidence": {c: by_conf.get(c, 0) for c in ("high", "medium", "low")},
            "paths_by_goal_kind": dict(sorted(by_goal_kind.items())),
            "paths_to_crown_jewel_network_access": crown,
            "unclassified_findings": [
                {
                    "finding_id": u.finding_id,
                    "host": index.host_of_machine(u.asset_id),
                    "cve_ids": list(u.cve_ids),
                    "reason": u.reason,
                }
                for u in result.unclassified_findings
            ],
            "unzoned_addresses": list(result.unzoned_addresses),
            "chokepoints": [
                {
                    "rank": c.rank,
                    "host": index.host_of_machine(c.asset_id),
                    "cve_ids": list(c.cve_ids),
                    "paths_broken": len(c.paths_broken),
                    "goals_cut": c.goals_cut,
                }
                for c in result.chokepoints
            ],
        },
        "expected_paths": per_path,
        "summary": {
            "expected": len(per_path),
            "strict_found": sum(p["strict"]["verdict"] == FOUND for p in per_path),
            "lenient_found": sum(p["lenient"]["verdict"] == FOUND for p in per_path),
            "ground_truth_infeasible": sorted(
                p["id"] for p in per_path if not p["feasibility"]["feasible"]
            ),
        },
        "ground_truth_contradictions": ground_truth_contradictions(ground_truth, index),
        "spurious": spurious_analysis(result.paths, facts, expected),
    }


# --------------------------------------------------------------------------- output


def generate_markdown_report(results: dict[str, Any]) -> str:
    meta, engine, summary = results["metadata"], results["engine"], results["summary"]
    lines = [
        "# Attack Path Validity (Layer 3 engine)",
        "",
        f"> **{meta['banner']}**",
        "",
        f"**Mode:** {meta['mode']}  ",
        f"**Ground truth:** `{meta['ground_truth']}` (hop lists: `{meta['expected']}`)  ",
        f"**Topology:** `{meta['topology']}` (`{meta['topology_id']}`)  ",
        f"**Rules digest:** `{meta['rules_digest']}`  ",
        f"**Engine limits:** max_depth {meta['max_depth']}, max_paths {meta['max_paths']}  ",
        f"**Inputs:** {meta['observations']} observations, {meta['findings']} findings "
        f"(interim bridge, detected_at fixed at {meta['findings_detected_at']})  ",
        "**Hosts with only synthetic observations:** "
        + ", ".join(meta["hosts_with_only_synthetic_observations"]),
        "",
        "| Fixture | Provenance |",
        "|---|---|",
        *(f"| `{f['file']}` | {f['provenance']} |" for f in meta["fixtures"]),
        "",
        "## Matching rules",
        "",
        *(f"- **{k}**: {v}" for k, v in meta["matching_rules"].items()),
        "",
        "## Verdicts",
        "",
        f"Strict FOUND {summary['strict_found']}/{summary['expected']}, lenient FOUND "
        f"{summary['lenient_found']}/{summary['expected']}. Ground truth infeasible per "
        f"topology: {', '.join(summary['ground_truth_infeasible']) or 'none'}.",
        "",
        "| Path | Hosts | Feasible per topology | Strict | Lenient | Final host reached as |",
        "|---|---|---|---|---|---|",
    ]
    for p in results["expected_paths"]:
        lines.append(
            f"| {p['id']} | {' -> '.join(p['hosts'])} | "
            f"{'yes' if p['feasibility']['feasible'] else '**no**'} | "
            f"{p['strict']['verdict']} ({p['strict']['matching_paths']}) | "
            f"{p['lenient']['verdict']} ({p['lenient']['matching_paths']}) | "
            f"{p['final_host_reached_as'] or '-'} |"
        )
    for p in results["expected_paths"]:
        lines += [
            "",
            f"### {p['id']}",
            "",
            p["summary"],
            "",
            "Feasibility (lab/topology.yaml):",
            "",
        ]
        for hop in p["feasibility"]["hops"]:
            mark = "ok" if hop["feasible"] else "**INFEASIBLE**"
            lines.append(f"- {hop['from']} -> {hop['to']}: {mark} ({hop['reason']})")
        if p["cve_checks"]:
            lines += [
                "",
                "| Host | CVE | Finding in fixtures | Classified | Exploited on example |",
            ]
            lines.append("|---|---|---|---|---|")
            for c in p["cve_checks"]:
                lines.append(
                    f"| {c['host']} | {c['cve']} | {c['finding_in_fixtures']} | "
                    f"{c['classified']} | {c['exploited_on_example_path']} |"
                )
        if p["example_path"]:
            ex = p["example_path"]
            lines += [
                "",
                f"Example path `{ex['path_id']}` (confidence {ex['confidence']}):",
                "",
                "`" + " -> ".join(ex["nodes"]) + "`",
                "",
                "Rules: " + ", ".join(ex["rules"]),
            ]
        if p["diagnosis"]:
            lines += ["", "Diagnosis:", "", *(f"- {d}" for d in p["diagnosis"])]

    lines += [
        "",
        "## Ground-truth contradictions (lab/ground_truth.yaml vs lab/topology.yaml)",
        "",
        "Reported, not corrected. The owner decides whether the lab wiring or the ground "
        "truth changes.",
        "",
    ]
    contradictions = results["ground_truth_contradictions"]
    if contradictions:
        lines += ["| Host | Claim | Why it fails |", "|---|---|---|"]
        lines += [f"| {c['host']} | {c['claim']} | {c['reason']} |" for c in contradictions]
    else:
        lines.append("None.")

    by_conf = engine["paths_by_confidence"]
    lines += [
        "",
        "## Engine output",
        "",
        f"- Total paths: {engine['total_paths']} (truncated: {engine['truncated']})",
        f"- By confidence: high {by_conf['high']}, medium {by_conf['medium']}, "
        f"low {by_conf['low']}",
        "- By goal kind: " + ", ".join(f"{k} {v}" for k, v in engine["paths_by_goal_kind"].items()),
        f"- Paths ending in network access to a crown-jewel zone: "
        f"{engine['paths_to_crown_jewel_network_access']}",
        f"- Unzoned addresses: {', '.join(engine['unzoned_addresses']) or 'none'}",
        "",
        "### Unclassified findings",
        "",
    ]
    if engine["unclassified_findings"]:
        lines += ["| Host | CVEs | Reason |", "|---|---|---|"]
        lines += [
            f"| {u['host']} | {', '.join(u['cve_ids']) or '-'} | {u['reason']} |"
            for u in engine["unclassified_findings"]
        ]
    else:
        lines.append("None.")
    lines += [
        "",
        "### Chokepoints",
        "",
        "| Rank | Host | CVEs | Paths broken | Goals cut |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {c['rank']} | {c['host']} | {', '.join(c['cve_ids']) or '-'} | "
        f"{c['paths_broken']} | {', '.join(c['goals_cut']) or '-'} |"
        for c in engine["chokepoints"]
    ]
    sp = results["spurious"]
    lines += [
        "",
        "## Spurious-path analysis",
        "",
        f"Rule: {sp['rule']}. Off-route paths are not necessarily wrong; ground truth lists "
        "three chains, not every chain.",
        "",
        f"- On route: {sp['on_route_paths']}; off route: {sp['off_route_paths']}",
        "- Goal hosts (paths ending there): "
        + ", ".join(f"{h} {n}" for h, n in sp["goal_hosts"].items()),
        "- Goal hosts not on any expected path: "
        + (", ".join(sp["goal_hosts_not_on_any_expected_path"]) or "none"),
        "",
        "| Off-route host sequence | Paths |",
        "|---|---|",
        *(f"| {' -> '.join(s['hosts'])} | {s['paths']} |" for s in sp["off_route_sequences"]),
        "",
    ]
    return "\n".join(lines)


def write_outputs(results: dict[str, Any], output_json: Path, output_md: Path) -> None:
    """Write JSON and Markdown results with LF line endings."""
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(generate_markdown_report(results))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Grade Layer 3 attack paths against lab/ground_truth.yaml (fixture-based)."
    )
    parser.add_argument("--ground-truth", type=Path, default=_DEFAULT_GROUND_TRUTH)
    parser.add_argument("--topology", type=Path, default=_DEFAULT_TOPOLOGY)
    parser.add_argument("--expected", type=Path, default=_DEFAULT_EXPECTED)
    parser.add_argument("--fixtures-dir", type=Path, default=_DEFAULT_FIXTURES)
    parser.add_argument("--output-json", type=Path, default=_DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", type=Path, default=_DEFAULT_OUTPUT_MD)
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout summary output")
    args = parser.parse_args(argv)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")

    for label, path in (
        ("Ground truth", args.ground_truth),
        ("Topology", args.topology),
        ("Expected paths", args.expected),
        ("Fixtures directory", args.fixtures_dir),
    ):
        if not path.exists():
            sys.stderr.write(f"Error: {label} not found at {path}\n")
            return 1

    results = run_evaluation(
        ground_truth_path=args.ground_truth,
        topology_path=args.topology,
        expected_path=args.expected,
        fixtures_dir=args.fixtures_dir,
    )
    write_outputs(results, args.output_json, args.output_md)

    if not args.quiet:
        engine = results["engine"]
        print("=" * 72)
        print(results["metadata"]["banner"])
        print("-" * 72)
        for p in results["expected_paths"]:
            print(p["summary"])
        print("-" * 72)
        for c in results["ground_truth_contradictions"]:
            print(f"ground truth contradiction: {c['host']} {c['claim']}: {c['reason']}")
        print(
            f"Total paths: {engine['total_paths']} (truncated: {engine['truncated']}); "
            f"by confidence: {engine['paths_by_confidence']}"
        )
        print(f"Unclassified findings: {len(engine['unclassified_findings'])}")
        sp = results["spurious"]
        print(f"On-route paths: {sp['on_route_paths']}; off-route: {sp['off_route_paths']}")
        print("=" * 72)
        print(f"Markdown report written to: {args.output_md}")
        print(f"JSON results written to:    {args.output_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
