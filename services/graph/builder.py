"""Deterministic attack-graph construction (Hard Rule 1).

`build_attack_graph` is a pure function of its inputs: observations, findings, optional
enrichment, the declared topology and the rule data. It reads no clock, no network and
no model. Nodes are attacker states; every edge is produced by exactly one named rule in
`rules/core.yaml` and carries the ids of the facts that satisfied it.

Each rule has one matcher here, registered in `MATCHERS`. A test checks that the
registry and the YAML name the same rules.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import networkx as nx

from packages.schema.models.finding import EnrichedFinding, Finding
from packages.schema.models.graph import (
    GraphNode,
    NodeKind,
    PathEdge,
    UnclassifiedFinding,
    weakest,
)
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.topology import NetworkTopology
from services.graph.capabilities import CapabilityMatch, classify
from services.graph.rules import CODE_EXECUTION, FILE_READ, RuleSet

# Rule names, one per matcher below. Kept as constants so a typo is an import error.
ENTRY = "entry_zone_service_access"
INTRA_ZONE = "intra_zone_service_access"
DECLARED_FLOW = "declared_flow_service_access"
EXPLOIT_EXEC = "exploit_grants_code_execution"
EXPLOIT_READ = "exploit_grants_file_read"
LOCAL_CREDS = "local_access_exposes_credentials"
CRED_REUSE = "credential_reuse_remote_login"

MATCHERS = frozenset(
    {ENTRY, INTRA_ZONE, DECLARED_FLOW, EXPLOIT_EXEC, EXPLOIT_READ, LOCAL_CREDS, CRED_REUSE}
)

_SERVICE_KINDS = {
    ObservationKind.PORT_OPEN,
    ObservationKind.SERVICE_VERSION,
    ObservationKind.VULN_CANDIDATE,
}
_DEFAULT_PORTS = {"http": 80, "https": 443}


# --------------------------------------------------------------------------- parsing


def _canonical_ip(text: str) -> str | None:
    try:
        return ipaddress.ip_address(text.strip().strip("[]")).compressed
    except ValueError:
        return None


def parse_endpoint(text: str) -> tuple[str, int, str] | None:
    """Parse `<ip>:<port>/<proto>`, `[v6]:<port>/<proto>` or a URL into
    (canonical ip, port, proto). Hostnames return None: zones are by address only."""
    text = text.strip()
    if not text:
        return None
    if "://" in text:
        parts = urlsplit(text)
        address = _canonical_ip(parts.hostname or "")
        try:
            port = parts.port or _DEFAULT_PORTS.get(parts.scheme.lower())
        except ValueError:
            return None
        if address is None or port is None:
            return None
        return address, port, "tcp"
    if "/" not in text:
        return None
    hostport, proto = text.rsplit("/", 1)
    if ":" not in hostport:
        return None
    host, port_text = hostport.rsplit(":", 1)
    address = _canonical_ip(host)
    if address is None or not port_text.isdigit():
        return None
    return address, int(port_text), proto.lower() or "tcp"


def _format_endpoint(address: str, port: int, proto: str) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port}/{proto}"


def _observation_endpoint(obs: Observation) -> tuple[str, int, str] | None:
    if obs.kind == ObservationKind.VULN_CANDIDATE:
        for candidate in (obs.attributes.get("endpoint", ""), obs.subject):
            parsed = parse_endpoint(candidate)
            if parsed:
                return parsed
        return None
    return parse_endpoint(obs.subject)


# --------------------------------------------------------------------------- facts


@dataclass
class ServiceFact:
    address: str
    port: int
    proto: str
    service_name: str = ""
    observation_ids: set[str] = field(default_factory=set)

    @property
    def endpoint(self) -> str:
        return _format_endpoint(self.address, self.port, self.proto)

    @property
    def node_id(self) -> str:
        return f"access:{self.endpoint}"


@dataclass
class AttackGraph:
    """The built graph plus everything needed to explain it."""

    engagement_id: str
    topology: NetworkTopology
    ruleset: RuleSet
    graph: nx.MultiDiGraph
    nodes: dict[str, GraphNode]
    edges: dict[str, PathEdge]
    findings: dict[str, Finding]
    unclassified: tuple[UnclassifiedFinding, ...]
    unzoned_addresses: tuple[str, ...]
    attacker_nodes: tuple[str, ...]
    goal_nodes: frozenset[str]

    def out_edges(self, node_id: str) -> list[PathEdge]:
        """Outgoing edges in a fixed order: target node, then edge id."""
        found = [self.edges[key] for _, _, key in self.graph.out_edges(node_id, keys=True)]
        return sorted(found, key=lambda e: (e.to_node, e.edge_id))


def _finding_ref(finding_id: str) -> str:
    return finding_id if finding_id.startswith("finding:") else f"finding:{finding_id}"


class _Builder:
    def __init__(
        self,
        engagement_id: str,
        observations: list[Observation],
        findings: list[Finding],
        enriched: dict[str, EnrichedFinding],
        topology: NetworkTopology,
        ruleset: RuleSet,
        exclude_finding_ids: frozenset[str],
    ) -> None:
        self.engagement_id = engagement_id
        self.topology = topology
        self.ruleset = ruleset
        self.enriched = enriched
        self.exclude = exclude_finding_ids
        self.obs_by_id = {o.observation_id: o for o in observations}
        self.findings = {f.finding_id: f for f in findings}

        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, PathEdge] = {}
        self.graph = nx.MultiDiGraph()
        self.unclassified: list[UnclassifiedFinding] = []

        self.machine_of_address: dict[str, str] = {}
        self.addresses_of_machine: dict[str, set[str]] = {}
        for host in topology.multi_homed_hosts:
            for address in host.addresses:
                self.machine_of_address[address] = host.name
            self.addresses_of_machine[host.name] = set(host.addresses)

        self.services: dict[tuple[str, int, str], ServiceFact] = {}
        self.host_obs: dict[str, set[str]] = {}
        self._collect_facts(observations)

    # ----------------------------------------------------------------- identity

    def machine(self, address: str) -> str:
        name = self.machine_of_address.get(address)
        if name is None:
            name = f"host:{address}"
            self.machine_of_address[address] = name
            self.addresses_of_machine.setdefault(name, set()).add(address)
        return name

    def machine_zones(self, machine: str) -> tuple[str, ...]:
        zones: set[str] = set()
        for address in self.addresses_of_machine.get(machine, set()):
            zones.update(self.topology.zones_of(address))
        return tuple(z.name for z in self.topology.zones if z.name in zones)

    def machine_label(self, machine: str) -> str:
        if machine.startswith("host:"):
            return machine.removeprefix("host:")
        addresses = ", ".join(sorted(self.addresses_of_machine.get(machine, set())))
        return f"{machine} ({addresses})"

    # ----------------------------------------------------------------- facts

    def _collect_facts(self, observations: list[Observation]) -> None:
        for obs in observations:
            if obs.kind == ObservationKind.HOST_UP:
                address = _canonical_ip(obs.subject)
                if address:
                    self.machine(address)
                    self.host_obs.setdefault(address, set()).add(obs.observation_id)
                continue
            if obs.kind not in _SERVICE_KINDS:
                continue
            parsed = _observation_endpoint(obs)
            if parsed is None:
                continue
            fact = self.services.setdefault(parsed, ServiceFact(*parsed))
            fact.observation_ids.add(obs.observation_id)
            self.machine(parsed[0])
            if obs.kind == ObservationKind.SERVICE_VERSION:
                name = obs.attributes.get("service_name", "")
                if name:
                    fact.service_name = name.lower()
            elif obs.kind == ObservationKind.PORT_OPEN and not fact.service_name:
                fact.service_name = obs.attributes.get("service_name_guess", "").lower()

    # ----------------------------------------------------------------- graph ops

    def add_node(self, node: GraphNode) -> str:
        self.nodes.setdefault(node.node_id, node)
        self.graph.add_node(node.node_id)
        return node.node_id

    def add_edge(self, edge: PathEdge) -> None:
        if edge.edge_id in self.edges:
            return
        self.edges[edge.edge_id] = edge
        self.graph.add_edge(edge.from_node, edge.to_node, key=edge.edge_id)

    def state_node(self, kind: NodeKind, machine: str) -> str:
        prefix = {
            NodeKind.CODE_EXECUTION: "exec",
            NodeKind.FILE_READ: "read",
            NodeKind.CREDENTIALS: "creds",
        }[kind]
        verb = {
            NodeKind.CODE_EXECUTION: "Code execution on",
            NodeKind.FILE_READ: "Arbitrary file read on",
            NodeKind.CREDENTIALS: "Credential material from",
        }[kind]
        return self.add_node(
            GraphNode(
                node_id=f"{prefix}:{machine}",
                kind=kind,
                label=f"{verb} {self.machine_label(machine)}",
                machine=machine,
                zones=self.machine_zones(machine),
                goal=kind == NodeKind.CODE_EXECUTION,
            )
        )

    def access_node(self, svc: ServiceFact) -> str:
        machine = self.machine(svc.address)
        return self.add_node(
            GraphNode(
                node_id=svc.node_id,
                kind=NodeKind.NETWORK_ACCESS,
                label=(
                    f"Network access to {svc.endpoint} "
                    f"({svc.service_name or 'unidentified service'})"
                ),
                machine=machine,
                zones=self.machine_zones(machine),
                # Judged by the service's own address: a multi-homed bastion's internal
                # SSH port is not in the crown-jewel zone just because the box also is.
                goal=any(
                    self.topology.zone(z).crown_jewel for z in self.topology.zones_of(svc.address)
                ),
            )
        )

    # ----------------------------------------------------------------- reachability

    def reach_rule(self, source_machine: str, svc: ServiceFact) -> tuple[str, str] | None:
        """Which rule (if any) lets `source_machine` reach `svc`, and why."""
        target_machine = self.machine(svc.address)
        if target_machine == source_machine:
            return None
        source_zones = set(self.machine_zones(source_machine))
        target_zones = set(self.topology.zones_of(svc.address))
        shared = sorted(source_zones & target_zones)
        if shared and self.topology.intra_zone_reachable:
            return INTRA_ZONE, f"shares zone {shared[0]}"
        for flow in self.topology.flows:
            if (
                flow.from_zone in source_zones
                and flow.to_zone in target_zones
                and (not flow.ports or svc.port in flow.ports)
            ):
                return DECLARED_FLOW, f"declared flow {flow.from_zone} -> {flow.to_zone}"
        return None

    # ----------------------------------------------------------------- rules

    def match_entry(self) -> list[str]:
        attackers: list[str] = []
        for zone in self.topology.zones:
            if not zone.attacker_entry:
                continue
            attacker = self.add_node(
                GraphNode(
                    node_id=f"attacker:{zone.name}",
                    kind=NodeKind.ATTACKER,
                    label=f"Attacker foothold in zone {zone.name}",
                    zones=(zone.name,),
                )
            )
            attackers.append(attacker)
            rule = self.ruleset.rule(ENTRY)
            for key in sorted(self.services):
                svc = self.services[key]
                if not zone.contains(svc.address):
                    continue
                self.add_edge(
                    PathEdge(
                        from_node=attacker,
                        to_node=self.access_node(svc),
                        rule_name=ENTRY,
                        evidence=(self.topology.topology_id, *sorted(svc.observation_ids)),
                        description=(
                            f"{svc.endpoint} was observed open and is in attacker-entry "
                            f"zone {zone.name}"
                        ),
                        confidence=rule.confidence,
                    )
                )
        return attackers

    def match_exploits(self) -> list[str]:
        """EXPLOIT_EXEC / EXPLOIT_READ for every classified finding on an observed service."""
        created: list[str] = []
        for finding_id in sorted(self.findings):
            finding = self.findings[finding_id]
            if finding_id in self.exclude:
                continue
            missing = [i for i in finding.observation_ids if i not in self.obs_by_id]
            evidence_obs = [
                self.obs_by_id[i] for i in finding.observation_ids if i in self.obs_by_id
            ]
            if not evidence_obs:
                self._unclassified(finding, "none of its observations were supplied to the build")
                continue
            endpoints = sorted({p for o in evidence_obs if (p := _observation_endpoint(o))})
            if not endpoints:
                self._unclassified(finding, "its evidence names no IP service endpoint")
                continue
            matches, tags, cwes = classify(
                evidence_obs, self.enriched.get(finding_id), self.ruleset
            )
            if not matches:
                seen = ", ".join([*cwes, *(f"tag:{t}" for t in tags)]) or "no tags or CWE ids"
                self._unclassified(
                    finding,
                    f"no capability rule matches its evidence ({seen})",
                )
                continue
            note = f" ({len(missing)} cited observations not supplied)" if missing else ""
            for endpoint in endpoints:
                svc = self.services.setdefault(endpoint, ServiceFact(*endpoint))
                access = self.access_node(svc)
                machine = self.machine(svc.address)
                for match in matches:
                    created.append(self._exploit_edge(finding, svc, access, machine, match, note))
        return created

    def _exploit_edge(
        self,
        finding: Finding,
        svc: ServiceFact,
        access: str,
        machine: str,
        match: CapabilityMatch,
        note: str,
    ) -> str:
        if match.capability == CODE_EXECUTION:
            rule_name, kind = EXPLOIT_EXEC, NodeKind.CODE_EXECUTION
        elif match.capability == FILE_READ:
            rule_name, kind = EXPLOIT_READ, NodeKind.FILE_READ
        else:  # pragma: no cover - capabilities are a closed set
            raise ValueError(match.capability)
        rule = self.ruleset.rule(rule_name)
        target = self.state_node(kind, machine)
        what = ", ".join(finding.cve_ids) or finding.title or finding.finding_id
        self.add_edge(
            PathEdge(
                from_node=access,
                to_node=target,
                rule_name=rule_name,
                evidence=(_finding_ref(finding.finding_id), *sorted(finding.observation_ids)),
                description=(
                    f"{what} on {svc.endpoint} ({finding.scanner}) classified "
                    f"{match.capability} by {'; '.join(match.signals)}{note}"
                ),
                confidence=weakest([rule.confidence, match.confidence]),
                finding_ids=(finding.finding_id,),
            )
        )
        return target

    def _unclassified(self, finding: Finding, reason: str) -> None:
        self.unclassified.append(
            UnclassifiedFinding(
                finding_id=finding.finding_id,
                asset_id=finding.asset_id,
                cve_ids=tuple(finding.cve_ids),
                reason=reason,
            )
        )

    def machine_evidence(self, machine: str) -> tuple[str, ...]:
        ids: set[str] = set()
        for address in self.addresses_of_machine.get(machine, set()):
            ids.update(self.host_obs.get(address, set()))
        if not ids:
            for svc in self.services.values():
                if self.machine(svc.address) == machine:
                    ids.update(svc.observation_ids)
        if not machine.startswith("host:"):
            ids.add(self.topology.topology_id)
        return tuple(sorted(ids)) or (self.topology.topology_id,)

    def expand_exec(self, node: GraphNode) -> list[str]:
        """INTRA_ZONE / DECLARED_FLOW from code execution, then LOCAL_CREDS."""
        assert node.machine is not None
        for key in sorted(self.services):
            svc = self.services[key]
            reach = self.reach_rule(node.machine, svc)
            if reach is None:
                continue
            rule_name, why = reach
            self.add_edge(
                PathEdge(
                    from_node=node.node_id,
                    to_node=self.access_node(svc),
                    rule_name=rule_name,
                    evidence=(self.topology.topology_id, *sorted(svc.observation_ids)),
                    description=(
                        f"{self.machine_label(node.machine)} {why}; "
                        f"{svc.endpoint} was observed open"
                    ),
                    confidence=self.ruleset.rule(rule_name).confidence,
                )
            )
        return [self._creds_edge(node)]

    def _creds_edge(self, node: GraphNode) -> str:
        assert node.machine is not None
        rule = self.ruleset.rule(LOCAL_CREDS)
        target = self.state_node(NodeKind.CREDENTIALS, node.machine)
        self.add_edge(
            PathEdge(
                from_node=node.node_id,
                to_node=target,
                rule_name=LOCAL_CREDS,
                evidence=self.machine_evidence(node.machine),
                description=f"Assumed, not observed: {rule.assumption}",
                confidence=rule.confidence,
            )
        )
        return target

    def expand_creds(self, node: GraphNode) -> list[str]:
        """CRED_REUSE: credentials -> code execution via a reachable remote-login service."""
        assert node.machine is not None
        rule = self.ruleset.rule(CRED_REUSE)
        created: list[str] = []
        for key in sorted(self.services):
            svc = self.services[key]
            if svc.service_name not in self.ruleset.remote_login_services:
                continue
            reach = self.reach_rule(node.machine, svc)
            if reach is None:
                continue
            target_machine = self.machine(svc.address)
            target = self.state_node(NodeKind.CODE_EXECUTION, target_machine)
            self.add_edge(
                PathEdge(
                    from_node=node.node_id,
                    to_node=target,
                    rule_name=CRED_REUSE,
                    evidence=(self.topology.topology_id, *sorted(svc.observation_ids)),
                    description=(
                        f"{svc.service_name} on {svc.endpoint} reachable from "
                        f"{self.machine_label(node.machine)} ({reach[1]}). "
                        f"Assumed, not observed: {rule.assumption}"
                    ),
                    confidence=rule.confidence,
                )
            )
            created.append(target)
        return created

    # ----------------------------------------------------------------- build

    def build(self) -> AttackGraph:
        attackers = self.match_entry()
        pending = sorted(set(self.match_exploits()))
        done: set[str] = set()
        while pending:
            node_id = pending.pop(0)
            if node_id in done:
                continue
            done.add(node_id)
            node = self.nodes[node_id]
            if node.kind == NodeKind.CODE_EXECUTION:
                new = self.expand_exec(node)
            elif node.kind == NodeKind.FILE_READ:
                new = [self._creds_edge(node)]
            elif node.kind == NodeKind.CREDENTIALS:
                new = self.expand_creds(node)
            else:  # pragma: no cover
                new = []
            pending = sorted(set(pending) | (set(new) - done))

        # Keep only what an attacker can actually reach from an entry zone.
        reachable: set[str] = set(attackers)
        for attacker in attackers:
            reachable |= nx.descendants(self.graph, attacker)
        graph = self.graph.subgraph(sorted(reachable)).copy()
        nodes = {n: self.nodes[n] for n in sorted(reachable)}
        edges = {
            k: self.edges[k] for k in sorted(self.edges) if self.edges[k].from_node in reachable
        }

        unzoned = sorted(a for a in self.machine_of_address if not self.topology.zones_of(a))
        return AttackGraph(
            engagement_id=self.engagement_id,
            topology=self.topology,
            ruleset=self.ruleset,
            graph=graph,
            nodes=nodes,
            edges=edges,
            findings=self.findings,
            unclassified=tuple(sorted(self.unclassified, key=lambda u: u.finding_id)),
            unzoned_addresses=tuple(unzoned),
            attacker_nodes=tuple(sorted(attackers)),
            goal_nodes=frozenset(n for n, node in nodes.items() if node.goal),
        )


def build_attack_graph(
    *,
    engagement_id: str,
    observations: Iterable[Observation],
    findings: Iterable[Finding],
    topology: NetworkTopology,
    ruleset: RuleSet,
    enriched: Iterable[EnrichedFinding] = (),
    exclude_finding_ids: Iterable[str] = (),
) -> AttackGraph:
    """Build the attack graph for one engagement. Pure and deterministic: input order
    does not matter, and the same inputs always give the same nodes, edges and ids."""
    obs = sorted(observations, key=lambda o: o.observation_id)
    fnd = sorted(findings, key=lambda f: f.finding_id)
    for engagement in sorted({o.engagement_id for o in obs} | {f.engagement_id for f in fnd}):
        if engagement != engagement_id:
            raise ValueError(
                f"facts from engagement {engagement!r} passed to a build for {engagement_id!r}"
            )
    if topology.engagement_id != engagement_id:
        raise ValueError("topology belongs to a different engagement")
    enriched_map = {e.finding.finding_id: e for e in enriched}
    return _Builder(
        engagement_id,
        obs,
        fnd,
        enriched_map,
        topology,
        ruleset,
        frozenset(exclude_finding_ids),
    ).build()
