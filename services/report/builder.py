"""Deterministic engagement-report builder (DECISIONS.md D-051).

`build_report` is a pure function: it reads no clock (the caller passes `generated_at`),
no database, no network and no model. It copies stored facts, stored enrichment and the
graph engine's output into an `EngagementReport`, keeping every attribution, and puts
everything in a fixed order, so the same inputs always render to identical bytes.

It never creates, edits or filters an attack-graph edge (CLAUDE.md, Hard Rule 1). Paths,
chokepoints and the remediation simulation arrive already computed by `services.graph`.
Assistant narrations are optional, attached only to the path they narrate, and labelled
model-generated.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime

from packages.schema.models.assistant import PathNarration
from packages.schema.models.engagement import Engagement
from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.graph import AttackGraphResult, AttackPath, SimulationResult
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.topology import NetworkTopology
from services.graph.builder import parse_endpoint
from services.report.models import (
    NARRATION_LABEL,
    NOT_SCORED,
    AssetEntry,
    AttackGraphSection,
    Attribution,
    AuthorizationSection,
    ChokepointEntry,
    EngagementReport,
    EngagementSection,
    EnrichedFieldEntry,
    EvidenceEntry,
    FindingEntry,
    NarrationEntry,
    PathEntry,
    PathStepEntry,
    ScanEntry,
    ScanRecord,
    ScoreComponentEntry,
    ScoreEntry,
    ServiceEntry,
    SimulationSection,
    UnclassifiedEntry,
    require_aware,
)

_SERVICE_KINDS = {ObservationKind.PORT_OPEN, ObservationKind.SERVICE_VERSION}

STANDING_LIMITATIONS = (
    "No accuracy, recall or false-positive metric for this platform has been measured "
    "yet; nothing in this report is a measured detection rate.",
    "Attack paths are only as complete as the declared topology and the scans run: a "
    "path that needs an unscanned host or an undeclared flow is not shown.",
    "Attack paths are ranked ordinally (D-047); there is no numeric path score.",
)


class ReportInputError(ValueError):
    """The inputs contradict each other (wrong engagement, unknown path, ...)."""


# --------------------------------------------------------------------------- helpers


def _finding_ref(finding_id: str) -> str:
    return finding_id if finding_id.startswith("finding:") else f"finding:{finding_id}"


def _canonical_ip(text: str) -> str | None:
    try:
        return ipaddress.ip_address(text.strip().strip("[]")).compressed
    except ValueError:
        return None


def _address_key(address: str) -> tuple[int, int, str]:
    """Sort IPv4 before IPv6, numerically, then anything unparseable by text."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (2, 0, address)
    return (0 if ip.version == 4 else 1, int(ip), address)


def _attributions(observations: Iterable[Observation]) -> tuple[Attribution, ...]:
    unique = {(o.scanner, o.provenance.source, o.provenance.confidence): None for o in observations}
    return tuple(
        Attribution(scanner=s, source=src, confidence=c)
        for s, src, c in sorted(unique, key=lambda t: (t[0], t[1].value, t[2].value))
    )


def _distinct(values: Iterable[str | None]) -> tuple[str, ...]:
    return tuple(sorted({v.strip() for v in values if v and v.strip()}))


def _path_order(paths: Sequence[AttackPath]) -> list[AttackPath]:
    """Rank order; unranked paths keep the engine's order after the ranked ones."""
    indexed = list(enumerate(paths))
    indexed.sort(key=lambda t: (t[1].rank is None, t[1].rank or 0, t[0]))
    return [p for _, p in indexed]


# --------------------------------------------------------------------------- sections


def _engagement_section(engagement: Engagement) -> EngagementSection:
    auth = engagement.authorization
    return EngagementSection(
        engagement_id=engagement.engagement_id,
        name=engagement.name,
        created_at=engagement.created_at,
        authorization=AuthorizationSection(
            authorized_by=auth.authorized_by,
            allowlist=tuple(auth.allowlist),
            granted_at=auth.granted_at,
            expires_at=auth.expires_at,
            authorization_reference=engagement.engagement_id,
        ),
    )


def _scan_entries(
    scans: Sequence[ScanRecord], observations: Sequence[Observation]
) -> tuple[ScanEntry, ...]:
    per_artifact: dict[str, int] = defaultdict(int)
    for obs in observations:
        per_artifact[obs.artifact_id] += 1
    ordered = sorted(scans, key=lambda s: (s.created_at, s.scan_id))
    return tuple(
        ScanEntry(
            scan_id=s.scan_id,
            scanner=s.scanner,
            target=s.target,
            status=s.status,
            artifact_id=s.artifact_id,
            observation_count=per_artifact.get(s.artifact_id, 0) if s.artifact_id else 0,
            created_at=s.created_at,
            completed_at=s.completed_at,
            error_message=s.error_message,
        )
        for s in ordered
    )


def _asset_entries(observations: Sequence[Observation]) -> tuple[AssetEntry, ...]:
    hosts: dict[str, list[Observation]] = defaultdict(list)
    services: dict[str, dict[tuple[int, str], list[Observation]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for obs in observations:
        if obs.kind == ObservationKind.HOST_UP:
            address = _canonical_ip(obs.subject)
            if address is not None:
                hosts[address].append(obs)
        elif obs.kind in _SERVICE_KINDS:
            parsed = parse_endpoint(obs.subject)
            if parsed is not None:
                address, port, proto = parsed
                services[address][(port, proto)].append(obs)

    entries: list[AssetEntry] = []
    for address in sorted(set(hosts) | set(services), key=_address_key):
        host_obs = hosts.get(address, [])
        service_entries: list[ServiceEntry] = []
        all_service_obs: list[Observation] = []
        for (port, proto), svc_obs in sorted(services.get(address, {}).items()):
            all_service_obs.extend(svc_obs)
            host = f"[{address}]" if ":" in address else address
            service_entries.append(
                ServiceEntry(
                    endpoint=f"{host}:{port}/{proto}",
                    port=port,
                    protocol=proto,
                    names=_distinct(
                        o.attributes.get("service_name") or o.attributes.get("service_name_guess")
                        for o in svc_obs
                    ),
                    products=_distinct(o.attributes.get("product") for o in svc_obs),
                    versions=_distinct(o.attributes.get("version") for o in svc_obs),
                    cpes=_distinct(o.attributes.get("cpe") for o in svc_obs),
                    attributions=_attributions(svc_obs),
                    observation_ids=tuple(sorted({o.observation_id for o in svc_obs})),
                )
            )
        entries.append(
            AssetEntry(
                address=address,
                hostnames=_distinct(o.attributes.get("hostname") for o in host_obs),
                attributions=_attributions([*host_obs, *all_service_obs]),
                services=tuple(service_entries),
                observation_ids=tuple(sorted({o.observation_id for o in host_obs})),
            )
        )
    return tuple(entries)


def _finding_entries(
    enriched: Sequence[EnrichedFinding],
    graph: AttackGraphResult | None,
) -> tuple[FindingEntry, ...]:
    on_paths: dict[str, list[str]] = defaultdict(list)
    chokepoint_rank: dict[str, int] = {}
    if graph is not None:
        for path in _path_order(graph.paths):
            used = {fid for edge in path.edges for fid in edge.finding_ids}
            for fid in sorted(used):
                on_paths[fid].append(path.path_id)
        for cp in graph.chokepoints:
            chokepoint_rank.setdefault(cp.finding_id, cp.rank)

    entries: list[FindingEntry] = []
    for ef in enriched:
        f = ef.finding
        score: ScoreEntry | None = None
        if ef.ers is not None:
            score = ScoreEntry(
                value=ef.ers.value,
                components=tuple(
                    ScoreComponentEntry(
                        name=c.name,
                        value=c.value,
                        weight=c.weight,
                        contribution=c.value * c.weight,
                        explanation=c.explanation,
                        source=c.provenance.source,
                        confidence=c.provenance.confidence,
                    )
                    for c in ef.ers.components
                ),
                explanation=ef.ers.explain(),
            )
        entries.append(
            FindingEntry(
                finding_id=f.finding_id,
                asset_id=f.asset_id,
                scanner=f.scanner,
                cve_ids=tuple(f.cve_ids),
                title=f.title,
                description=f.description,
                detected_at=f.detected_at,
                observation_ids=tuple(sorted(set(f.observation_ids))),
                fields=tuple(
                    EnrichedFieldEntry(
                        name=name,
                        value=attr.value,
                        source=attr.provenance.source,
                        confidence=attr.provenance.confidence,
                        retrieved_at=attr.provenance.retrieved_at,
                        note=attr.provenance.note,
                    )
                    for name, attr in sorted(ef.fields.items())
                ),
                ers_status="scored" if score is not None else NOT_SCORED,
                ers=score,
                on_path_ids=tuple(on_paths.get(f.finding_id, ())),
                chokepoint_rank=chokepoint_rank.get(f.finding_id),
            )
        )
    # Highest stored ERS first; unscored findings after every scored one. Ties and the
    # unscored block are ordered by finding id.
    entries.sort(key=lambda e: (e.ers is None, -(e.ers.value if e.ers else 0.0), e.finding_id))
    return tuple(entries)


def _narration_entry(narration: PathNarration) -> NarrationEntry:
    return NarrationEntry(
        label=NARRATION_LABEL,
        model=narration.model,
        text=narration.text,
        citations=tuple(c.ref_id for c in narration.citations),
        grounded=narration.grounding.grounded,
        unsupported_entities=tuple(narration.grounding.unsupported_entities),
        invalid_citations=tuple(narration.grounding.invalid_citations),
    )


def _graph_section(
    graph: AttackGraphResult, narrations: dict[str, PathNarration]
) -> AttackGraphSection:
    labels = {n.node_id: n.label for n in graph.nodes}

    def label(node_id: str) -> str:
        return labels.get(node_id, node_id)

    paths = tuple(
        PathEntry(
            path_id=p.path_id,
            rank=p.rank,
            rank_explanation=p.rank_explanation,
            confidence=p.confidence,
            entry_node=p.entry_node,
            entry_label=label(p.entry_node),
            goal_node=p.goal_node,
            goal_label=label(p.goal_node),
            steps=tuple(
                PathStepEntry(
                    index=i,
                    edge_id=e.edge_id,
                    from_node=e.from_node,
                    from_label=label(e.from_node),
                    to_node=e.to_node,
                    to_label=label(e.to_node),
                    rule_name=e.rule_name,
                    description=e.description,
                    confidence=e.confidence,
                    evidence=tuple(e.evidence),
                    finding_ids=tuple(e.finding_ids),
                )
                for i, e in enumerate(p.edges, start=1)
            ),
            narration=(
                _narration_entry(narrations[p.path_id]) if p.path_id in narrations else None
            ),
        )
        for p in _path_order(graph.paths)
    )
    chokepoints = tuple(
        ChokepointEntry(
            rank=cp.rank,
            finding_id=cp.finding_id,
            asset_id=cp.asset_id,
            cve_ids=tuple(cp.cve_ids),
            remediation=cp.remediation,
            paths_broken=tuple(cp.paths_broken),
            goals_cut=tuple(cp.goals_cut),
            goal_labels=tuple(label(g) for g in cp.goals_cut),
        )
        for cp in sorted(graph.chokepoints, key=lambda c: (c.rank, c.finding_id))
    )
    return AttackGraphSection(
        topology_id=graph.topology_id,
        rules_digest=graph.rules_digest,
        ordering=graph.ordering,
        max_depth=graph.max_depth,
        max_paths=graph.max_paths,
        truncated=graph.truncated,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        paths=paths,
        chokepoints=chokepoints,
        unclassified_findings=tuple(
            UnclassifiedEntry(
                finding_id=u.finding_id,
                asset_id=u.asset_id,
                cve_ids=tuple(u.cve_ids),
                reason=u.reason,
            )
            for u in graph.unclassified_findings
        ),
        unzoned_addresses=tuple(graph.unzoned_addresses),
    )


def _simulation_section(
    simulation: SimulationResult, graph: AttackGraphResult
) -> SimulationSection:
    top = min(graph.chokepoints, key=lambda c: (c.rank, c.finding_id))
    if tuple(simulation.fixed_finding_ids) != (top.finding_id,):
        raise ReportInputError(
            f"the simulation fixed {list(simulation.fixed_finding_ids)}, but the report "
            f"simulates the top chokepoint only ({top.finding_id!r})"
        )
    labels = {n.node_id: n.label for n in graph.nodes}
    return SimulationSection(
        chokepoint_rank=top.rank,
        fixed_finding_ids=tuple(simulation.fixed_finding_ids),
        baseline_path_count=simulation.baseline_path_count,
        remaining_path_count=simulation.remaining_path_count,
        removed_path_ids=tuple(simulation.removed_path_ids),
        goals_no_longer_reachable=tuple(simulation.goals_no_longer_reachable),
        goal_labels=tuple(labels.get(g, g) for g in simulation.goals_no_longer_reachable),
        after_truncated=simulation.after.truncated,
    )


def _evidence_entries(
    *,
    observations: Sequence[Observation],
    enriched: Sequence[EnrichedFinding],
    topology: NetworkTopology | None,
    assets: Sequence[AssetEntry],
    findings: Sequence[FindingEntry],
    graph: AttackGraphSection | None,
) -> tuple[EvidenceEntry, ...]:
    cited: dict[str, set[str]] = defaultdict(set)
    for asset in assets:
        for oid in asset.observation_ids:
            cited[oid].add(f"asset:{asset.address}")
        for svc in asset.services:
            for oid in svc.observation_ids:
                cited[oid].add(f"asset:{asset.address}")
    for finding in findings:
        for oid in finding.observation_ids:
            cited[oid].add(_finding_ref(finding.finding_id))
    if graph is not None:
        cited[graph.topology_id].add("attack_graph")
        for path in graph.paths:
            for step in path.steps:
                for ref in step.evidence:
                    cited[ref].add(f"path:{path.path_id}")

    obs_by_id = {o.observation_id: o for o in observations}
    finding_by_ref = {_finding_ref(e.finding.finding_id): e.finding for e in enriched}
    entries: list[EvidenceEntry] = []
    for evidence_id in sorted(cited):
        cited_by = tuple(sorted(cited[evidence_id]))
        obs = obs_by_id.get(evidence_id)
        stored = finding_by_ref.get(evidence_id)
        if obs is not None:
            summary = (
                f"{obs.scanner} {obs.kind.value} {obs.subject} at "
                f"{obs.observed_at.isoformat()} ({obs.provenance.source.value}, "
                f"{obs.provenance.confidence.value}; artifact {obs.artifact_id})"
            )
            entries.append(
                EvidenceEntry(
                    evidence_id=evidence_id, kind="observation", summary=summary, cited_by=cited_by
                )
            )
        elif stored is not None:
            what = ", ".join(stored.cve_ids) or stored.title or "no CVE"
            summary = f"{stored.scanner} finding on {stored.asset_id}: {what}"
            entries.append(
                EvidenceEntry(
                    evidence_id=evidence_id, kind="finding", summary=summary, cited_by=cited_by
                )
            )
        elif topology is not None and evidence_id == topology.topology_id:
            summary = f"Network topology declared by {topology.declared_by}: zones " + ", ".join(
                z.name for z in topology.zones
            )
            entries.append(
                EvidenceEntry(
                    evidence_id=evidence_id, kind="topology", summary=summary, cited_by=cited_by
                )
            )
        else:
            entries.append(
                EvidenceEntry(
                    evidence_id=evidence_id,
                    kind="unresolved",
                    summary="Not among the facts this report was built from.",
                    cited_by=cited_by,
                )
            )
    return tuple(entries)


def _limitations(
    findings: Sequence[FindingEntry],
    graph: AttackGraphSection | None,
    attack_graph_unavailable: str | None,
    skipped_findings: int,
    narrated: int,
) -> tuple[str, ...]:
    notes: list[str] = []
    unscored = sum(1 for f in findings if f.ers is None)
    if unscored:
        notes.append(
            f"Findings not scored: {unscored} of {len(findings)}. No Exposure Risk Score "
            "is stored for them; they are listed as not scored, never as zero."
        )
    if skipped_findings:
        notes.append(
            "Stored finding rows left out because they could not be read (malformed "
            f"data): {skipped_findings}."
        )
    if attack_graph_unavailable:
        notes.append(f"Attack graph not built: {attack_graph_unavailable}")
    if graph is not None:
        if graph.truncated:
            notes.append(
                f"Path enumeration stopped at max_paths={graph.max_paths}: the path list and "
                "chokepoint counts are a deterministic prefix, not the full set."
            )
        if graph.unclassified_findings:
            notes.append(
                "Findings no rule could turn into an attacker capability, so they appear on "
                f"no path: {len(graph.unclassified_findings)} (listed in section 5)."
            )
        if graph.unzoned_addresses:
            notes.append(
                "Observed addresses outside every declared zone, so no rule can place them: "
                + ", ".join(graph.unzoned_addresses)
            )
    if narrated:
        notes.append(
            f"Paths carrying a model-generated narration: {narrated}. Narrations are "
            "labelled, were grounding-checked when produced, and are not evidence."
        )
    return (*notes, *STANDING_LIMITATIONS)


# --------------------------------------------------------------------------- entry point


def build_report(
    *,
    engagement: Engagement,
    scans: Sequence[ScanRecord],
    observations: Sequence[Observation],
    enriched: Sequence[EnrichedFinding],
    topology: NetworkTopology | None,
    graph: AttackGraphResult | None,
    simulation: SimulationResult | None,
    generated_at: datetime,
    narrations: Sequence[PathNarration] = (),
    attack_graph_unavailable: str | None = None,
    skipped_findings: int = 0,
) -> EngagementReport:
    """Assemble the engagement report from stored facts and engine output.

    `graph` is `services.graph.analyze`'s result over the same facts, or None with
    `attack_graph_unavailable` saying why. `simulation` is `simulate_remediation` for the
    top-ranked chokepoint alone, or None when there is no chokepoint. Raises
    `ReportInputError` when the inputs describe different engagements or a narration
    names a path the graph does not contain.
    """
    generated_at = require_aware(generated_at)
    eid = engagement.engagement_id

    foreign = sorted(
        {o.observation_id for o in observations if o.engagement_id != eid}
        | {e.finding.finding_id for e in enriched if e.finding.engagement_id != eid}
    )
    if foreign:
        raise ReportInputError(f"records {foreign} do not belong to engagement {eid!r}")
    if graph is not None and graph.engagement_id != eid:
        raise ReportInputError(f"the attack graph is for engagement {graph.engagement_id!r}")
    if topology is not None and topology.engagement_id != eid:
        raise ReportInputError(f"the topology is for engagement {topology.engagement_id!r}")
    if graph is None and attack_graph_unavailable is None:
        raise ReportInputError("no attack graph given and no reason why")
    if simulation is not None and (graph is None or not graph.chokepoints):
        raise ReportInputError("a simulation needs an attack graph with a chokepoint")

    path_ids = {p.path_id for p in graph.paths} if graph is not None else set()
    by_path: dict[str, PathNarration] = {}
    for n in narrations:
        if n.engagement_id != eid:
            raise ReportInputError(f"narration of {n.path_id!r} is for another engagement")
        if n.path_id not in path_ids:
            raise ReportInputError(f"narration names path {n.path_id!r}, not in this graph")
        if n.path_id in by_path:
            raise ReportInputError(f"two narrations given for path {n.path_id!r}")
        by_path[n.path_id] = n

    assets = _asset_entries(observations)
    findings = _finding_entries(enriched, graph)
    graph_section = _graph_section(graph, by_path) if graph is not None else None

    simulation_section: SimulationSection | None = None
    simulation_unavailable: str | None = None
    if graph is None:
        simulation_unavailable = "no attack graph was built"
    elif not graph.chokepoints:
        simulation_unavailable = "the attack graph has no chokepoint to remediate"
    elif simulation is None:
        simulation_unavailable = "no simulation result was supplied"
    else:
        simulation_section = _simulation_section(simulation, graph)

    return EngagementReport(
        generated_at=generated_at,
        engagement=_engagement_section(engagement),
        scans=_scan_entries(scans, observations),
        assets=assets,
        findings=findings,
        attack_graph=graph_section,
        attack_graph_unavailable=None if graph is not None else attack_graph_unavailable,
        simulation=simulation_section,
        simulation_unavailable=simulation_unavailable,
        limitations=_limitations(
            findings,
            graph_section,
            None if graph is not None else attack_graph_unavailable,
            skipped_findings,
            len(by_path),
        ),
        evidence=_evidence_entries(
            observations=observations,
            enriched=enriched,
            topology=topology,
            assets=assets,
            findings=findings,
            graph=graph_section,
        ),
    )
