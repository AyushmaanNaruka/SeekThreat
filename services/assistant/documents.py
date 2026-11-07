"""Pure builders: schema records -> AssistantDocument.

One fact per document, one citable id per document (DECISIONS.md D-048), so a citation
always resolves to exactly one record. Text is built only from the record itself: no
clock, no randomness, no model, so the same record always gives the same bytes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from packages.schema.models.assistant import AssistantDocument
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue
from packages.schema.models.graph import AttackGraphResult, AttackPath, Chokepoint, GraphNode
from packages.schema.models.observation import Observation
from packages.schema.models.provenance import Attributed
from packages.schema.models.topology import NetworkTopology

ASSUMPTION_MARKER = "Assumed, not observed"

# Attributes shown first, in this order; the rest follow alphabetically.
_SALIENT_ATTRIBUTES = (
    "product",
    "version",
    "extrainfo",
    "cpe",
    "service_name",
    "service_name_guess",
    "port",
    "protocol",
    "endpoint",
    "cve_ids",
    "cwe_ids",
    "cvss_score",
    "template_id",
    "template_name",
    "scanner_severity",
    "matched_at",
    "url",
    "hostname",
    "hostnames",
    "ipv4",
    "description",
)
_MAX_ATTRIBUTE_CHARS = 500

# Human labels for fused enrichment fields; unknown fields keep their key.
_FIELD_LABELS = {
    "cvss_score": "CVSS",
    "cvss_vector": "CVSS vector",
    "cwe_ids": "CWE",
    "epss_score": "EPSS",
    "epss_percentile": "EPSS percentile",
    "in_kev": "In CISA KEV",
    "summary": "Summary",
}


def _clip(value: str, limit: int = _MAX_ATTRIBUTE_CHARS) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def _format_value(value: EnrichmentValue) -> str:
    if value is None:
        return "none reported"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return ", ".join(value) if value else "none"
    return str(value)


def _ordered_attributes(attributes: Mapping[str, str]) -> list[tuple[str, str]]:
    salient = [(k, attributes[k]) for k in _SALIENT_ATTRIBUTES if k in attributes]
    rest = sorted((k, v) for k, v in attributes.items() if k not in _SALIENT_ATTRIBUTES)
    return salient + rest


def observation_document(obs: Observation) -> AssistantDocument:
    kind = obs.kind.value
    lines = [
        f"Observation {obs.observation_id}: scanner {obs.scanner} reported {kind} "
        f"for {obs.subject}.",
        f"Observed at {obs.observed_at.isoformat()} "
        f"(source {obs.provenance.source.value}, {obs.provenance.confidence.value} confidence).",
    ]
    for key, value in _ordered_attributes(obs.attributes):
        if value.strip():
            lines.append(f"{key}: {_clip(value)}")
    return AssistantDocument(
        doc_id=obs.observation_id,
        kind="observation",
        engagement_id=obs.engagement_id,
        title=f"{obs.scanner} {kind} {obs.subject}",
        text="\n".join(lines),
        metadata={
            "scanner": obs.scanner,
            "observation_kind": kind,
            "subject": obs.subject,
            "observed_at": obs.observed_at.isoformat(),
        },
    )


def _field_line(name: str, field: Attributed[EnrichmentValue]) -> str:
    label = _FIELD_LABELS.get(name, name)
    value = _format_value(field.value)
    if name == "summary" and isinstance(field.value, str):
        value = _clip(field.value)
    prov = field.provenance
    note = f"; {_clip(prov.note, 200)}" if prov.note else ""
    return f"{label} {value} ({prov.source.value}, {prov.confidence.value} confidence{note})"


def enriched_finding_document(ef: EnrichedFinding) -> AssistantDocument:
    f = ef.finding
    cves = ", ".join(f.cve_ids) if f.cve_ids else "none"
    lines = [
        f"Finding {f.finding_id} on asset {f.asset_id}, reported by scanner {f.scanner}.",
        f"CVEs: {cves}.",
    ]
    if f.title:
        lines.append(f"Title: {_clip(f.title)}")
    if f.description:
        lines.append(f"Description: {_clip(f.description)}")
    lines.append(f"Detected at {f.detected_at.isoformat()}.")
    lines.append(f"Observations: {', '.join(f.observation_ids)}.")
    if ef.fields:
        lines.append("Enrichment (value, source, confidence):")
        lines.extend(f"- {_field_line(name, ef.fields[name])}" for name in sorted(ef.fields))
    else:
        lines.append("Enrichment: none recorded.")
    if ef.ers is not None:
        lines.append(ef.ers.explain())
    else:
        lines.append("Exposure Risk Score: not scored.")
    metadata = {"asset_id": f.asset_id, "scanner": f.scanner, "cve_ids": ",".join(f.cve_ids)}
    if ef.ers is not None:
        metadata["ers"] = f"{ef.ers.value:.2f}"
    return AssistantDocument(
        doc_id=f"finding:{f.finding_id}",
        kind="finding",
        engagement_id=f.engagement_id,
        title=_clip(f.title or f"{cves} on {f.asset_id}", 200),
        text="\n".join(lines),
        metadata=metadata,
    )


def is_assumption_step(description: str) -> bool:
    """Edges produced by assumption rules say so in their description (services/graph)."""
    return ASSUMPTION_MARKER.lower() in description.lower()


def path_document(
    path: AttackPath, nodes: Sequence[GraphNode], engagement_id: str
) -> AssistantDocument:
    labels = {node.node_id: node.label for node in nodes}

    def label(node_id: str) -> str:
        return labels.get(node_id, node_id)

    rank = str(path.rank) if path.rank is not None else "not ranked"
    lines = [
        f"Attack path {path.path_id}, proven by the deterministic rules engine.",
        f"Rank: {rank}. {path.rank_explanation or 'No rank explanation recorded.'}",
        f"Confidence: {path.confidence.value} (the weakest step).",
        f"Entry: {label(path.entry_node)}. Goal: {label(path.goal_node)}.",
        f"Steps: {len(path.edges)}.",
    ]
    for n, edge in enumerate(path.edges, start=1):
        marker = " ASSUMPTION." if is_assumption_step(edge.description) else ""
        lines.append(
            f"Step {n}: {label(edge.from_node)} -[{edge.rule_name}, {edge.confidence.value}]-> "
            f"{label(edge.to_node)}: {edge.description or 'no description'}{marker}"
        )
        lines.append(f"  Evidence: {', '.join(edge.evidence)}")
        if edge.finding_ids:
            lines.append(f"  Findings: {', '.join(edge.finding_ids)}")
    return AssistantDocument(
        doc_id=path.path_id,
        kind="path",
        engagement_id=engagement_id,
        title=f"Attack path rank {rank}: {label(path.entry_node)} to {label(path.goal_node)}",
        text="\n".join(lines),
        metadata={
            "rank": rank,
            "confidence": path.confidence.value,
            "entry_node": path.entry_node,
            "goal_node": path.goal_node,
            "rules": ",".join(edge.rule_name for edge in path.edges),
        },
    )


def chokepoint_document(cp: Chokepoint, engagement_id: str) -> AssistantDocument:
    cves = ", ".join(cp.cve_ids) if cp.cve_ids else "no CVE id"
    asset = cp.asset_id or "an unrecorded asset"
    goals = ", ".join(cp.goals_cut) if cp.goals_cut else "none"
    lines = [
        f"Chokepoint rank {cp.rank}: finding {cp.finding_id} ({cves}) on {asset}.",
        f"Fixing it breaks {len(cp.paths_broken)} of the enumerated attack paths.",
        f"Goals no longer reachable once fixed: {goals}.",
        f"Remediation: {cp.remediation}",
        f"Paths broken: {', '.join(cp.paths_broken) if cp.paths_broken else 'none'}.",
    ]
    return AssistantDocument(
        doc_id=f"chokepoint:{cp.finding_id}",
        kind="finding",
        engagement_id=engagement_id,
        title=f"Chokepoint rank {cp.rank}: {cves} on {asset}",
        text="\n".join(lines),
        metadata={"finding_id": cp.finding_id, "rank": str(cp.rank), "asset_id": asset},
    )


def topology_document(topology: NetworkTopology) -> AssistantDocument:
    lines = [
        f"Declared network topology {topology.topology_id} for engagement "
        f"{topology.engagement_id}.",
        f"Declared by {topology.declared_by} at {topology.declared_at.isoformat()}.",
    ]
    if topology.source_note:
        lines.append(f"Source: {topology.source_note}")
    lines.append("Zones:")
    for zone in topology.zones:
        flags = [
            flag
            for flag, on in (
                ("attacker entry", zone.attacker_entry),
                ("crown jewel", zone.crown_jewel),
            )
            if on
        ]
        flag_text = f" [{', '.join(flags)}]" if flags else ""
        desc = f": {zone.description}" if zone.description else ""
        lines.append(f"- {zone.name} ({', '.join(zone.cidrs)}){flag_text}{desc}")
    lines.append(
        "Hosts in the same zone can reach each other."
        if topology.intra_zone_reachable
        else "Hosts in the same zone cannot reach each other unless a flow allows it."
    )
    if topology.flows:
        lines.append("Allowed flows:")
        for flow in topology.flows:
            ports = ", ".join(str(p) for p in flow.ports) if flow.ports else "all ports"
            desc = f": {flow.description}" if flow.description else ""
            lines.append(f"- {flow.from_zone} -> {flow.to_zone} on {ports}{desc}")
    else:
        lines.append("Allowed flows: none declared.")
    for host in topology.multi_homed_hosts:
        lines.append(f"Multi-homed host {host.name}: {', '.join(host.addresses)}.")
    return AssistantDocument(
        doc_id=topology.topology_id,
        kind="topology",
        engagement_id=topology.engagement_id,
        title=f"Network topology declared by {topology.declared_by}",
        text="\n".join(lines),
        metadata={"declared_by": topology.declared_by},
    )


def documents_for_engagement(
    *,
    engagement_id: str,
    observations: Iterable[Observation] = (),
    enriched_findings: Iterable[EnrichedFinding] = (),
    graph: AttackGraphResult | None = None,
    topology: NetworkTopology | None = None,
) -> list[AssistantDocument]:
    """Every document for one engagement, sorted by doc_id, de-duplicated.

    Raises ValueError if any record belongs to another engagement: mixing engagements
    in one index would let one engagement's answer cite another's facts.
    """

    def check(owner: str, what: str) -> None:
        if owner != engagement_id:
            raise ValueError(f"{what} belongs to engagement {owner!r}, not {engagement_id!r}")

    docs: list[AssistantDocument] = []
    for obs in observations:
        check(obs.engagement_id, f"observation {obs.observation_id}")
        docs.append(observation_document(obs))
    for ef in enriched_findings:
        check(ef.finding.engagement_id, f"finding {ef.finding.finding_id}")
        docs.append(enriched_finding_document(ef))
    if graph is not None:
        check(graph.engagement_id, "attack graph")
        docs.extend(path_document(p, graph.nodes, engagement_id) for p in graph.paths)
        docs.extend(chokepoint_document(cp, engagement_id) for cp in graph.chokepoints)
    if topology is not None:
        check(topology.engagement_id, f"topology {topology.topology_id}")
        docs.append(topology_document(topology))

    unique: dict[str, AssistantDocument] = {}
    for doc in docs:
        unique.setdefault(doc.doc_id, doc)
    return [unique[k] for k in sorted(unique)]
