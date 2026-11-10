"""Render an `EngagementReport` as JSON or Markdown (DECISIONS.md D-049).

Both renderers are pure and take only the report, so one report always renders to the
same bytes. Text that came from scanners or feeds is escaped before it lands in Markdown:
it cannot open a table cell, start a heading or inject raw HTML into a rendered view.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import datetime

from services.report.models import (
    NOT_SCORED,
    Attribution,
    EngagementReport,
    EnrichedFieldEntry,
    FindingEntry,
    PathEntry,
)

FORMATS = ("md", "json")
MEDIA_TYPES = {"md": "text/markdown; charset=utf-8", "json": "application/json"}


def render_json(report: EngagementReport) -> str:
    """The report model, serialised. Field order is the model's declaration order."""
    return report.model_dump_json(indent=2) + "\n"


# --------------------------------------------------------------------------- escaping


def _text(value: object) -> str:
    """Untrusted text for a Markdown paragraph or cell: one line, no raw HTML, no
    table breaks, no emphasis or link syntax taking effect."""
    text = " ".join(str(value).split())
    for char in ("\\", "`", "*", "[", "]", "|", "#"):
        text = text.replace(char, "\\" + char)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _code(value: object) -> str:
    """An identifier in a code span. Backticks inside are swapped so the span holds."""
    text = " ".join(str(value).split()).replace("`", "'")
    return f"`{text.replace('|', '¦')}`"


def _codes(values: Iterable[object], empty: str = "none") -> str:
    rendered = [_code(v) for v in values]
    return ", ".join(rendered) if rendered else empty


def _when(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "—"


def _num(value: float) -> str:
    return f"{value:.2f}"


def _field_value(field: EnrichedFieldEntry) -> str:
    value = field.value
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return _text(", ".join(value)) if value else "—"
    if isinstance(value, float):
        return _text(json.dumps(value))
    return _text(value)


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


# --------------------------------------------------------------------------- sections


def _engagement(report: EngagementReport) -> list[str]:
    e = report.engagement
    a = e.authorization
    return [
        "## 1. Engagement and authorization",
        "",
        *_table(
            ("Item", "Value"),
            [
                ("Engagement ID", _code(e.engagement_id)),
                ("Name", _text(e.name)),
                ("Created", _when(e.created_at)),
                ("Authorized by", _text(a.authorized_by)),
                ("Target allowlist", _codes(a.allowlist)),
                ("Authorization window", f"{_when(a.granted_at)} to {_when(a.expires_at)}"),
                ("Authorization reference", _code(a.authorization_reference)),
            ],
        ),
        "",
        "Every scan and query in this engagement is audit-logged with the authorization "
        "reference above.",
    ]


def _scans(report: EngagementReport) -> list[str]:
    lines = ["## 2. Scan inventory", ""]
    if not report.scans:
        return [*lines, "No scans are recorded for this engagement."]
    rows = [
        (
            _code(s.scan_id),
            _text(s.scanner),
            _code(s.target),
            _text(s.status),
            str(s.observation_count),
            _code(s.artifact_id) if s.artifact_id else "—",
            _when(s.created_at),
            _when(s.completed_at),
            _text(s.error_message) if s.error_message else "—",
        )
        for s in report.scans
    ]
    headers = (
        "Scan",
        "Scanner",
        "Target",
        "Status",
        "Observations",
        "Artifact",
        "Created",
        "Completed",
        "Error",
    )
    return [*lines, *_table(headers, rows)]


def _attrib(attributions: Sequence[Attribution]) -> str:
    return (
        "; ".join(
            f"{_text(a.scanner)} ({a.source.value}, {a.confidence.value})" for a in attributions
        )
        or "—"
    )


def _assets(report: EngagementReport) -> list[str]:
    lines = ["## 3. Assets and services", ""]
    if not report.assets:
        return [*lines, "No hosts or services were observed."]
    lines.append(
        "Derived from host and service observations. Where scanners disagree every "
        "reported value is listed."
    )
    for asset in report.assets:
        names = f" ({', '.join(_text(h) for h in asset.hostnames)})" if asset.hostnames else ""
        lines += ["", f"### {_text(asset.address)}{names}", ""]
        lines.append(f"Reported by: {_attrib(asset.attributions)}")
        if asset.observation_ids:
            lines.append(f"Host evidence: {_codes(asset.observation_ids)}")
        if not asset.services:
            lines += ["", "No open services observed."]
            continue
        rows = [
            (
                _code(s.endpoint),
                _text(", ".join(s.names)) or "—",
                _text(", ".join(s.products)) or "—",
                _text(", ".join(s.versions)) or "—",
                _codes(s.cpes, empty="—"),
                _attrib(s.attributions),
                _codes(s.observation_ids),
            )
            for s in asset.services
        ]
        lines += [
            "",
            *_table(
                ("Endpoint", "Service", "Product", "Version", "CPE", "Reported by", "Evidence"),
                rows,
            ),
        ]
    return lines


def _finding(index: int, f: FindingEntry) -> list[str]:
    heading = ", ".join(f.cve_ids) or f.title or "Finding without CVE"
    lines = [
        f"### F{index}. {_text(heading)}",
        "",
        f"- Finding: {_code(f.finding_id)}",
        f"- Asset: {_code(f.asset_id)}",
        f"- Reported by: {_text(f.scanner)}, detected {_when(f.detected_at)}",
    ]
    if f.title and f.title != heading:
        lines.append(f"- Title: {_text(f.title)}")
    lines.append(f"- Evidence: {_codes(f.observation_ids)}")
    if f.on_path_ids:
        lines.append(f"- On attack paths: {_codes(f.on_path_ids)}")
    if f.chokepoint_rank is not None:
        lines.append(f"- Chokepoint rank: {f.chokepoint_rank}")
    lines.append("")
    if f.ers is None:
        lines.append(
            f"**Exposure Risk Score: {NOT_SCORED}.** No score is stored for this finding; "
            "it is not zero."
        )
    else:
        lines += [
            f"**Exposure Risk Score: {_num(f.ers.value)}**, the sum of these weighted components:",
            "",
            *_table(
                (
                    "Component",
                    "Value",
                    "Weight",
                    "Contribution",
                    "Explanation",
                    "Source",
                    "Confidence",
                ),
                [
                    (
                        _text(c.name),
                        _num(c.value),
                        _num(c.weight),
                        _num(c.contribution),
                        _text(c.explanation),
                        c.source.value,
                        c.confidence.value,
                    )
                    for c in f.ers.components
                ],
            ),
        ]
    lines.append("")
    if f.fields:
        lines += [
            "Enriched fields:",
            "",
            *_table(
                ("Field", "Value", "Source", "Confidence", "Retrieved", "Note"),
                [
                    (
                        _text(x.name),
                        _field_value(x),
                        x.source.value,
                        x.confidence.value,
                        _when(x.retrieved_at),
                        _text(x.note) if x.note else "—",
                    )
                    for x in f.fields
                ],
            ),
        ]
    else:
        lines.append("No enriched fields are stored for this finding.")
    return lines


def _findings(report: EngagementReport) -> list[str]:
    lines = ["## 4. Findings", ""]
    if not report.findings:
        return [*lines, "No findings are recorded for this engagement."]
    scored = sum(1 for f in report.findings if f.ers is not None)
    lines.append(
        f"{len(report.findings)} findings: {scored} scored, "
        f"{len(report.findings) - scored} {NOT_SCORED}. Ordered by stored Exposure Risk "
        "Score, highest first; unscored findings follow, by finding id."
    )
    for i, f in enumerate(report.findings, start=1):
        lines += ["", *_finding(i, f)]
    return lines


def _path(p: PathEntry) -> list[str]:
    rank = f"Rank {p.rank}" if p.rank is not None else "Unranked"
    lines = [
        f"### {rank}: {_text(p.entry_label)} to {_text(p.goal_label)}",
        "",
        f"- Path: {_code(p.path_id)}",
        f"- Confidence (weakest step): {p.confidence.value}",
    ]
    if p.rank_explanation:
        lines.append(f"- Why this rank: {_text(p.rank_explanation)}")
    rows = [
        (
            str(s.index),
            _text(s.from_label),
            _text(s.to_label),
            _code(s.rule_name),
            s.confidence.value,
            _text(s.description) if s.description else "—",
            _codes(s.evidence),
        )
        for s in p.steps
    ]
    lines += [
        "",
        *_table(("Step", "From", "To", "Rule", "Confidence", "What it means", "Evidence"), rows),
    ]
    if p.narration is not None:
        n = p.narration
        lines += [
            "",
            f"**Model-generated narration** ({_text(n.model)}). {n.label}",
            "",
            f"> {_text(n.text)}",
            "",
            f"Grounding check: {'passed' if n.grounded else 'FAILED'}."
            + (f" Unsupported: {_codes(n.unsupported_entities)}." if n.unsupported_entities else "")
            + (
                f" Invalid citations: {_codes(n.invalid_citations)}." if n.invalid_citations else ""
            ),
        ]
    return lines


def _attack_graph(report: EngagementReport) -> list[str]:
    lines = ["## 5. Attack paths", ""]
    g = report.attack_graph
    if g is None:
        return [*lines, f"Not built: {_text(report.attack_graph_unavailable or 'unknown')}"]
    lines += [
        "Built by the deterministic rules engine. Every step names the rule that produced "
        "it and the evidence that satisfied the rule.",
        "",
        f"- Topology: {_code(g.topology_id)}",
        f"- Rules digest: {_code(g.rules_digest)}",
        f"- Graph: {g.node_count} nodes, {g.edge_count} edges, {len(g.paths)} paths",
        f"- Limits: max_depth {g.max_depth}, max_paths {g.max_paths}"
        + (" (enumeration was truncated)" if g.truncated else ""),
        f"- Ordering: {_text(g.ordering)}",
    ]
    if not g.paths:
        lines += ["", "No attack path reaches a goal from an attacker entry zone."]
    for p in g.paths:
        lines += ["", *_path(p)]
    if g.unclassified_findings:
        lines += [
            "",
            "### Findings on no path",
            "",
            *_table(
                ("Finding", "Asset", "CVEs", "Why no rule applies"),
                [
                    (_code(u.finding_id), _code(u.asset_id), _codes(u.cve_ids), _text(u.reason))
                    for u in g.unclassified_findings
                ],
            ),
        ]
    return lines


def _chokepoints(report: EngagementReport) -> list[str]:
    lines = ["## 6. Chokepoints", ""]
    g = report.attack_graph
    if g is None or not g.chokepoints:
        return [*lines, "No chokepoints: there are no attack paths to break."]
    rows = [
        (
            str(c.rank),
            _code(c.finding_id),
            _code(c.asset_id) if c.asset_id else "—",
            _codes(c.cve_ids),
            ", ".join(_text(x) for x in c.goal_labels) or "—",
            str(len(c.paths_broken)),
            _text(c.remediation),
        )
        for c in g.chokepoints
    ]
    return [
        *lines,
        "Fixes ranked by goals cut off, then paths broken.",
        "",
        *_table(
            ("Rank", "Finding", "Asset", "CVEs", "Goals cut", "Paths broken", "Remediation"),
            rows,
        ),
    ]


def _simulation(report: EngagementReport) -> list[str]:
    lines = ["## 7. Remediation simulation (top chokepoint)", ""]
    s = report.simulation
    if s is None:
        return [*lines, f"Not run: {_text(report.simulation_unavailable or 'unknown')}."]
    lines += [
        f"The graph was rebuilt from the same facts with {_codes(s.fixed_finding_ids)} "
        f"(chokepoint rank {s.chokepoint_rank}) treated as fixed.",
        "",
        f"- Paths before: {s.baseline_path_count}",
        f"- Paths after: {s.remaining_path_count}"
        + (" (rebuild was truncated)" if s.after_truncated else ""),
        f"- Paths removed: {_codes(s.removed_path_ids)}",
        "- Goals no longer reachable: "
        + (", ".join(_text(x) for x in s.goal_labels) if s.goal_labels else "none"),
    ]
    return lines


def _limitations(report: EngagementReport) -> list[str]:
    return ["## 8. Coverage and limitations", "", *(f"- {_text(n)}" for n in report.limitations)]


def _evidence(report: EngagementReport) -> list[str]:
    lines = ["## Appendix A. Evidence", ""]
    if not report.evidence:
        return [*lines, "No evidence is cited."]
    rows = [
        (_code(e.evidence_id), e.kind, _text(e.summary), _codes(e.cited_by))
        for e in report.evidence
    ]
    return [
        *lines,
        "Every id cited anywhere above, resolved against the stored facts.",
        "",
        *_table(("Evidence", "Kind", "What it is", "Cited by"), rows),
    ]


def render_markdown(report: EngagementReport) -> str:
    sections = [
        [
            f"# Engagement report: {_text(report.engagement.name)}",
            "",
            f"- Generated: {_when(report.generated_at)}",
            f"- Report format: {_code(report.report_format)}",
            "",
            "Attack paths in this report were constructed by the deterministic rules engine "
            "from observed scan facts. Text produced by a language model, where present, is "
            "labelled as such and is not a source of any path or step.",
        ],
        _engagement(report),
        _scans(report),
        _assets(report),
        _findings(report),
        _attack_graph(report),
        _chokepoints(report),
        _simulation(report),
        _limitations(report),
        _evidence(report),
    ]
    return "\n\n".join("\n".join(s) for s in sections) + "\n"


def render(report: EngagementReport, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "md":
        return render_markdown(report)
    raise ValueError(f"unknown report format {fmt!r}; expected one of {FORMATS}")
