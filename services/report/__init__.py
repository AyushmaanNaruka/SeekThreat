"""Engagement report: one deterministic builder, rendered as Markdown or JSON (D-049).

Pure like `services.graph`: no clock (the caller passes `generated_at`), no database, no
network, no model. The builder copies stored facts and engine output; it never creates
an attack-graph edge.
"""

from services.report.builder import ReportInputError, build_report
from services.report.models import EngagementReport, ScanRecord
from services.report.render import FORMATS, MEDIA_TYPES, render, render_json, render_markdown

__all__ = [
    "FORMATS",
    "MEDIA_TYPES",
    "EngagementReport",
    "ReportInputError",
    "ScanRecord",
    "build_report",
    "render",
    "render_json",
    "render_markdown",
]
