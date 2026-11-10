"""The engagement report as data (DECISIONS.md D-051).

`EngagementReport` is the single structure both output formats are rendered from: the
JSON export is this model serialised, the Markdown export is a rendering of it. Nothing
in here is measured or estimated by the report itself: every value is copied from a
stored fact, a stored enrichment, or the deterministic graph engine's output, and keeps
the attribution it came with.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Confidence, Source

REPORT_FORMAT = "seekthreat.report/1"

NOT_SCORED = "not scored"

NARRATION_LABEL = (
    "Model-generated narration of an already-proven path. It is not evidence and no "
    "edge in this report was derived from it."
)


def require_aware(value: datetime) -> datetime:
    """Reject naive datetimes, as every timestamp in packages.schema does."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class ScanRecord(_Frozen):
    """One scan job as stored by the API. Input to the builder and copied into the
    report's scan inventory."""

    scan_id: str
    scanner: str
    target: str
    status: str
    artifact_id: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime | None = None

    @field_validator("created_at", "completed_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware(value)


class AuthorizationSection(_Frozen):
    authorized_by: str
    allowlist: tuple[str, ...]
    granted_at: datetime
    expires_at: datetime
    # Every audit event for this engagement carries this id as its authorization
    # reference, so the report can be matched against the audit log.
    authorization_reference: str


class EngagementSection(_Frozen):
    engagement_id: str
    name: str
    created_at: datetime
    authorization: AuthorizationSection


class ScanEntry(_Frozen):
    scan_id: str
    scanner: str
    target: str
    status: str
    artifact_id: str | None
    # Observations stored under this scan's artifact, counted from the facts handed in.
    observation_count: int
    created_at: datetime
    completed_at: datetime | None
    error_message: str | None


class Attribution(_Frozen):
    """Who reported a fact, from which source, at what confidence."""

    scanner: str
    source: Source
    confidence: Confidence


class ServiceEntry(_Frozen):
    endpoint: str
    port: int
    protocol: str
    # Distinct values reported across observations, sorted. Scanners can disagree;
    # the report lists every claim rather than picking one.
    names: tuple[str, ...]
    products: tuple[str, ...]
    versions: tuple[str, ...]
    cpes: tuple[str, ...]
    attributions: tuple[Attribution, ...]
    observation_ids: tuple[str, ...]


class AssetEntry(_Frozen):
    address: str
    hostnames: tuple[str, ...]
    attributions: tuple[Attribution, ...]
    services: tuple[ServiceEntry, ...]
    # host_up facts for this address (service facts are listed on each service).
    observation_ids: tuple[str, ...]


class EnrichedFieldEntry(_Frozen):
    name: str
    value: EnrichmentValue
    source: Source
    confidence: Confidence
    retrieved_at: datetime
    note: str | None


class ScoreComponentEntry(_Frozen):
    name: str
    value: float
    weight: float
    # value * weight: this component's share of the score.
    contribution: float
    explanation: str
    source: Source
    confidence: Confidence


class ScoreEntry(_Frozen):
    value: float
    components: tuple[ScoreComponentEntry, ...]
    # ExposureRiskScore.explain(), verbatim.
    explanation: str


class FindingEntry(_Frozen):
    finding_id: str
    asset_id: str
    scanner: str
    cve_ids: tuple[str, ...]
    title: str
    description: str
    detected_at: datetime
    observation_ids: tuple[str, ...]
    fields: tuple[EnrichedFieldEntry, ...]
    # "scored" with `ers` set, or "not scored" with `ers` None. Never a zero stand-in.
    ers_status: Literal["scored", "not scored"]
    ers: ScoreEntry | None
    # Attack paths with at least one step that depends on this finding, in rank order.
    on_path_ids: tuple[str, ...]
    chokepoint_rank: int | None


class PathStepEntry(_Frozen):
    index: int
    edge_id: str
    from_node: str
    from_label: str
    to_node: str
    to_label: str
    rule_name: str
    description: str
    confidence: Confidence
    evidence: tuple[str, ...]
    finding_ids: tuple[str, ...]


class NarrationEntry(_Frozen):
    label: str
    model: str
    text: str
    citations: tuple[str, ...]
    grounded: bool
    unsupported_entities: tuple[str, ...]
    invalid_citations: tuple[str, ...]


class PathEntry(_Frozen):
    path_id: str
    rank: int | None
    rank_explanation: str | None
    confidence: Confidence
    entry_node: str
    entry_label: str
    goal_node: str
    goal_label: str
    steps: tuple[PathStepEntry, ...]
    narration: NarrationEntry | None


class ChokepointEntry(_Frozen):
    rank: int
    finding_id: str
    asset_id: str | None
    cve_ids: tuple[str, ...]
    remediation: str
    paths_broken: tuple[str, ...]
    goals_cut: tuple[str, ...]
    goal_labels: tuple[str, ...]


class UnclassifiedEntry(_Frozen):
    finding_id: str
    asset_id: str
    cve_ids: tuple[str, ...]
    reason: str


class AttackGraphSection(_Frozen):
    topology_id: str
    rules_digest: str
    ordering: str
    max_depth: int
    max_paths: int
    truncated: bool
    node_count: int
    edge_count: int
    paths: tuple[PathEntry, ...]
    chokepoints: tuple[ChokepointEntry, ...]
    unclassified_findings: tuple[UnclassifiedEntry, ...]
    unzoned_addresses: tuple[str, ...]


class SimulationSection(_Frozen):
    chokepoint_rank: int
    fixed_finding_ids: tuple[str, ...]
    baseline_path_count: int
    remaining_path_count: int
    removed_path_ids: tuple[str, ...]
    goals_no_longer_reachable: tuple[str, ...]
    goal_labels: tuple[str, ...]
    after_truncated: bool


class EvidenceEntry(_Frozen):
    evidence_id: str
    kind: Literal["observation", "finding", "topology", "unresolved"]
    summary: str
    # Report sections citing it: "asset:<address>", "finding:<id>", "path:<id>".
    cited_by: tuple[str, ...]


class EngagementReport(_Frozen):
    report_format: str = REPORT_FORMAT
    generated_at: datetime
    engagement: EngagementSection
    scans: tuple[ScanEntry, ...]
    assets: tuple[AssetEntry, ...]
    findings: tuple[FindingEntry, ...]
    # None when the graph could not be built; `attack_graph_unavailable` says why.
    attack_graph: AttackGraphSection | None
    attack_graph_unavailable: str | None
    simulation: SimulationSection | None
    simulation_unavailable: str | None
    # Plain statements of what this report does not cover. Never empty: the standing
    # caveats are always listed.
    limitations: tuple[str, ...]
    evidence: tuple[EvidenceEntry, ...]

    @field_validator("generated_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)
