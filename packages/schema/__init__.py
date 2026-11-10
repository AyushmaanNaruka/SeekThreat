"""Shared data models. Everything crosses this boundary.

Two invariants:
  1. Every enriched field carries where it came from and how confident we are.
     No unattributed data anywhere in the system.
  2. Every score renders its own explanation. No opaque numbers.
"""

from packages.schema.models.asset import Asset, Service
from packages.schema.models.assistant import (
    Answer,
    AssistantDocument,
    CitationRepair,
    GroundingCheck,
    PathNarration,
    RetrievedDocument,
)
from packages.schema.models.citation import Citation, CitationKind
from packages.schema.models.engagement import (
    Authorization,
    Engagement,
    ScanRequest,
    target_matches,
)
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.graph import (
    AttackGraphResult,
    AttackPath,
    Chokepoint,
    GraphNode,
    NodeKind,
    PathEdge,
    Rule,
    SimulationResult,
    UnclassifiedFinding,
)
from packages.schema.models.observation import (
    Observation,
    ObservationKind,
    RawArtifact,
    ScanResult,
)
from packages.schema.models.provenance import (
    Attributed,
    Confidence,
    Provenance,
    Source,
)
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent
from packages.schema.models.topology import MultiHomedHost, NetworkTopology, Zone, ZoneFlow

__all__ = [
    "Answer",
    "Asset",
    "AssistantDocument",
    "AttackGraphResult",
    "AttackPath",
    "Attributed",
    "Authorization",
    "Chokepoint",
    "Citation",
    "CitationKind",
    "CitationRepair",
    "Confidence",
    "Engagement",
    "EnrichedFinding",
    "EnrichmentValue",
    "ExposureRiskScore",
    "Finding",
    "GraphNode",
    "GroundingCheck",
    "MultiHomedHost",
    "NetworkTopology",
    "NodeKind",
    "Observation",
    "ObservationKind",
    "PathEdge",
    "PathNarration",
    "Provenance",
    "RawArtifact",
    "RetrievedDocument",
    "Rule",
    "ScanRequest",
    "ScanResult",
    "ScoreComponent",
    "Service",
    "SimulationResult",
    "Source",
    "target_matches",
    "UnclassifiedFinding",
    "Zone",
    "ZoneFlow",
]
