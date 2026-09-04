"""Shared data models. Everything crosses this boundary.

Two invariants:
  1. Every enriched field carries where it came from and how confident we are.
     No unattributed data anywhere in the system.
  2. Every score renders its own explanation. No opaque numbers.
"""

from packages.schema.models.asset import Asset, Service
from packages.schema.models.citation import Citation, CitationKind
from packages.schema.models.engagement import (
    Authorization,
    Engagement,
    ScanRequest,
    target_matches,
)
from packages.schema.models.finding import EnrichedFinding, EnrichmentValue, Finding
from packages.schema.models.graph import AttackPath, Chokepoint, PathEdge, Rule
from packages.schema.models.observation import Observation, ObservationKind, RawArtifact
from packages.schema.models.provenance import (
    Attributed,
    Confidence,
    Provenance,
    Source,
)
from packages.schema.models.scoring import ExposureRiskScore, ScoreComponent

__all__ = [
    "Asset",
    "AttackPath",
    "Attributed",
    "Authorization",
    "Chokepoint",
    "Citation",
    "CitationKind",
    "Confidence",
    "Engagement",
    "EnrichedFinding",
    "EnrichmentValue",
    "ExposureRiskScore",
    "Finding",
    "Observation",
    "ObservationKind",
    "PathEdge",
    "Provenance",
    "RawArtifact",
    "Rule",
    "ScanRequest",
    "ScoreComponent",
    "Service",
    "Source",
    "target_matches",
]
