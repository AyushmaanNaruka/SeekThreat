"""Decide what a finding lets an attacker do, from evidence already held.

Inputs are the scanner's own template tags and CWE ids on the finding's observations,
plus fused `cwe_ids` from enrichment when available. Free text (titles, descriptions)
is never read: matching prose would be guessing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from packages.schema.models.finding import EnrichedFinding
from packages.schema.models.observation import Observation
from packages.schema.models.provenance import Confidence
from services.graph.ruleset import CAPABILITIES, RuleSet

_CWE = re.compile(r"CWE-[0-9]{1,5}", re.ASCII)
_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass(frozen=True)
class CapabilityMatch:
    capability: str
    confidence: Confidence
    # Human-readable signals, e.g. "nuclei tag 'rce'", "CWE-94 (enrichment)".
    signals: tuple[str, ...]


def _split(value: str) -> list[str]:
    return [p.strip() for p in re.split(r"[,|]", value) if p.strip()]


def evidence_ids(
    observations: Iterable[Observation], enriched: EnrichedFinding | None
) -> tuple[dict[str, str], dict[str, str]]:
    """Return ({tag: where}, {CWE: where}) gathered from the finding's evidence."""
    tags: dict[str, str] = {}
    cwes: dict[str, str] = {}
    for obs in sorted(observations, key=lambda o: o.observation_id):
        for tag in _split(obs.attributes.get("tags", "")):
            tags.setdefault(tag.lower(), f"{obs.scanner} tag")
        for cwe in _CWE.findall(obs.attributes.get("cwe_ids", "").upper()):
            cwes.setdefault(cwe, f"{obs.scanner}")
    if enriched is not None and "cwe_ids" in enriched.fields:
        attributed = enriched.fields["cwe_ids"]
        value = attributed.value
        raw = value if isinstance(value, list) else [str(value or "")]
        for item in raw:
            for cwe in _CWE.findall(str(item).upper()):
                cwes.setdefault(cwe, f"enrichment:{attributed.provenance.source.value}")
    return tags, cwes


def classify(
    observations: Iterable[Observation],
    enriched: EnrichedFinding | None,
    ruleset: RuleSet,
) -> tuple[list[CapabilityMatch], tuple[str, ...], tuple[str, ...]]:
    """Classify one finding. Returns (matches, tags seen, CWEs seen); the seen lists
    explain an empty result."""
    tags, cwes = evidence_ids(observations, enriched)
    matches: list[CapabilityMatch] = []
    for capability in CAPABILITIES:
        hits: list[tuple[Confidence, str]] = []
        for signal in ruleset.signals:
            ids = signal.ids_for(capability)
            if signal.kind == "scanner_tag":
                for tag in sorted(set(tags) & ids):
                    hits.append((signal.confidence, f"{tags[tag]} '{tag}'"))
            else:
                for cwe in sorted(set(cwes) & ids):
                    hits.append((signal.confidence, f"{cwe} ({cwes[cwe]})"))
        if hits:
            best = max((c for c, _ in hits), key=lambda c: _RANK[c])
            matches.append(
                CapabilityMatch(
                    capability=capability,
                    confidence=best,
                    signals=tuple(s for _, s in hits),
                )
            )
    return matches, tuple(sorted(tags)), tuple(sorted(cwes))


__all__ = ["CapabilityMatch", "classify", "evidence_ids"]
