"""Track 1 entry point: observations -> identity-resolved, de-duplicated Findings.

Identity resolution and deduplication need the whole engagement's facts, not just one
scan's: the nmap scan that ties `dvwa.lab.local` to `172.20.1.10` and the nuclei scan
that found a CVE on `dvwa.lab.local` are usually separate scans. `normalize_scan_observations`
therefore normalises the engagement's observations together and returns the findings the
new scan touched — those it supports with an observation, or whose asset join rests on
one of its observations — so a scan re-enqueues what it changed and nothing else.

Pure and deterministic: same observations in, same findings (ids, order, content) out.
No DNS, no network, no database access here.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel

from packages.schema.models.finding import Finding
from packages.schema.models.observation import Observation
from services.normalize.dedup import MergeRecord, dedupe_findings
from services.normalize.identity import Ambiguity, IdentityLink, IdentityResolver


class NormalizationResult(BaseModel):
    findings: list[Finding]
    merges: list[MergeRecord]
    links: list[IdentityLink]
    ambiguities: list[Ambiguity]
    unresolved_observation_ids: list[str]


def normalize_observations(
    observations: Iterable[Observation], detected_at: datetime
) -> NormalizationResult:
    """Normalise observations, resolving identity separately within each engagement."""
    by_engagement: dict[str, dict[str, Observation]] = defaultdict(dict)
    for obs in observations:
        by_engagement[obs.engagement_id].setdefault(obs.observation_id, obs)

    result = NormalizationResult(
        findings=[], merges=[], links=[], ambiguities=[], unresolved_observation_ids=[]
    )
    for engagement_id in sorted(by_engagement):
        group = sorted(by_engagement[engagement_id].values(), key=lambda o: o.observation_id)
        resolver = IdentityResolver(group)
        dedup = dedupe_findings(group, resolver, detected_at)
        result.findings.extend(dedup.findings)
        result.merges.extend(dedup.merges)
        result.links.extend(resolver.links)
        result.ambiguities.extend(resolver.ambiguities)
        result.unresolved_observation_ids.extend(dedup.unresolved_observation_ids)
    return result


def normalize_scan_observations(
    scan_observations: Iterable[Observation],
    detected_at: datetime,
    engagement_observations: Iterable[Observation] = (),
) -> NormalizationResult:
    """Normalise a scan in its engagement's context; return the findings it touched.

    `engagement_observations` is the engagement's stored fact base (it may already
    include the scan's own observations; duplicates are collapsed by id).
    """
    scan_obs = list(scan_observations)
    scan_ids = {o.observation_id for o in scan_obs}
    full = normalize_observations([*engagement_observations, *scan_obs], detected_at)

    def touched(merge: MergeRecord) -> bool:
        if scan_ids.intersection(merge.observation_ids):
            return True
        return any(scan_ids.intersection(r.observation_ids) for r in merge.resolutions)

    keep = {m.finding_id for m in full.merges if touched(m)}
    return NormalizationResult(
        findings=[f for f in full.findings if f.finding_id in keep],
        merges=[m for m in full.merges if m.finding_id in keep],
        links=full.links,
        ambiguities=full.ambiguities,
        unresolved_observation_ids=sorted(scan_ids.intersection(full.unresolved_observation_ids)),
    )
