"""Cross-scanner deduplication: vuln_candidate observations -> Findings.

Merge rule (the only two ways observations end up in one Finding):

1. **Same CVE set on the same listener.** Two `vuln_candidate` observations merge when
   they resolve to the same canonical `asset_id` (see `identity.py`), name the same port
   and protocol (or both name none), and report exactly the same non-empty set of
   canonical CVE IDs. Scanner does not matter: nuclei and ssh-audit both reporting
   CVE-2023-48795 on `host:172.20.2.50` port 22/tcp is one finding.
2. **Same scanner identity on the same listener.** Observations with no CVE merge only
   when they come from the same scanner and carry the same scanner identity keys
   (`template_id`, `matcher_name`, `nikto_id`, `method`, URL path, `finding_type`,
   `category`, `algorithm`) on the same asset and port — i.e. the same check fired twice.

Nothing else merges. Similar titles, overlapping-but-unequal CVE sets, a CVE with a port
and the same CVE without one, or two scanners' no-CVE checks that "look alike" all stay
separate findings: a false merge hides evidence, a duplicate only repeats it.

Provenance is kept, not flattened: `observation_ids` lists every supporting observation,
`scanner` lists every scanner that reported it, and the description carries each
scanner's own confidence and note, because a banner-inferred ssh-audit CVE (low) and a
nuclei template match (high) are different strengths of evidence for the same finding.

`finding_id` is a hash of the merge key, never of observation ids or timestamps, so
re-normalising the same engagement (or a re-scan) upserts the same finding. Output is
sorted by (asset_id, finding_id).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from packages.schema.models.finding import CVE_ID_PATTERN, Finding
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.provenance import Confidence
from services.normalize.identity import IdentityResolver, Resolution, endpoint_of

RULE_CVE = "same_cve_same_listener"
RULE_SCANNER = "same_scanner_check_same_listener"

# Scanner identity keys, in a fixed order. Volatile values (timestamps, banners, curl
# commands) are excluded so a re-scan hashes identically. `url` is reduced to its path:
# nuclei's `url` repeats the host and port, which the asset/listener already cover.
_IDENTITY_KEYS = (
    "template_id",
    "matcher_name",
    "nikto_id",
    "method",
    "url",
    "finding_type",
    "category",
    "algorithm",
)

_CONFIDENCE_RANK = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


class MergeRecord(BaseModel):
    """Why one Finding contains the observations it does."""

    model_config = ConfigDict(frozen=True)

    finding_id: str
    rule: str
    key: tuple[str, ...]
    asset_id: str
    # How each distinct host spelling in the group reached `asset_id` (joins included).
    resolutions: tuple[Resolution, ...]
    observation_ids: tuple[str, ...]
    scanners: tuple[str, ...]


class DedupResult(BaseModel):
    findings: list[Finding]
    merges: list[MergeRecord]
    # vuln_candidate observations that name no usable host; visible, not dropped silently.
    unresolved_observation_ids: list[str]


def cve_ids_of(observation: Observation) -> list[str]:
    """Canonical CVE IDs the scanner itself reported, sorted. Never inferred."""
    out: set[str] = set()
    for part in observation.attributes.get("cve_ids", "").split(","):
        norm = part.strip().upper()
        if CVE_ID_PATTERN.fullmatch(norm):
            out.add(norm)
    return sorted(out)


def _identity_value(key: str, value: str) -> str:
    if key == "url" and "://" in value:
        return urlsplit(value).path or "/"
    return value


def merge_key(observation: Observation, asset_id: str) -> tuple[str, tuple[str, ...]]:
    """(rule, key) for an observation already resolved to `asset_id`."""
    endpoint = endpoint_of(observation)
    service = endpoint.service_key if endpoint is not None else ""
    cves = cve_ids_of(observation)
    if cves:
        return RULE_CVE, ("cve", asset_id, service, ",".join(cves))
    a = observation.attributes
    identity = tuple(f"{k}={_identity_value(k, a[k])}" for k in _IDENTITY_KEYS if a.get(k))
    return RULE_SCANNER, ("check", asset_id, service, observation.scanner, *identity)


def finding_id_for(key: tuple[str, ...]) -> str:
    return "fnd-" + hashlib.sha256("\x1f".join(key).encode("utf-8")).hexdigest()[:24]


def _title(observation: Observation, cve_ids: list[str]) -> str:
    a = observation.attributes
    if a.get("template_name"):
        if a.get("matcher_name"):
            return f"{a['template_name']}: {a['matcher_name']}"
        return a["template_name"]
    if a.get("msg"):
        return a["msg"]
    if a.get("finding_type") == "weak_algorithm" and a.get("algorithm"):
        return f"Weak SSH {a.get('category', 'algorithm')} algorithm: {a['algorithm']}"
    if cve_ids:
        return ", ".join(cve_ids)
    return a.get("template_id") or a.get("nikto_id") or f"{observation.scanner} finding"


def _description(group: list[Observation], resolutions: list[Resolution]) -> str:
    # Finding has no confidence field, so every scanner's own confidence goes here: a
    # low-confidence banner-inferred CVE must not read as a confirmed one.
    reported: list[str] = []
    for obs in group:
        line = f"{obs.scanner}: confidence {obs.provenance.confidence.value}"
        if obs.provenance.note:
            line += f" ({obs.provenance.note})"
        if line not in reported:
            reported.append(line)
    parts = ["Reported by " + "; ".join(reported)]
    for res in resolutions:
        if res.joined and res.rule:
            parts.append(f"Asset {res.alias} joined to {res.asset_id} by rule {res.rule}")
    for obs in group:
        a = obs.attributes
        for k in ("description", "notes", "recommendation"):
            if a.get(k) and a[k] not in parts:
                parts.append(a[k])
        if a.get("url") and f"URL: {a['url']}" not in parts:
            parts.append(f"URL: {a['url']}")
    return " | ".join(parts)


def _evidence_order(obs: Observation) -> tuple[int, str, str]:
    return (_CONFIDENCE_RANK[obs.provenance.confidence], obs.scanner, obs.observation_id)


def dedupe_findings(
    observations: Iterable[Observation],
    resolver: IdentityResolver,
    detected_at: datetime,
) -> DedupResult:
    """Group one engagement's vuln_candidate observations into Findings."""
    groups: dict[str, list[Observation]] = defaultdict(list)
    meta: dict[str, tuple[str, tuple[str, ...]]] = {}
    resolutions: dict[str, dict[str, Resolution]] = defaultdict(dict)
    unresolved: set[str] = set()
    seen: set[str] = set()
    for obs in observations:
        if obs.kind != ObservationKind.VULN_CANDIDATE or obs.observation_id in seen:
            continue
        seen.add(obs.observation_id)
        asset = resolver.resolve_observation(obs)
        if asset is None:
            unresolved.add(obs.observation_id)
            continue
        rule, key = merge_key(obs, asset.asset_id)
        fid = finding_id_for(key)
        groups[fid].append(obs)
        meta.setdefault(fid, (rule, key))
        resolutions[fid].setdefault(asset.alias, asset)

    findings: list[Finding] = []
    merges: list[MergeRecord] = []
    for fid, group in groups.items():
        group.sort(key=_evidence_order)
        rule, key = meta[fid]
        asset_id = key[1]
        group_res = [resolutions[fid][alias] for alias in sorted(resolutions[fid])]
        engagement_ids = {o.engagement_id for o in group}
        if len(engagement_ids) != 1:
            raise ValueError(f"finding {fid} would span engagements {sorted(engagement_ids)}")
        cve_ids = cve_ids_of(group[0])
        obs_ids = sorted(o.observation_id for o in group)
        scanners = sorted({o.scanner for o in group})
        findings.append(
            Finding(
                finding_id=fid,
                engagement_id=group[0].engagement_id,
                asset_id=asset_id,
                scanner=",".join(scanners),
                cve_ids=cve_ids,
                title=_title(group[0], cve_ids)[:500],
                description=_description(group, group_res)[:2000],
                observation_ids=obs_ids,
                detected_at=detected_at,
            )
        )
        merges.append(
            MergeRecord(
                finding_id=fid,
                rule=rule,
                key=key,
                asset_id=asset_id,
                resolutions=tuple(group_res),
                observation_ids=tuple(obs_ids),
                scanners=tuple(scanners),
            )
        )
    findings.sort(key=lambda f: (f.asset_id, f.finding_id))
    merges.sort(key=lambda m: (m.asset_id, m.finding_id))
    return DedupResult(
        findings=findings, merges=merges, unresolved_observation_ids=sorted(unresolved)
    )
