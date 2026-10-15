"""Interim observation -> Finding bridge (DECISIONS.md D-044).

Until Track 1's normalizer lands, nothing turned a scan's observations into findings,
so enrichment had nothing to enrich. This bridge is deliberately minimal and
deterministic:

- one Finding per distinct `vuln_candidate` observation; other kinds are facts, not
  vulnerabilities, and are left alone;
- `asset_id` follows the D-040 contract (`host:<canonical ip>` or `host:<lowercase fqdn>`),
  taken from the observation's nmap-style `endpoint` attribute (`<ip>:<port>/tcp`);
- `cve_ids` are only the canonical CVE IDs the scanner itself reported, never inferred;
- `finding_id` hashes what was found (scanner, asset, endpoint, the scanner's own
  identity keys), not the observation id, so a re-scan upserts the same finding instead
  of duplicating it.

No cross-scanner deduplication or asset joining happens here; that is Track 1's job.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable
from datetime import datetime
from urllib.parse import urlsplit

from packages.schema.models.finding import CVE_ID_PATTERN, Finding
from packages.schema.models.observation import Observation, ObservationKind

# Attribute keys that identify *what* a scanner found, in a fixed order. Volatile values
# (timestamps, banners, curl commands) are excluded so a re-scan hashes identically.
_IDENTITY_KEYS = (
    "template_id",
    "matcher_name",
    "nikto_id",
    "method",
    "url",
    "finding_type",
    "category",
    "algorithm",
    "cve_ids",
)


def _host_from(observation: Observation) -> str | None:
    """Return the canonical host (IP or lowercase hostname) an observation is about."""
    endpoint = observation.attributes.get("endpoint") or observation.subject
    candidate = endpoint.strip()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    elif "/" in candidate:
        # nmap spelling "<ip>:<port>/tcp"; IPv6 is written unbracketed, so split the
        # port off the right-hand side only.
        candidate = candidate.split("/", 1)[0].rsplit(":", 1)[0]
    elif candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        # Bare "<host>:<port>" (some nuclei records carry no endpoint attribute).
        candidate = candidate.rsplit(":", 1)[0]
    candidate = candidate.strip("[]")
    if not candidate or candidate == "unknown":
        # nuclei_json uses "unknown" when a record names no host at all.
        return None
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return candidate.lower()


def _cve_ids(observation: Observation) -> list[str]:
    raw = observation.attributes.get("cve_ids", "")
    out: list[str] = []
    for part in raw.split(","):
        norm = part.strip().upper()
        if CVE_ID_PATTERN.fullmatch(norm) and norm not in out:
            out.append(norm)
    return out


def _title(observation: Observation, cve_ids: list[str]) -> str:
    a = observation.attributes
    if a.get("template_name"):
        # One template can fire several matchers (e.g. one per missing header).
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


def _description(observation: Observation) -> str:
    a = observation.attributes
    parts = [a[k] for k in ("description", "notes", "recommendation") if a.get(k)]
    if a.get("url"):
        parts.append(f"URL: {a['url']}")
    # Finding has no confidence field, so carry the scanner's own confidence and note
    # here: a low-confidence, banner-inferred CVE must not read as a confirmed one.
    prov = observation.provenance
    confidence = f"Scanner confidence: {prov.confidence.value}"
    if prov.note:
        confidence += f" ({prov.note})"
    parts.append(confidence)
    return " | ".join(parts)


def _finding_id(observation: Observation, asset_id: str) -> str:
    a = observation.attributes
    key = "\x1f".join(
        [observation.scanner, asset_id, a.get("endpoint", observation.subject)]
        + [f"{k}={a[k]}" for k in _IDENTITY_KEYS if a.get(k)]
    )
    return "fnd-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def findings_from_observations(
    observations: Iterable[Observation], detected_at: datetime
) -> list[Finding]:
    """Build one Finding per distinct vuln_candidate observation, in a stable order."""
    by_id: dict[str, Finding] = {}
    for obs in observations:
        if obs.kind != ObservationKind.VULN_CANDIDATE:
            continue
        host = _host_from(obs)
        if host is None:
            continue
        asset_id = f"host:{host}"
        finding_id = _finding_id(obs, asset_id)
        existing = by_id.get(finding_id)
        if existing is not None:
            # Same thing reported twice in one scan: one finding, both observations.
            existing.observation_ids.append(obs.observation_id)
            continue
        cve_ids = _cve_ids(obs)
        by_id[finding_id] = Finding(
            finding_id=finding_id,
            engagement_id=obs.engagement_id,
            asset_id=asset_id,
            scanner=obs.scanner,
            cve_ids=cve_ids,
            title=_title(obs, cve_ids)[:500],
            description=_description(obs)[:2000],
            observation_ids=[obs.observation_id],
            detected_at=detected_at,
        )
    return sorted(by_id.values(), key=lambda f: (f.asset_id, f.finding_id))
