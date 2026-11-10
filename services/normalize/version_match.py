"""Version-match CVE candidates from nmap service-version facts (DECISIONS.md D-049, Proposed).

nmap's parser deliberately emits no vulnerability observations; matching a product and
version to CVEs is our job (services/scanners/nmap_xml.py docstring). This module does it,
deterministically, from rule data in `rules/version_cves.yaml`:

- input is `service_version` observations only, and only those whose own provenance is
  not LOW (nmap `conf` >= 7). A guessed version is not matched;
- a rule fires when the product (or CPE vendor:product) is listed and the version is a
  purely numeric dotted string inside one of the rule's half-open intervals. Anything
  non-numeric is skipped, never guessed;
- each match becomes one `Finding` with `scanner="version-match"`, citing exactly the
  service_version observation it was derived from. Its description names the rule id, the
  interval, the reference, the rule-data digest and the confidence (always LOW, because a
  banner match is not proof: banners lie and distributions backport fixes).

The finding carries no CWE ids or tags of its own. What it lets an attacker do is decided
by the graph engine from enrichment's fused `cwe_ids` for the CVE, and the engine caps
every edge built on a version-match finding at LOW (capabilities.yaml `derived_findings`).

Pure: no clock (the caller passes `detected_at`), no network, no randomness.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from packages.schema.models.finding import CVE_ID_PATTERN, Finding
from packages.schema.models.observation import Observation, ObservationKind
from packages.schema.models.provenance import Confidence
from services.normalize.interim_bridge import _host_from

VERSION_MATCH_SCANNER = "version-match"
VERSION_MATCH_CONFIDENCE = Confidence.LOW
RULES_PATH = Path(__file__).resolve().parent / "rules" / "version_cves.yaml"

_NUMERIC_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*", re.ASCII)
_CRLF, _LF = bytes([13, 10]), bytes([10])

Version = tuple[int, ...]


def parse_version(text: str) -> Version | None:
    """A purely numeric dotted version as a tuple, or None for anything else."""
    text = text.strip()
    if not _NUMERIC_VERSION.fullmatch(text):
        return None
    return tuple(int(p) for p in text.split("."))


def _cmp(a: Version, b: Version) -> int:
    width = max(len(a), len(b))
    pa, pb = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)


@dataclass(frozen=True)
class Interval:
    introduced: str
    fixed: str

    def contains(self, version: Version) -> bool:
        low, high = parse_version(self.introduced), parse_version(self.fixed)
        if low is None or high is None:  # rejected at load time; defensive
            return False
        return _cmp(version, low) >= 0 and _cmp(version, high) < 0

    def __str__(self) -> str:
        return f">= {self.introduced}, < {self.fixed}"


@dataclass(frozen=True)
class VersionRule:
    rule_id: str
    cve: str
    products: frozenset[str]
    cpes: frozenset[str]
    affected: tuple[Interval, ...]
    reference: str
    verified: bool

    def interval_for(self, version: Version) -> Interval | None:
        for interval in self.affected:
            if interval.contains(version):
                return interval
        return None


@dataclass(frozen=True)
class VersionRuleSet:
    rules: tuple[VersionRule, ...]
    digest: str


def _norm_product(text: str) -> str:
    return " ".join(text.lower().split())


def _parse_rules(raw: Any, digest: str) -> VersionRuleSet:
    rules: list[VersionRule] = []
    seen: set[str] = set()
    for entry in raw["rules"]:
        rule_id = str(entry["id"])
        if rule_id in seen:
            raise ValueError(f"duplicate version rule id {rule_id!r}")
        seen.add(rule_id)
        cve = str(entry["cve"]).strip().upper()
        if not CVE_ID_PATTERN.fullmatch(cve):
            raise ValueError(f"version rule {rule_id!r}: invalid CVE id {cve!r}")
        intervals: list[Interval] = []
        for item in entry["affected"]:
            interval = Interval(introduced=str(item["introduced"]), fixed=str(item["fixed"]))
            low, high = parse_version(interval.introduced), parse_version(interval.fixed)
            if low is None or high is None or _cmp(low, high) >= 0:
                raise ValueError(f"version rule {rule_id!r}: bad interval {interval}")
            intervals.append(interval)
        if not intervals:
            raise ValueError(f"version rule {rule_id!r} lists no affected interval")
        products = frozenset(_norm_product(str(p)) for p in entry.get("products") or [])
        cpes = frozenset(str(c).strip().lower() for c in entry.get("cpes") or [])
        if not products and not cpes:
            raise ValueError(f"version rule {rule_id!r} names no product or CPE")
        rules.append(
            VersionRule(
                rule_id=rule_id,
                cve=cve,
                products=products,
                cpes=cpes,
                affected=tuple(intervals),
                reference=str(entry["reference"]),
                verified=bool(entry.get("verified", False)),
            )
        )
    return VersionRuleSet(rules=tuple(rules), digest=digest)


def load_version_rules(path: Path = RULES_PATH) -> VersionRuleSet:
    """Parse the rule file. The digest is over its contents (line endings normalised),
    so every derived finding can cite exactly which rule data produced it."""
    content = path.read_bytes().replace(_CRLF, _LF)
    digest = "version-rules:sha256:" + hashlib.sha256(content).hexdigest()[:24]
    return _parse_rules(yaml.safe_load(content), digest)


@lru_cache(maxsize=1)
def _default_rules() -> VersionRuleSet:
    return load_version_rules()


def _cpe_products(cpe_attr: str) -> set[str]:
    """`vendor:product` pairs from nmap's comma-joined CPE 2.2 strings (cpe:/a:v:p:ver)."""
    out: set[str] = set()
    for cpe in cpe_attr.split(","):
        parts = cpe.strip().lower().split(":")
        if len(parts) >= 4 and parts[0] == "cpe" and parts[1] in {"/a", "/o", "/h"}:
            out.add(f"{parts[2]}:{parts[3]}")
    return out


@dataclass(frozen=True)
class VersionMatch:
    rule: VersionRule
    interval: Interval
    observation: Observation
    product: str
    version: str
    matched_on: str  # "product" or "cpe"


def match_observation(obs: Observation, ruleset: VersionRuleSet) -> list[VersionMatch]:
    """Every rule the service_version observation matches, in rule-file order."""
    if obs.kind != ObservationKind.SERVICE_VERSION:
        return []
    if obs.provenance.confidence == Confidence.LOW:
        return []
    attrs = obs.attributes
    version_text = attrs.get("version", "").strip()
    version = parse_version(version_text)
    if version is None:
        return []
    product = _norm_product(attrs.get("product", ""))
    cpe_products = _cpe_products(attrs.get("cpe", ""))
    matches: list[VersionMatch] = []
    for rule in ruleset.rules:
        if product and product in rule.products:
            matched_on = "product"
        elif cpe_products & rule.cpes:
            matched_on = "cpe"
        else:
            continue
        interval = rule.interval_for(version)
        if interval is not None:
            matches.append(
                VersionMatch(
                    rule=rule,
                    interval=interval,
                    observation=obs,
                    product=attrs.get("product", "") or product,
                    version=version_text,
                    matched_on=matched_on,
                )
            )
    return matches


def _finding_id(asset_id: str, endpoint: str, rule_id: str, cve: str) -> str:
    key = "\x1f".join([VERSION_MATCH_SCANNER, asset_id, endpoint, rule_id, cve])
    return "fnd-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def _description(match: VersionMatch, digest: str) -> str:
    rule = match.rule
    verified = "verified" if rule.verified else "NOT yet verified against the advisory"
    return " | ".join(
        [
            (
                f"Derived by rule {rule.rule_id} ({VERSION_MATCH_SCANNER}): "
                f"{match.product} {match.version} on {match.observation.subject} "
                f"(matched on {match.matched_on}) is in the affected range "
                f"{match.interval} for {rule.cve}"
            ),
            f"Reference: {rule.reference} (rule range {verified})",
            (
                "Not observed: a version banner can be wrong and distributions backport "
                "fixes, so this is a candidate, not a confirmed vulnerability"
            ),
            f"Derived from observation {match.observation.observation_id}",
            f"Rule data: {digest}",
            f"Source: {VERSION_MATCH_SCANNER}; confidence: {VERSION_MATCH_CONFIDENCE.value}",
        ]
    )


def version_match_findings(
    observations: Iterable[Observation],
    detected_at: datetime,
    ruleset: VersionRuleSet | None = None,
) -> list[Finding]:
    """One Finding per (service endpoint, matched rule), in a stable order."""
    rules = ruleset or _default_rules()
    by_id: dict[str, Finding] = {}
    for obs in sorted(observations, key=lambda o: o.observation_id):
        for match in match_observation(obs, rules):
            host = _host_from(obs)
            if host is None:
                continue
            asset_id = f"host:{host}"
            finding_id = _finding_id(asset_id, obs.subject, match.rule.rule_id, match.rule.cve)
            existing = by_id.get(finding_id)
            if existing is not None:
                # The same service version seen twice (e.g. two scans in one batch).
                if obs.observation_id not in existing.observation_ids:
                    existing.observation_ids.append(obs.observation_id)
                continue
            by_id[finding_id] = Finding(
                finding_id=finding_id,
                engagement_id=obs.engagement_id,
                asset_id=asset_id,
                scanner=VERSION_MATCH_SCANNER,
                cve_ids=[match.rule.cve],
                title=(
                    f"{match.rule.cve}: {match.product} {match.version} in affected "
                    f"version range (version match, unconfirmed)"
                )[:500],
                description=_description(match, rules.digest)[:2000],
                observation_ids=[obs.observation_id],
                detected_at=detected_at,
            )
    return sorted(by_id.values(), key=lambda f: (f.asset_id, f.finding_id))


def version_match_cve_ids(
    observations: Iterable[Observation], ruleset: VersionRuleSet | None = None
) -> list[str]:
    """The CVE ids version matching would derive, sorted, for targeted feed sync."""
    rules = ruleset or _default_rules()
    return sorted({m.rule.cve for obs in observations for m in match_observation(obs, rules)})


__all__ = [
    "VERSION_MATCH_CONFIDENCE",
    "VERSION_MATCH_SCANNER",
    "VersionMatch",
    "VersionRule",
    "VersionRuleSet",
    "load_version_rules",
    "match_observation",
    "parse_version",
    "version_match_cve_ids",
    "version_match_findings",
]
