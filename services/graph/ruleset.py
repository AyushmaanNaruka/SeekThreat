"""Load the rule and capability data files (DECISIONS.md D-004: rules are data)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from packages.schema.models.graph import Rule
from packages.schema.models.provenance import Confidence

RULES_DIR = Path(__file__).resolve().parent / "rules"

CODE_EXECUTION = "code_execution"
FILE_READ = "file_read"
CAPABILITIES = (CODE_EXECUTION, FILE_READ)
_CRLF, _LF = bytes([13, 10]), bytes([10])


@dataclass(frozen=True)
class CapabilitySignal:
    """One way of recognising a capability: a set of identifiers and the confidence a
    match supports."""

    kind: str  # "scanner_tag" or "cwe"
    confidence: Confidence
    code_execution: frozenset[str]
    file_read: frozenset[str]

    def ids_for(self, capability: str) -> frozenset[str]:
        return self.code_execution if capability == CODE_EXECUTION else self.file_read


@dataclass(frozen=True)
class RuleSet:
    rules: dict[str, Rule]
    remote_login_services: frozenset[str]
    signals: tuple[CapabilitySignal, ...]
    digest: str
    # Finding.scanner -> the highest confidence an edge built on such a finding may have.
    derived_finding_caps: dict[str, Confidence] = field(default_factory=dict)

    def rule(self, name: str) -> Rule:
        return self.rules[name]


def _upper_set(values: Any) -> frozenset[str]:
    return frozenset(str(v).strip().upper() for v in (values or []))


def _lower_set(values: Any) -> frozenset[str]:
    return frozenset(str(v).strip().lower() for v in (values or []))


def load_ruleset(rules_dir: Path = RULES_DIR) -> RuleSet:
    """Parse `core.yaml` and `capabilities.yaml`. The digest covers both files' contents, so
    a result can cite exactly which rule data produced it."""
    # Line endings are normalised so a Windows (CRLF) checkout of the same rules gives
    # the same digest as a Unix one.
    core_bytes = (rules_dir / "core.yaml").read_bytes().replace(_CRLF, _LF)
    cap_bytes = (rules_dir / "capabilities.yaml").read_bytes().replace(_CRLF, _LF)
    core = yaml.safe_load(core_bytes)
    caps = yaml.safe_load(cap_bytes)

    rules: dict[str, Rule] = {}
    for raw in core["rules"]:
        rule = Rule(
            name=raw["name"],
            description=" ".join(str(raw["description"]).split()),
            preconditions=tuple(
                {str(k): str(v) for k, v in pre.items()} for pre in raw["preconditions"]
            ),
            effect=raw["effect"],
            citation=raw.get("citation"),
            confidence=Confidence(raw["confidence"]),
            assumption=" ".join(str(raw["assumption"]).split()) if raw.get("assumption") else None,
        )
        if rule.name in rules:
            raise ValueError(f"duplicate rule name {rule.name!r}")
        rules[rule.name] = rule

    signals: list[CapabilitySignal] = []
    tags = caps["scanner_tags"]
    signals.append(
        CapabilitySignal(
            kind="scanner_tag",
            confidence=Confidence(tags["confidence"]),
            code_execution=_lower_set(tags.get(CODE_EXECUTION)),
            file_read=_lower_set(tags.get(FILE_READ)),
        )
    )
    for block in caps["cwe"]:
        signals.append(
            CapabilitySignal(
                kind="cwe",
                confidence=Confidence(block["confidence"]),
                code_execution=_upper_set(block.get(CODE_EXECUTION)),
                file_read=_upper_set(block.get(FILE_READ)),
            )
        )

    digest = hashlib.sha256(core_bytes + b"\x00" + cap_bytes).hexdigest()
    return RuleSet(
        rules=rules,
        remote_login_services=_lower_set(core.get("remote_login_services")),
        signals=tuple(signals),
        digest=f"rules:sha256:{digest[:24]}",
        derived_finding_caps={
            str(scanner).strip().lower(): Confidence(cap)
            for scanner, cap in (caps.get("derived_findings") or {}).items()
        },
    )
