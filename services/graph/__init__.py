"""Deterministic attack-path engine (Layer 3).

The language model never creates edges (CLAUDE.md, Hard Rule 1). Everything in this
package is a pure function of observed facts, the declared topology and the rule data
in `rules/`.
"""

from services.graph.builder import AttackGraph, build_attack_graph
from services.graph.engine import (
    analyze,
    enumerate_paths,
    find_chokepoints,
    simulate_remediation,
)
from services.graph.ruleset import RuleSet, load_ruleset

__all__ = [
    "AttackGraph",
    "RuleSet",
    "analyze",
    "build_attack_graph",
    "enumerate_paths",
    "find_chokepoints",
    "load_ruleset",
    "simulate_remediation",
]
