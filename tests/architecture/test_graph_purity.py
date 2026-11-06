"""The graph engine is a pure function of facts (Hard Rule 1, docs/02-architecture.md).

services/graph may import only the standard library, networkx, yaml, packages.schema and
itself. No model client, no HTTP, no sockets, no database, no clock: the same facts must
always produce the same paths, and nothing but named rules may create an edge.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GRAPH = REPO_ROOT / "services" / "graph"

ALLOWED_THIRD_PARTY = {"networkx", "yaml", "pydantic"}
ALLOWED_INTERNAL = ("packages.schema", "services.graph")
FORBIDDEN_STDLIB = {
    "socket",
    "http",
    "urllib.request",
    "subprocess",
    "random",
    "time",
    "sqlite3",
    "asyncio",
}
FORBIDDEN_CALLS = {"now", "utcnow", "today", "time", "random", "uuid4"}
STDLIB_OK = {
    "__future__",
    "collections",
    "dataclasses",
    "enum",
    "hashlib",
    "ipaddress",
    "json",
    "pathlib",
    "re",
    "typing",
    "urllib.parse",
    "urllib",
}


def _imports(py_file: Path) -> list[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.append(node.module)
    return names


def _allowed(name: str) -> bool:
    top = name.split(".")[0]
    if name in FORBIDDEN_STDLIB or top in FORBIDDEN_STDLIB:
        return False
    return (
        name.startswith(ALLOWED_INTERNAL)
        or top in ALLOWED_THIRD_PARTY
        or name in STDLIB_OK
        or top in STDLIB_OK
    )


def test_checker_rejects_forbidden_imports() -> None:
    """A checker that allows everything would pass silently. Prove it bites."""
    for bad in ("socket", "urllib.request", "httpx", "services.assistant", "apps.api.db"):
        assert not _allowed(bad), bad
    for good in ("networkx", "packages.schema.models.graph", "urllib.parse", "hashlib"):
        assert _allowed(good), good


def test_graph_package_exists_and_has_code() -> None:
    assert len(list(GRAPH.rglob("*.py"))) >= 4, "services/graph is empty; this test is vacuous"


def test_graph_imports_only_pure_dependencies() -> None:
    violations: list[str] = []
    for py_file in sorted(GRAPH.rglob("*.py")):
        for name in _imports(py_file):
            if not _allowed(name):
                violations.append(f"{py_file.name}: {name}")
    assert violations == [], "services/graph must stay pure:\n" + "\n".join(violations)


def test_graph_reads_no_clock_or_randomness() -> None:
    violations: list[str] = []
    for py_file in sorted(GRAPH.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in FORBIDDEN_CALLS
            ):
                violations.append(f"{py_file.name}:{node.lineno} .{node.func.attr}()")
    assert violations == [], "\n".join(violations)
