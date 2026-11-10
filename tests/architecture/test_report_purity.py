"""The report builder is a pure function of stored facts and engine output (D-049).

services/report may import the standard library's pure modules, pydantic,
packages.schema, services.graph (pure itself) and its own package. No database, no
HTTP, no model client, no clock: the caller passes `generated_at`, so the same inputs
always render to the same bytes. services.assistant is forbidden too: narrations arrive
as `PathNarration` data, never by calling the model from here.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "services" / "report"

ALLOWED_INTERNAL = ("packages.schema", "services.graph", "services.report")
STDLIB_OK = {
    "__future__",
    "collections",
    "collections.abc",
    "datetime",
    "hashlib",
    "ipaddress",
    "json",
    "re",
    "typing",
}
ALLOWED_THIRD_PARTY = {"pydantic"}
FORBIDDEN_CALLS = {"now", "utcnow", "today", "time", "random", "uuid4"}


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
    return (
        name.startswith(ALLOWED_INTERNAL)
        or name in STDLIB_OK
        or name.split(".")[0] in ALLOWED_THIRD_PARTY
    )


def test_checker_rejects_forbidden_imports() -> None:
    for bad in ("apps.api.db", "services.assistant", "sqlalchemy", "httpx", "time", "socket"):
        assert not _allowed(bad), bad
    for good in ("packages.schema.models.graph", "services.graph.builder", "json"):
        assert _allowed(good), good


def test_report_package_exists() -> None:
    assert len(list(REPORT.glob("*.py"))) >= 3, "services/report is missing; test is vacuous"


def test_report_imports_only_pure_dependencies() -> None:
    violations = [
        f"{f.name}: {name}"
        for f in sorted(REPORT.rglob("*.py"))
        for name in _imports(f)
        if not _allowed(name)
    ]
    assert violations == [], "services/report must stay pure:\n" + "\n".join(violations)


def test_report_reads_no_clock_or_randomness() -> None:
    violations: list[str] = []
    for py_file in sorted(REPORT.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in FORBIDDEN_CALLS
            ):
                violations.append(f"{py_file.name}:{node.lineno} .{node.func.attr}()")
    assert violations == [], "\n".join(violations)
