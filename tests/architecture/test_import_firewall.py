"""The language model never creates graph edges.

services/assistant may import packages.schema and nothing else from this tree,
so it structurally cannot reach the code that constructs edges.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ASSISTANT = REPO_ROOT / "services" / "assistant"

FORBIDDEN_PREFIXES = (
    "services.graph",
    "services.enrichment",
    "services.scanners",
    "services.normalize",
    "apps.api",
)


def _absolute_module(node: ast.ImportFrom, module_path: Path) -> str:
    """Resolve a possibly-relative ImportFrom to a dotted module name."""
    if node.level == 0:
        return node.module or ""
    package_parts = module_path.relative_to(REPO_ROOT).parts[:-1]
    keep = len(package_parts) - (node.level - 1)
    base = list(package_parts[:keep]) if keep > 0 else []
    if node.module:
        base.append(node.module)
    return ".".join(base)


def forbidden_imports_in(path: Path) -> list[str]:
    """Return every forbidden module imported by the Python files under `path`."""
    violations: list[str] = []
    for py_file in sorted(path.rglob("*.py")):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [_absolute_module(node, py_file)]
            else:
                continue
            for name in names:
                if any(
                    name == prefix or name.startswith(prefix + ".") for prefix in FORBIDDEN_PREFIXES
                ):
                    try:
                        rel = py_file.relative_to(REPO_ROOT)
                    except ValueError:
                        # py_file lives outside REPO_ROOT (e.g. a tmp_path
                        # fixture in a self-test) — fall back to the raw path.
                        rel = py_file
                    violations.append(f"{rel}: imports {name}")
    return violations


def test_assistant_package_exists() -> None:
    """Without this, the firewall test would pass over an empty tree."""
    assert ASSISTANT.is_dir(), "services/assistant is missing; the firewall test is vacuous"
    assert (ASSISTANT / "__init__.py").exists()


def test_assistant_imports_nothing_it_should_not() -> None:
    violations = forbidden_imports_in(ASSISTANT)
    assert violations == [], (
        "services/assistant must not import graph, enrichment or scanner code — "
        "the model narrates proven paths, it never builds them.\n" + "\n".join(violations)
    )


def test_checker_detects_a_planted_violation(tmp_path: Path) -> None:
    """A checker that always returns [] would pass silently. Prove it bites."""
    offender = tmp_path / "bad.py"
    offender.write_text(
        "from services.graph.builder import build_graph\nimport services.enrichment\n",
        encoding="utf-8",
    )
    violations = forbidden_imports_in(tmp_path)
    assert len(violations) == 2
    assert any("services.graph.builder" in v for v in violations)
    assert any("services.enrichment" in v for v in violations)


def test_checker_allows_the_schema(tmp_path: Path) -> None:
    good = tmp_path / "good.py"
    good.write_text(
        "from packages.schema import AttackPath, Citation\nimport packages.schema\n",
        encoding="utf-8",
    )
    assert forbidden_imports_in(tmp_path) == []
