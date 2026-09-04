"""Proves the repository root is importable from tests."""

import packages.schema  # noqa: F401
import services.scanners  # noqa: F401


def test_repository_root_is_importable() -> None:
    assert packages.schema is not None
