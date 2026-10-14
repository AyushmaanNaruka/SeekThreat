"""Suite-wide test fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _no_real_post_scan_dispatch(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    """Never publish the post-scan enrichment task to a real broker from a test.

    A completed scan dispatches ``sync_new_findings_cves.apply_async``. Unpatched,
    every scan happy-path test would try to reach Redis (and be slow or flaky
    depending on whether one happens to be running). Tests that exercise the
    dispatcher patch the task themselves; this only replaces ``apply_async``.
    """
    from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves

    mock = MagicMock(name="sync_new_findings_cves.apply_async")
    monkeypatch.setattr(sync_new_findings_cves, "apply_async", mock)
    yield mock
