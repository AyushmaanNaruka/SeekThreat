"""Deployment wiring for Layer 2 enrichment.

- Every queue the Celery app routes a task to must be consumed by the worker
  that docker-compose starts; otherwise ``.delay()`` enqueues jobs nobody runs.
- The ``enrichment_cache_dir`` setting reaches every EnrichmentService the API
  constructs, so the local feed mirrors are actually used in deployment.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from apps.api.core.config import Settings
from apps.api.worker import celery_app

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "infra" / "docker-compose.yml"


def _worker_command() -> str:
    """Return the `command:` of the `worker` service in docker-compose.yml.

    Parsed with a small line scanner rather than a YAML library so the test
    adds no dependency; the compose file keeps services at two-space indent.
    """
    lines = COMPOSE_FILE.read_text(encoding="utf-8").splitlines()
    in_worker = False
    for line in lines:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            in_worker = line.strip() == "worker:"
            continue
        if in_worker:
            match = re.match(r"^    command:\s*(.+)$", line)
            if match:
                return match.group(1).strip()
    raise AssertionError("worker service command not found in docker-compose.yml")


def _consumed_queues(command: str) -> set[str]:
    tokens = shlex.split(command)
    queues: set[str] = set()
    for i, token in enumerate(tokens):
        if token.startswith("--queues="):
            queues.update(q for q in token.split("=", 1)[1].split(",") if q)
        elif token in ("--queues", "-Q") and i + 1 < len(tokens):
            queues.update(q for q in tokens[i + 1].split(",") if q)
    return queues


def test_compose_worker_consumes_every_routed_queue() -> None:
    routes: dict[str, dict[str, Any]] = celery_app.conf.task_routes
    routed_queues = {route["queue"] for route in routes.values()}
    assert routed_queues, "celery task_routes is empty -- probe would pass vacuously"

    consumed = _consumed_queues(_worker_command())
    missing = routed_queues - consumed
    assert not missing, (
        f"docker-compose worker does not consume queue(s) {sorted(missing)}; tasks routed "
        f"there would never run. Worker consumes: {sorted(consumed)}"
    )


def test_worker_module_docstring_names_every_routed_queue() -> None:
    import apps.api.worker as worker

    doc = worker.__doc__ or ""
    match = re.search(r"--queues=(\S+)", doc)
    assert match, "worker docstring no longer shows the worker start command"
    documented = set(match.group(1).split(","))
    routed = {route["queue"] for route in celery_app.conf.task_routes.values()}
    assert routed <= documented


def test_enrichment_cache_dir_defaults_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENRICHMENT_CACHE_DIR", raising=False)
    assert Settings(_env_file=None).enrichment_cache_dir is None  # type: ignore[call-arg]


def test_enrichment_cache_dir_reads_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ENRICHMENT_CACHE_DIR", str(tmp_path))
    assert Settings(_env_file=None).enrichment_cache_dir == tmp_path  # type: ignore[call-arg]


def test_celery_task_passes_cache_dir_to_enrichment_service(tmp_path: Path) -> None:
    from apps.api.tasks import enrichment as task_module
    from tests.fixtures.findings.baseline_findings import ENGAGEMENT_ID, FINDING_LOG4SHELL

    fake_service = MagicMock()
    fake_service.enrich_batch.return_value = []
    with (
        patch.object(task_module.settings, "enrichment_cache_dir", tmp_path),
        patch.object(task_module, "SessionLocal", return_value=MagicMock()),
        patch.object(task_module, "EnrichmentService", return_value=fake_service) as ctor,
    ):
        task_module.run_enrichment(
            [FINDING_LOG4SHELL.model_dump(mode="json")], engagement_id=ENGAGEMENT_ID
        )

    assert ctor.call_args.kwargs["cache_dir"] == tmp_path


def test_router_passes_cache_dir_to_enrichment_service(tmp_path: Path) -> None:
    from apps.api.routers import findings as router_module

    with (
        patch.object(router_module.settings, "enrichment_cache_dir", tmp_path),
        patch.object(router_module, "EnrichmentService") as ctor,
    ):
        router_module._build_service(MagicMock())

    assert ctor.call_args.kwargs["cache_dir"] == tmp_path
