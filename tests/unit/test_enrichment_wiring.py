"""Deployment wiring for Layer 2 enrichment.

- Every queue the Celery app routes a task to must be consumed by some worker
  that docker-compose starts; otherwise ``.delay()`` enqueues jobs nobody runs.
- Slow upstream feed lookups (``enrichment`` queue) run on their own single-slot
  worker, never on the scan worker, so they cannot starve scans.
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


def _service_commands() -> dict[str, str]:
    """Map compose service name -> its `command:` line.

    Parsed with a small line scanner rather than a YAML library so the test
    adds no dependency; the compose file keeps services at two-space indent.
    """
    commands: dict[str, str] = {}
    current: str | None = None
    for line in COMPOSE_FILE.read_text(encoding="utf-8").splitlines():
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            current = header.group(1)
            continue
        if re.match(r"^\S", line):
            current = None
            continue
        match = re.match(r"^    command:\s*(.+)$", line)
        if current and match:
            commands[current] = match.group(1).strip()
    return commands


def _worker_commands() -> dict[str, str]:
    """Compose services that run a Celery worker."""
    return {
        name: cmd
        for name, cmd in _service_commands().items()
        if "celery" in cmd and " worker" in f" {cmd}"
    }


def _consumed_queues(command: str) -> set[str]:
    tokens = shlex.split(command)
    queues: set[str] = set()
    for i, token in enumerate(tokens):
        if token.startswith("--queues="):
            queues.update(q for q in token.split("=", 1)[1].split(",") if q)
        elif token in ("--queues", "-Q") and i + 1 < len(tokens):
            queues.update(q for q in tokens[i + 1].split(",") if q)
    return queues


def test_compose_workers_consume_every_routed_queue() -> None:
    routes: dict[str, dict[str, Any]] = celery_app.conf.task_routes
    routed_queues = {route["queue"] for route in routes.values()}
    assert routed_queues, "celery task_routes is empty -- probe would pass vacuously"

    workers = _worker_commands()
    assert workers, "docker-compose starts no celery worker"
    consumed: set[str] = set()
    for cmd in workers.values():
        consumed |= _consumed_queues(cmd)
    missing = routed_queues - consumed
    assert not missing, (
        f"no docker-compose worker consumes queue(s) {sorted(missing)}; tasks routed "
        f"there would never run. Workers consume: {sorted(consumed)}"
    )


def test_enrichment_queue_has_a_dedicated_single_slot_worker() -> None:
    """Post-scan sync and the beat sync share one slot: no concurrent upstream storms,
    and a long NVD crawl never holds a scan worker process."""
    workers = _worker_commands()
    assert "enrichment-worker" in workers
    enrichment = workers["enrichment-worker"]
    assert _consumed_queues(enrichment) == {"enrichment"}
    tokens = shlex.split(enrichment)
    assert "--concurrency=1" in tokens or (
        "--concurrency" in tokens and tokens[tokens.index("--concurrency") + 1] == "1"
    )
    assert "enrichment" not in _consumed_queues(workers["worker"])


def test_every_enrichment_task_is_routed_to_the_enrichment_queue() -> None:
    routes = celery_app.conf.task_routes
    for name in (
        "seekthreat.enrichment.enrich",
        "seekthreat.sync_feeds.run",
        "seekthreat.enrichment.sync_new_findings_cves",
    ):
        assert routes[name]["queue"] == "enrichment", name


def test_worker_module_docstring_names_every_routed_queue() -> None:
    import apps.api.worker as worker

    doc = worker.__doc__ or ""
    match = re.search(r"--queues=(\S+)", doc)
    assert match, "worker docstring no longer shows the worker start command"
    documented = set(match.group(1).split(","))
    routed = {route["queue"] for route in celery_app.conf.task_routes.values()}
    assert routed <= documented


def test_enrichment_cache_dir_defaults_to_feed_syncer_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Readers (API/worker) and the writer (FeedSyncer) must resolve the same directory."""
    from services.enrichment.sources.sync import FeedSyncer, get_default_cache_dir

    monkeypatch.delenv("ENRICHMENT_CACHE_DIR", raising=False)
    default = Settings(_env_file=None).enrichment_cache_dir  # type: ignore[call-arg]
    assert default == get_default_cache_dir()
    assert FeedSyncer(cache_dir=None).cache_dir == default


def _service_block(name: str) -> list[str]:
    """Lines of one top-level compose service (two-space indent convention)."""
    lines = COMPOSE_FILE.read_text(encoding="utf-8").splitlines()
    block: list[str] = []
    inside = False
    for line in lines:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line) or re.match(r"^\S", line):
            inside = line.strip() == f"{name}:"
            continue
        if inside:
            block.append(line)
    return block


def test_compose_runs_celery_beat() -> None:
    block = "\n".join(_service_block("beat"))
    assert block, "docker-compose has no beat service; the daily feed sync never fires"
    assert "celery -A apps.api.worker" in block and " beat" in block


def test_compose_shares_one_enrichment_cache_volume() -> None:
    for service in ("api", "worker", "enrichment-worker", "beat"):
        block = "\n".join(_service_block(service))
        assert "ENRICHMENT_CACHE_DIR: /data/enrichment_cache" in block, service
        assert "enrichmentcache:/data/enrichment_cache" in block, service
    top_level = COMPOSE_FILE.read_text(encoding="utf-8")
    assert re.search(r"^volumes:(?:\n  .*)*\n  enrichmentcache:", top_level, re.MULTILINE)


def test_beat_schedule_is_daily_at_0200_utc() -> None:
    from celery.schedules import crontab

    entry = celery_app.conf.beat_schedule["sync-enrichment-feeds-daily"]
    assert entry["schedule"] == crontab(hour=2, minute=0)
    assert celery_app.conf.timezone == "UTC"


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
