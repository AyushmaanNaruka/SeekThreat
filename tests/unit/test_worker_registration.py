"""The Celery worker must actually have the scan task registered.

`celery -A apps.api.worker.celery_app worker` imports only that one module. If
importing it does not also register `seekthreat.scans.execute`, the worker
starts, connects to the broker, and then rejects every job it is handed as an
unregistered task -- so `execute_scan.delay()` enqueues work nobody runs and
every scan row sits at 'pending' forever.

These tests run in a SUBPROCESS on purpose. Registration is a global side
effect of importing the task module, and several other test modules import
`apps.api.tasks.scans` directly. In-process assertions would therefore pass
whether or not `apps/api/worker.py` registers anything itself, which is
precisely the bug being guarded against.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

TASK_NAME = "seekthreat.scans.execute"

# Import ONLY the worker module, exactly as the celery CLI does, then force the
# app to finalize and print what it knows about.
_PROBE = """
import apps.api.worker as worker

registered = sorted(
    name for name in worker.celery_app.tasks if not name.startswith("celery.")
)
print(";".join(registered))
"""


def _registered_tasks_in_fresh_process() -> list[str]:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"probe process failed (exit {result.returncode})\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = result.stdout.strip()
    return payload.split(";") if payload else []


def test_scan_task_is_registered_by_importing_the_worker_module() -> None:
    """Importing apps.api.worker alone must register the scan task."""
    registered = _registered_tasks_in_fresh_process()
    assert TASK_NAME in registered, (
        f"{TASK_NAME!r} is not registered after importing apps.api.worker. "
        f"A real Celery worker would reject every dispatched scan as an "
        f"unregistered task. Registered: {registered}"
    )


def test_worker_registers_exactly_the_expected_tasks() -> None:
    """Guards against the probe passing for the wrong reason.

    If this list needs updating because a genuinely new task was added, update
    it. If it changed because task discovery started sweeping in something
    unexpected, that is worth knowing about.
    """
    assert _registered_tasks_in_fresh_process() == [TASK_NAME]
