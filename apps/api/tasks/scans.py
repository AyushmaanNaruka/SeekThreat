"""Celery task: async scan execution.

This module contains the Celery task that replaces the FastAPI
BackgroundTasks-based ``_execute_scan_task`` from Task 3. The task runs
inside the worker process, fully outside the HTTP request lifecycle.

Design decisions:
- Authorization is passed as a JSON-serializable dict and reconstructed
  inside the task using ``Authorization.model_validate()``.  Celery
  serialises arguments through JSON so live Python objects cannot cross
  the boundary.
- The task opens its own ``SessionLocal()`` session. The request session
  is already closed when Celery picks up the job.
- Transient errors (network, DB blip) are retried up to 3 times with a
  30-second back-off before the scan is marked failed.
- Permanent errors are *not* retried. Every retry is a full rescan, so
  re-attempting an error whose outcome cannot change (an unsupported
  scanner name, a missing binary) only multiplies the work. See
  ``PERMANENT_ERRORS``.
- However the scan fails, the task re-raises once the row is marked
  failed. Celery derives task state from the return value, so swallowing
  the exception would record the task as SUCCESS while the scan sat at
  'failed' in the database.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from apps.api.core.audit import log_audit_event
from apps.api.db.repositories import (
    ScanRepository,
    save_scan_result,
)
from apps.api.db.session import SessionLocal
from apps.api.worker import celery_app
from packages.schema.models.engagement import Authorization, ScanRequest
from services.scanners.base import AuthorizationError, ScannerAdapter, ScannerUnavailableError
from services.scanners.nmap_adapter import NmapAdapter
from services.scanners.nuclei_adapter import NucleiAdapter

logger = logging.getLogger(__name__)

# Failures that a retry cannot fix. An unsupported scanner name stays
# unsupported, a missing binary stays missing, and an unauthorized target must
# never be re-attempted at all. Retrying any of these costs a full rescan per
# attempt for an outcome that cannot change.
PERMANENT_ERRORS = (
    ValueError,
    ScannerUnavailableError,
    AuthorizationError,
)


@celery_app.task(  # type: ignore[misc]  # celery ships no type stubs for .task()
    bind=True,
    name="seekthreat.scans.execute",
    max_retries=3,
    default_retry_delay=30,
)
def execute_scan(
    self: Any,
    scan_id: str,
    engagement_id: str,
    scanner: str,
    target: str,
    options: dict[str, Any],
    authorization_dict: dict[str, Any],
) -> None:
    """Execute a scan asynchronously and persist the results.

    Args:
        scan_id: Unique identifier of the pending scan record.
        engagement_id: Parent engagement identifier (for audit events).
        scanner: Scanner name (e.g. ``"nmap"``).
        target: IP address, CIDR range, or hostname to scan.
        options: Scanner-specific execution options.
        authorization_dict: JSON-safe representation of the
            ``Authorization`` record, produced via
            ``auth.model_dump(mode="json")``.  Reconstructed with
            ``Authorization.model_validate()``.
    """
    # Reconstruct Authorization from the JSON-serialized dict.
    # model_validate handles datetime strings and list→frozenset coercion.
    authorization = Authorization.model_validate(authorization_dict)

    db = SessionLocal()
    scan_repo = ScanRepository(db)
    try:
        scan_repo.update_status(scan_id=scan_id, status="running")
        db.commit()

        # Build scan request from reconstructed authorization
        request = ScanRequest(
            target=target,
            authorization=authorization,
            options=options,
        )

        adapter: ScannerAdapter
        if scanner == "nmap":
            adapter = NmapAdapter()
        elif scanner == "nuclei":
            adapter = NucleiAdapter()
        else:
            raise ValueError(f"Unsupported scanner: {scanner!r}")

        # Check before invoking rather than letting the subprocess call fail:
        # this turns "binary not installed in the image" into a clear, named,
        # non-retried error instead of an opaque OSError retried four times.
        if not adapter.is_available():
            raise ScannerUnavailableError(
                f"Scanner {scanner!r} is not installed or not runnable in this environment."
            )

        scan_result = adapter.scan(request)

        # Persist results idempotently (upsert — safe to re-run)
        save_scan_result(db, scan_result)

        scan_repo.update_status(
            scan_id=scan_id,
            status="completed",
            artifact_id=scan_result.artifact.artifact_id,
            completed_at=datetime.now(UTC),
        )
        db.commit()

        log_audit_event(
            event="scan.completed",
            actor=authorization.authorized_by,
            target=target,
            engagement_id=engagement_id,
            scanner=scanner,
            status="completed",
            details={
                "scan_id": scan_id,
                "artifact_id": scan_result.artifact.artifact_id,
                "observation_count": len(scan_result.observations),
                "celery_task_id": getattr(self.request, "id", None),
            },
        )

    except Exception as exc:
        db.rollback()
        error_msg = f"{type(exc).__name__}: {exc}"
        logger.error("Scan %s failed: %s", scan_id, error_msg, exc_info=True)

        if not isinstance(exc, PERMANENT_ERRORS):
            # Transient: hand back to Celery, which re-raises Retry to
            # reschedule. Once retries are exhausted it raises
            # MaxRetriesExceededError, and we fall through to mark the row.
            try:
                raise self.retry(exc=exc) from exc
            except self.MaxRetriesExceededError:
                pass

        try:
            scan_repo.update_status(
                scan_id=scan_id,
                status="failed",
                error_message=error_msg,
                completed_at=datetime.now(UTC),
            )
            db.commit()
        except Exception:
            db.rollback()

        log_audit_event(
            event="scan.failed",
            actor=authorization.authorized_by,
            target=target,
            engagement_id=engagement_id,
            scanner=scanner,
            status="error",
            details={
                "scan_id": scan_id,
                "error": error_msg,
                "celery_task_id": getattr(self.request, "id", None),
            },
        )

        # Re-raise so Celery records FAILURE. Returning normally here would
        # leave the task marked SUCCESS while the scan row says 'failed'.
        raise
    finally:
        db.close()
