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
  scanner name, a missing binary, a scan that cannot finish inside its
  own timeout) only multiplies the work. See ``PERMANENT_ERRORS``.
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
from services.scanners.base import (
    AuthorizationError,
    ScannerAdapter,
    ScannerTimeoutError,
    ScannerUnavailableError,
)
from services.scanners.nmap_adapter import NmapAdapter
from services.scanners.nmap_xml import NmapParseError
from services.scanners.nuclei_adapter import NucleiAdapter
from services.scanners.nuclei_json import NucleiParseError


# Import lazily resolved at call time to avoid a circular import at module
# load; post_scan_enrichment imports celery_app which also lives in worker.
def _dispatch_post_scan_enrichment(artifact_id: str, engagement_id: str, scan_id: str) -> None:
    """Fire-and-forget: dispatch the post-scan enrichment task.

    Any failure to enqueue (e.g. Redis unavailable) is caught and logged;
    it must never propagate back to the scan result.
    """
    try:
        from apps.api.tasks.post_scan_enrichment import sync_new_findings_cves  # noqa: PLC0415

        sync_new_findings_cves.apply_async(
            kwargs={
                "artifact_id": artifact_id,
                "engagement_id": engagement_id,
                "scan_id": scan_id,
            }
        )
        logger.info(
            "post_scan_enrichment: enqueued for scan %s / artifact %s",
            scan_id,
            artifact_id,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "post_scan_enrichment: failed to enqueue for scan %s: %s "
            "— enrichment will run at next beat",
            scan_id,
            exc,
        )


logger = logging.getLogger(__name__)

# Failures that a retry cannot fix. An unsupported scanner name stays
# unsupported, a missing binary stays missing, a scan that blew its timeout blows
# it again with the same budget and template set, and an unauthorized target must
# never be re-attempted at all. A parse error is a deterministic function of the
# tool's output, so a rescan only reproduces output the parser rejects again.
# Retrying any of these costs a full rescan per attempt for an outcome that cannot
# change.
PERMANENT_ERRORS = (
    ValueError,
    ScannerUnavailableError,
    ScannerTimeoutError,
    AuthorizationError,
    NmapParseError,
    NucleiParseError,
)


def run_scan(
    scan_id: str,
    engagement_id: str,
    scanner: str,
    target: str,
    options: dict[str, Any],
    authorization_dict: dict[str, Any],
    task: Any = None,
) -> None:
    """Execute a scan and persist the results.

    Invoked by the Celery task worker (task=self). Opens its own database
    session via ``SessionLocal()`` and closes it on exit.

    Args:
        scan_id: Unique identifier of the pending scan record.
        engagement_id: Parent engagement identifier (for audit events).
        scanner: Scanner name (e.g. ``"nmap"``).
        target: IP address, CIDR range, or hostname to scan.
        options: Scanner-specific execution options.
        authorization_dict: JSON-safe representation of the
            ``Authorization`` record.
        task: Optional Celery task instance. When provided, transient errors
            are retried and the exception is re-raised on final failure so
            Celery marks the task as FAILURE.
    """
    db = SessionLocal()

    scan_repo = ScanRepository(db)
    actor = (
        authorization_dict.get("authorized_by", "unknown")
        if isinstance(authorization_dict, dict)
        else "unknown"
    )

    try:
        # Reconstruct Authorization from the JSON-serialized dict.
        # model_validate handles datetime strings and list→frozenset coercion.
        authorization = Authorization.model_validate(authorization_dict)
        actor = authorization.authorized_by

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

        # Dispatch post-scan enrichment off the request path (fire-and-forget).
        # This is the integration point for Task 6 (D-036): the scan itself is
        # already committed; a failure to enqueue must not roll it back.
        _dispatch_post_scan_enrichment(
            artifact_id=scan_result.artifact.artifact_id,
            engagement_id=engagement_id,
            scan_id=scan_id,
        )

        celery_task_id = (
            getattr(task.request, "id", None)
            if task is not None and hasattr(task, "request")
            else None
        )

        log_audit_event(
            event="scan.completed",
            actor=actor,
            target=target,
            engagement_id=engagement_id,
            scanner=scanner,
            status="completed",
            details={
                "scan_id": scan_id,
                "artifact_id": scan_result.artifact.artifact_id,
                "observation_count": len(scan_result.observations),
                "celery_task_id": celery_task_id,
            },
        )

    except Exception as exc:
        db.rollback()
        error_msg = f"{type(exc).__name__}: {exc}"
        logger.error("Scan %s failed: %s", scan_id, error_msg, exc_info=True)

        is_celery = task is not None and hasattr(task, "retry") and callable(task.retry)

        if is_celery and not isinstance(exc, PERMANENT_ERRORS):
            # Transient: hand back to Celery, which re-raises Retry to
            # reschedule. Once retries are exhausted it raises
            # MaxRetriesExceededError, and we fall through to mark the row.
            try:
                max_retries_exc = getattr(task, "MaxRetriesExceededError", Exception)
                raise task.retry(exc=exc) from exc
            except max_retries_exc:
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

        celery_task_id = (
            getattr(task.request, "id", None)
            if task is not None and hasattr(task, "request")
            else None
        )

        log_audit_event(
            event="scan.failed",
            actor=actor,
            target=target,
            engagement_id=engagement_id,
            scanner=scanner,
            status="error",
            details={
                "scan_id": scan_id,
                "error": error_msg,
                "celery_task_id": celery_task_id,
            },
        )

        # Re-raise so Celery records FAILURE. Returning normally here would
        # leave the task marked SUCCESS while the scan row says 'failed'.
        if is_celery:
            raise
    finally:
        db.close()


@celery_app.task(  # type: ignore[untyped-decorator]  # celery ships no type stubs for .task()
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
    return run_scan(
        scan_id=scan_id,
        engagement_id=engagement_id,
        scanner=scanner,
        target=target,
        options=options,
        authorization_dict=authorization_dict,
        task=self,
    )
