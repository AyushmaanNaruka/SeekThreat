"""Cross-process exclusive lock for one mirror file (stdlib only).

Targeted per-CVE sync does read-merge-write on a mirror file. Post-scan tasks,
the 02:00 beat sync and the CLI can each do that at the same time, possibly from
different containers that share the cache volume, so an in-process lock is not
enough: the later writer would replace the file with its own merge and drop the
earlier writer's additions.

The lock is a sibling file created with ``os.open(O_CREAT | O_EXCL | O_WRONLY)``.
Exclusive create is atomic on local filesystems on Windows and Linux and on the
Docker volumes the compose stack uses, which makes it a portable mutex without
``fcntl``/``msvcrt``. The file records pid, host, a random token and the time it
was taken, for diagnostics and so release removes only our own lock.

A holder that dies leaves its lock behind. A lock older than ``stale_after``
seconds (by file mtime) is treated as abandoned and broken. The lock is held only
around the local read-merge-write, never across network I/O, so a live holder
keeps it for well under a second; the default ``stale_after`` leaves a wide
margin. Waiting is bounded by ``timeout`` with capped exponential back-off.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any

logger = logging.getLogger(__name__)

#: A lock file older than this is abandoned (its holder crashed or was killed).
DEFAULT_STALE_AFTER_SECONDS = 300.0
#: Longest a writer waits for a mirror lock before reporting failure.
DEFAULT_LOCK_TIMEOUT_SECONDS = 60.0
_INITIAL_BACKOFF_SECONDS = 0.01
_MAX_BACKOFF_SECONDS = 0.5

__all__ = [
    "DEFAULT_LOCK_TIMEOUT_SECONDS",
    "DEFAULT_STALE_AFTER_SECONDS",
    "MirrorLock",
    "MirrorLockTimeout",
    "lock_path_for",
]


class MirrorLockTimeout(TimeoutError):
    """The mirror lock could not be acquired within the timeout."""


def lock_path_for(target: Path | str) -> Path:
    """Lock file for a mirror: ``cve_org.json`` -> ``.cve_org.json.lock`` (same dir)."""
    target = Path(target)
    return target.with_name(f".{target.name}.lock")


class MirrorLock:
    """Exclusive, cross-process lock on one mirror file. Use as a context manager."""

    def __init__(
        self,
        target: Path | str,
        *,
        timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
        stale_after: float = DEFAULT_STALE_AFTER_SECONDS,
    ) -> None:
        self.path = lock_path_for(target)
        self.timeout = timeout
        self.stale_after = stale_after
        self._token: str | None = None

    def _try_create(self) -> bool:
        token = uuid.uuid4().hex
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except (FileExistsError, PermissionError):
            # Windows reports a lock file that is mid-delete as PermissionError.
            return False
        owner = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "token": token,
            "acquired_at": datetime.now(UTC).isoformat(),
        }
        try:
            os.write(fd, json.dumps(owner).encode("utf-8"))
        finally:
            os.close(fd)
        self._token = token
        return True

    def _read_owner(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _break_if_stale(self) -> None:
        try:
            age = time.time() - self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if age < self.stale_after:
            return
        owner = self._read_owner()
        logger.warning(
            "mirror lock %s is %.0fs old (owner %s); breaking it as abandoned",
            self.path,
            age,
            owner,
        )
        with contextlib.suppress(FileNotFoundError, PermissionError):
            self.path.unlink()

    def acquire(self) -> None:
        """Take the lock, waiting up to ``timeout`` seconds; raise MirrorLockTimeout."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        backoff = _INITIAL_BACKOFF_SECONDS
        while True:
            if self._try_create():
                return
            self._break_if_stale()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MirrorLockTimeout(
                    f"could not lock {self.path.name} within {self.timeout:.1f}s "
                    f"(held by {self._read_owner()})"
                )
            time.sleep(min(backoff, remaining))
            backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)

    def release(self) -> None:
        """Remove the lock file if it is still ours (it may have been broken as stale)."""
        token, self._token = self._token, None
        if token is None:
            return
        owner = self._read_owner()
        if owner is not None and owner.get("token") != token:
            logger.warning("mirror lock %s was taken over by %s; not removing it", self.path, owner)
            return
        # On Windows unlink fails while a waiter has the file open to read its owner;
        # that window is tiny, so retry briefly rather than leave a lock behind.
        for _attempt in range(50):
            try:
                self.path.unlink()
                return
            except FileNotFoundError:
                return
            except PermissionError:
                time.sleep(_INITIAL_BACKOFF_SECONDS)
        logger.error("could not remove mirror lock %s; it will expire as stale", self.path)

    def __enter__(self) -> MirrorLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
