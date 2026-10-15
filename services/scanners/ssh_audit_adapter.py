"""ssh-audit adapter — SSH server configuration auditor integration.

LICENCE NOTE: ssh-audit (github.com/jtesta/ssh-audit) is MIT licensed by Joe Testa. We
invoke the binary as a subprocess and parse its JSON output. We never vendor or link
its source code.

Non-destructive by construction. ssh-audit opens a TCP connection, reads the server's
identification banner and its SSH_MSG_KEXINIT algorithm lists, then (for the host-key and
Diffie-Hellman group-exchange checks) performs a handful of further key-exchange
handshakes. It never authenticates. The argv below is fixed. It passes --skip-rate-test,
because a standard audit would otherwise open up to 38 connections in 1.5s to infer
DHEat exposure and we do not generate that load, and it deliberately omits every
ssh-audit mode that does more than a handshake audit:

  --dheat / --conn-rate-test   concurrent-connection DoS simulation (CVE-2002-20001)
  -c / --client-audit          listens on a port instead of connecting out
  -g / --gex-test              custom Diffie-Hellman group-exchange modulus probing
  -T / --targets, --threads    multi-target scanning; one authorized target per run
  -P / -M / --policy           policy checks and policy files read from disk

Exit codes (ssh-audit exitcodes.py, v2.4+): 0 good, 1 connection error, 2 warnings found,
3 failures found, -1 (255) unknown error. 2 and 3 mean the audit RAN and found things, so
they are results, not errors. What decides success here is whether stdout is a JSON
object: a connection error prints plain text to stdout and exits 1.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import shutil
import subprocess
from pathlib import Path

from packages.schema.models.engagement import is_valid_hostname

from .base import (
    Observation,
    RawArtifact,
    ScannerAdapter,
    ScannerTimeoutError,
    ScannerUnavailableError,
    ScanRequest,
)
from .ssh_audit_json import parse_ssh_audit_json

logger = logging.getLogger(__name__)

DEFAULT_PORT = 22
DEFAULT_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 3600
# ssh-audit's own per-socket connect/read timeout (`-t`, default 5). Never longer than the
# overall budget, so a short `timeout` option cannot be outlived by a single read.
SOCKET_TIMEOUT_SECONDS = 10
PORT_RE = re.compile(r"^[0-9]{1,5}$")
# How much of ssh-audit's output to keep in an error message. Enough for the
# "[exception] cannot connect to ..." line, short enough not to flood a log record.
OUTPUT_TAIL_CHARS = 2000
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _resolve_ssh_audit_bin() -> str | None:
    from apps.api.core.config import settings

    configured = getattr(settings, "ssh_audit_path", None)
    if configured:
        p = Path(configured)
        if p.is_file():
            return str(p)
    return shutil.which("ssh-audit")


def _timeout_seconds(value: object) -> int:
    """Validate the caller's timeout. Options cross an HTTP and a Celery JSON boundary,
    so `timeout` arrives as whatever the client sent — a string, a float, None, a bool.
    `subprocess.run` raises TypeError deep in the call for some of those, which would be
    retried as a transient error. A non-finite float is refused before `int()` (which
    raises OverflowError); a fractional float is refused rather than truncated."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"ssh-audit timeout option must be a number of seconds, got {value!r}")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError(
            f"ssh-audit timeout option must be a whole number of seconds, got {value!r}"
        )
    seconds = int(value)
    if not 0 < seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"ssh-audit timeout option must be between 1 and {MAX_TIMEOUT_SECONDS} seconds, "
            f"got {seconds}"
        )
    return seconds


def _port(options: dict[str, object]) -> int:
    """The TCP port to audit; defaults to 22. A bool, float or non-numeric string is
    refused rather than coerced."""
    value = options.get("port", DEFAULT_PORT)
    text = str(value).strip()
    if isinstance(value, bool | float) or not PORT_RE.match(text) or not 0 < int(text) < 65536:
        raise ValueError(f"ssh-audit port option must be 1-65535, got {value!r}")
    return int(text)


def _ssh_audit_host(request: ScanRequest) -> str:
    """Return the host handed to ssh-audit, from the target the gate approved.

    Re-checks the target independently of the gate, so a gate bug alone does not put an
    unapproved or option-shaped string in front of ssh-audit. The target must be a bare
    IP address or a strict DNS hostname: no port (that is the `port` option), scheme,
    path, userinfo or IPv6 zone, and nothing that starts with `-`. The argv also places
    the host after `--`, so even a value that slipped through could not be read as a flag.
    """
    target = request.target.strip()
    if not target:
        raise ValueError("ssh-audit target is empty")
    if target.startswith("-"):
        raise ValueError(f"ssh-audit target {target!r} may not start with '-'")
    if "%" not in target:
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            if is_valid_hostname(target):
                return target
    raise ValueError(
        f"ssh-audit target {target!r} is not an IP address or a valid hostname; pass the "
        f"port as the 'port' option instead"
    )


def _output_tail(stdout: bytes | str | None) -> str:
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", errors="replace")
    elif isinstance(stdout, str):
        text = stdout
    else:
        return ""
    return " ".join(_ANSI_RE.sub("", text).split())[-OUTPUT_TAIL_CHARS:]


def _is_audit_json(text: str) -> bool:
    try:
        data = json.loads(text)
    except ValueError:
        return False
    return isinstance(data, dict) and "banner" in data


class SshAuditAdapter(ScannerAdapter):
    name = "ssh-audit"
    content_type = "application/json"

    @property
    def version_command(self) -> list[str]:  # type: ignore[override]
        # ssh-audit has no --version flag. 2.x's usage text opened with "# ssh-audit.py vX.Y.Z";
        # 3.x prints argparse "usage: ssh-audit ..." with no version, so this is not a reliable
        # version probe there. Availability is decided by is_available(), not by this command.
        exe = _resolve_ssh_audit_bin() or "ssh-audit"
        return [exe, "-h"]

    def is_available(self) -> bool:
        return _resolve_ssh_audit_bin() is not None

    def _execute(self, request: ScanRequest) -> str:
        # Caller-supplied flags are NOT accepted — see nmap_adapter.py and DECISIONS.md
        # D-017. ssh-audit has flags that read files (-T, -P), listen on a port (-c) or
        # generate attack traffic (--dheat); none may be reachable from an API request.
        exe = _resolve_ssh_audit_bin() or "ssh-audit"
        host = _ssh_audit_host(request)
        port = _port(request.options)
        timeout = _timeout_seconds(request.options.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        cmd = [
            exe,
            "-j",
            # See the module docstring: no DHEat-style connection burst.
            "--skip-rate-test",
            # Plain error text; ANSI escapes would end up in logs and scan error rows.
            "-n",
            "-t",
            str(min(SOCKET_TIMEOUT_SECONDS, timeout)),
            # Always explicit. With -p given ssh-audit does not try to split a port off the
            # host, so an unbracketed IPv6 literal is read as a host, not as host:port.
            "-p",
            str(port),
            # Host last, after `--`: it cannot be parsed as an option.
            "--",
            host,
        ]
        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                f"ssh-audit exceeded its {timeout}s budget against {request.target!r}:{port} "
                f"and was killed; its partial output was not recorded as a result. Raise "
                f"options['timeout'] rather than retrying."
            ) from exc
        except FileNotFoundError as exc:
            raise ScannerUnavailableError(
                f"ssh-audit binary not executable at {exe!r}: {exc}"
            ) from exc
        except OSError as exc:
            raise ScannerUnavailableError(f"could not start ssh-audit at {exe!r}: {exc}") from exc

        # Decoded explicitly rather than via text=True: that flag applies universal-newline
        # translation, which would make the verbatim artifact platform-dependent and its
        # content hash unstable across Windows and Linux.
        stdout = result.stdout.decode("utf-8", errors="replace")

        # A non-zero exit is NOT an error by itself: 2 and 3 mean "audit completed, found
        # warnings/failures". It is an error only when no audit JSON came out — a
        # connection failure (exit 1, plain text on stdout) or an ssh-audit fault.
        if not _is_audit_json(stdout):
            raise ValueError(
                f"ssh-audit exited {result.returncode} auditing {request.target!r}:{port} "
                f"without producing audit JSON: {_output_tail(stdout) or '(no output)'} "
                f"{_output_tail(result.stderr)}".rstrip()
            )

        stderr_tail = _output_tail(result.stderr)
        if stderr_tail:
            logger.warning(
                "ssh-audit stderr for target %s:%s: %s", request.target, port, stderr_tail
            )
        return stdout

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_ssh_audit_json(artifact, engagement_id=request.authorization.engagement_id)
