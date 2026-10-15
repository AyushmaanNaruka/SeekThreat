"""Nikto adapter — web server misconfiguration and known-issue scanner integration.

LICENCE NOTE: Nikto is GPL-2.0 (Chris Sullo / CIRT.net). We invoke the `nikto` binary as a
separate process and parse its JSON report. We never vendor, copy, link or port its source
or its check databases (CLAUDE.md hard rule 3). Nothing under services/ derives from Nikto.

SAFETY NOTE (CLAUDE.md hard rule 4 — non-destructive only). Nikto ships checks that upload
files, brute-force logins, send injection payloads or read arbitrary files. They are
excluded in two independent ways, both fixed in the argv (no caller can widen them):

  - `-Tuning` is an *include* list, never a reverse (`x`) list, so a category Nikto adds in
    a future release stays off until someone opts it in. Included: 1 interesting files,
    2 misconfiguration / default files, 3 information disclosure, a authentication bypass
    (detection only), b software identification, d web service, e administrative console.
    Excluded: 0 file upload, 4 injection (XSS/script/HTML), 5 and 7 remote file retrieval
    (reads /etc/passwd-style files through traversal flaws — a proof of exploitation, not
    a canary), 6 denial of service, 8 command execution / remote shell, 9 SQL injection,
    c remote source inclusion.
  - `-Plugins` is an include list of read-only plugins. Tuning only governs the `tests`
    plugin; the other plugins run regardless, and several are active: put_del_test uploads
    and deletes files, auth guesses credentials, dictionary/apacheusers enumerate and guess,
    shellshock/strutshock/dishwasher/ms10_070/apache_expect_xss send attack payloads. None
    of them are listed. `report_json` must be listed: Nikto treats `-Plugins` as the
    complete set and silently emits nothing on stdout without it.

Widening either list is a scope decision and belongs in DECISIONS.md.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import shutil
import subprocess
from collections.abc import Mapping
from datetime import datetime
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
from .nikto_json import parse_nikto_json, parse_run_timestamp

logger = logging.getLogger(__name__)

# See the module docstring for why each category and plugin is in or out.
SAFE_TUNING = "123abde"
EXCLUDED_TUNING = frozenset("0456789c")
SAFE_PLUGINS = (
    "headers",
    "httpoptions",
    "msgs",
    "outdated",
    "cookies",
    "robots",
    "favicon",
    "paths",
    "embedded",
    "multiple_index",
    "clientaccesspolicy",
    "negotiate",
    "origin_reflection",
    "sitefiles",
    "tests",
    "cgi",
    "parked",
    "content_search",
    "report_json",
)

DEFAULT_TIMEOUT_SECONDS = 1800
MAX_TIMEOUT_SECONDS = 21600  # 6h — a scan longer than this is a scheduling mistake
# Nikto enforces `-maxtime` itself and exits 0 with a partial report. The subprocess
# watchdog sits this far behind it, so Nikto's own limit is what normally fires.
WATCHDOG_GRACE_SECONDS = 60
APPROVED_SCHEMES = frozenset({"http", "https"})
PORT_RE = re.compile(r"^[0-9]{1,5}$")
STDERR_TAIL_CHARS = 2000
_MAXTIME_STDERR = "maximum execution time"


def _resolve_nikto_bin() -> str | None:
    # `nikto_path` is a config setting the coordinator adds separately; read it
    # defensively so this module works before and after that lands.
    from apps.api.core.config import settings

    configured = getattr(settings, "nikto_path", None)
    if configured:
        p = Path(str(configured))
        if p.is_file():
            return str(p)
    return shutil.which("nikto") or shutil.which("nikto.pl")


def _timeout_seconds(value: object) -> int:
    """Validate the caller's timeout. Options cross an HTTP and a Celery JSON boundary,
    so `timeout` arrives as whatever the client sent — a string, a float, None, a bool.
    A non-finite float is refused before `int()` (OverflowError is not a ValueError and
    would be retried as transient); a fractional float is refused rather than truncated."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"Nikto timeout option must be a number of seconds, got {value!r}")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError(f"Nikto timeout option must be a whole number of seconds, got {value!r}")
    seconds = int(value)
    if not 0 < seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"Nikto timeout option must be between 1 and {MAX_TIMEOUT_SECONDS} seconds, "
            f"got {seconds}"
        )
    return seconds


def _stderr_tail(stderr: bytes | str | None) -> str:
    if isinstance(stderr, bytes):
        text = stderr.decode("utf-8", errors="replace")
    elif isinstance(stderr, str):
        text = stderr
    else:
        return ""
    return " ".join(text.split())[-STDERR_TAIL_CHARS:]


def _nikto_target_args(request: ScanRequest) -> list[str]:
    """Build the target part of the argv from the target the gate approved.

    The authorization gate never parses a URL down to a host, deliberately (see the
    parser-differential cases in tests/unit/test_authorization_matching.py), so neither
    does this. It re-checks the target independently of the gate, so a gate bug alone does
    not put an unapproved host in front of nikto:

    - A bare target must be an IP address or a strict DNS hostname — no port, path,
      userinfo or fragment. It goes to `-host` as-is; the validated `port` and `scheme`
      options become separate `-port` / `-ssl` / `-nossl` flags, so nothing is ever
      concatenated into the host string.
    - A URL target (containing `://`) is passed verbatim to `-host`, and only when that
      exact string is a non-wildcard entry of the authorization's allowlist.
    """
    target = request.target.strip()
    if not target:
        raise ValueError("Nikto target is empty")
    if target.startswith("-"):
        # Getopt would read it as a flag rather than a value.
        raise ValueError(f"Nikto target {target!r} may not start with '-'")

    port_opt = request.options.get("port")
    scheme_opt = request.options.get("scheme")

    if "://" in target:
        if port_opt is not None or scheme_opt is not None:
            raise ValueError(
                f"Nikto target {target!r} is already a URL; the 'port' and 'scheme' "
                f"options only apply to a bare host or IP target"
            )
        exact_entries = {
            entry.strip()
            for entry in request.authorization.allowlist
            if not entry.strip().startswith("*")
        }
        if target not in exact_entries:
            raise ValueError(
                f"Nikto URL target {target!r} is not an exact allowlist entry; a URL is "
                f"only scanned when the authorizer allowlisted that exact string"
            )
        return ["-host", target]

    if "%" in target:
        # ipaddress accepts any text after '%' as an IPv6 scope id, and nikto splits -host
        # on commas (treating a readable path as a host file), so a scope could smuggle in
        # a second host. Same guard as ssh_audit_adapter; the gate refuses these too.
        raise ValueError(f"Nikto target {target!r} has an IPv6 scope id; scoped targets are refused")

    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not is_valid_hostname(target):
            raise ValueError(
                f"Nikto target {target!r} is not an IP address or a valid hostname; pass "
                f"the port and scheme as the 'port' and 'scheme' options instead"
            ) from None

    args = ["-host", target]

    if port_opt is not None:
        port = str(port_opt).strip()
        if not PORT_RE.match(port) or not 0 < int(port) < 65536:
            raise ValueError(f"Nikto port option must be 1-65535, got {port_opt!r}")
        args += ["-port", str(int(port))]

    if scheme_opt is not None:
        scheme = str(scheme_opt).strip().lower()
        if scheme not in APPROVED_SCHEMES:
            raise ValueError(
                f"Nikto scheme option must be one of {sorted(APPROVED_SCHEMES)}, got {scheme_opt!r}"
            )
        args.append("-ssl" if scheme == "https" else "-nossl")

    return args


def _warn_unknown_options(options: Mapping[str, object]) -> None:
    """Log option keys this adapter does not implement.

    They are ignored, never forwarded: a `tuning`, `plugins` or `args` key cannot change
    what nikto runs, so ignoring is safe — but say so, so the caller learns it was dropped.
    """
    unknown = sorted(set(options) - {"port", "scheme", "timeout"})
    if unknown:
        logger.warning("nikto adapter ignoring unsupported option(s): %s", unknown)


class NiktoAdapter(ScannerAdapter):
    name = "nikto"
    content_type = "application/json"

    @property
    def version_command(self) -> list[str]:  # type: ignore[override]
        exe = _resolve_nikto_bin() or "nikto"
        return [exe, "-Version"]

    def is_available(self) -> bool:
        return _resolve_nikto_bin() is not None

    def _execute(self, request: ScanRequest) -> str:
        # Caller-supplied flags are NOT accepted here — see the identical note in
        # nmap_adapter.py and DECISIONS.md D-017. nikto's `-host` is repeatable and
        # `-Plugins`/`-Tuning` select what runs, so a pass-through would let a caller add
        # an unauthorized target or re-enable the destructive checks excluded above.
        _warn_unknown_options(request.options)
        exe = _resolve_nikto_bin() or "nikto"
        timeout = _timeout_seconds(request.options.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        cmd = [
            exe,
            *_nikto_target_args(request),
            "-ask",
            "no",
            "-nointeractive",
            "-nolookup",
            "-Format",
            "json",
            "-o",
            "-",
            "-maxtime",
            f"{timeout}s",
            "-Tuning",
            SAFE_TUNING,
            "-Plugins",
            ";".join(SAFE_PLUGINS),
        ]

        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout + WATCHDOG_GRACE_SECONDS,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                f"nikto exceeded its {timeout}s budget against {request.target!r} and was "
                f"killed; its partial output was not recorded as a result. Raise "
                f"options['timeout'] rather than retrying."
            ) from exc
        except FileNotFoundError as exc:
            raise ScannerUnavailableError(f"nikto binary not executable at {exe!r}: {exc}") from exc
        except OSError as exc:
            raise ScannerUnavailableError(f"could not start nikto at {exe!r}: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            raise ValueError(
                f"nikto exited {exc.returncode} scanning {request.target!r}: "
                f"{_stderr_tail(exc.stderr)}"
            ) from exc

        stderr_tail = _stderr_tail(result.stderr)
        if _MAXTIME_STDERR in stderr_tail:
            # Nikto stops itself at -maxtime, prints this on stderr and exits 0 with the
            # findings it had so far. Recording that as a finished scan would overstate
            # coverage, so it is treated exactly like a watchdog timeout.
            raise ScannerTimeoutError(
                f"nikto reached its own {timeout}s -maxtime against {request.target!r}; "
                f"its partial output was not recorded as a result. Raise "
                f"options['timeout'] rather than retrying."
            )
        if stderr_tail:
            logger.warning("nikto stderr for target %s: %s", request.target, stderr_tail)

        # Decoded explicitly rather than via text=True: that flag applies universal-newline
        # translation, which would make the verbatim artifact (and its content hash)
        # platform-dependent.
        stdout = result.stdout.decode("utf-8", errors="replace")
        if "Unable to connect to" in stdout:
            # nikto reports an unreachable target as a finding and exits 0; the parser
            # drops it, so say so here or a dead target looks like a clean scan.
            logger.warning("nikto could not connect to target %s", request.target)
        return stdout

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_nikto_json(artifact, engagement_id=request.authorization.engagement_id)
