"""Nuclei adapter — vulnerability scanner integration.

LICENCE NOTE: Nuclei is MIT licensed by ProjectDiscovery. We invoke the binary
as a subprocess and parse its JSONL output. We never vendor or link Nuclei source code.
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
from .nuclei_json import parse_nuclei_json, parse_run_timestamp

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_TEMPLATE_DIRS = (
    (REPO_ROOT / "services" / "scanners" / "nuclei_templates").resolve(),
    (REPO_ROOT / "tests" / "fixtures" / "nuclei").resolve(),
)

# Detection-only tags. `rce` and `default-login` are deliberately absent: rce
# templates send code-execution payloads and default-login templates attempt
# authentication, both of which break hard rule 4 (non-destructive only).
# Severity levels (info/low/...) are not tags and belong under -severity.
APPROVED_TAGS = frozenset(
    {
        "cve",
        "tech",
        "panel",
        "ssl",
        "dns",
        "exposure",
        "misconfig",
        "config",
        "token",
        "network",
        "http",
    }
)
# Applied to every run, including runs with no -tags, so the full template set
# never executes these categories either.
EXCLUDE_TAGS = "dos,intrusive,fuzz,bruteforce,rce,default-login"

DEFAULT_TIMEOUT_SECONDS = 1800
MAX_TIMEOUT_SECONDS = 21600  # 6h — a scan longer than this is a scheduling mistake
APPROVED_SCHEMES = frozenset({"http", "https"})
PORT_RE = re.compile(r"^[0-9]{1,5}$")
# How much of nuclei's stderr to keep in an error message. Enough for the FTL line
# that says what actually went wrong, short enough not to flood a log record.
STDERR_TAIL_CHARS = 2000


def _resolve_nuclei_bin() -> str | None:
    from apps.api.core.config import settings

    if settings.nuclei_path:
        p = Path(settings.nuclei_path)
        if p.is_file():
            return str(p)
    return shutil.which("nuclei")


def _timeout_seconds(value: object) -> int:
    """Validate the caller's timeout. Options cross an HTTP and a Celery JSON boundary,
    so `timeout` arrives as whatever the client sent — a string, a float, None, a bool.
    `subprocess.run` accepts some of those and raises TypeError deep in the call on the
    rest, which surfaces as an opaque transient error and gets retried. A non-finite
    float is refused before `int()`, which raises OverflowError on infinity — not a
    ValueError, so it too would be retried as transient. A fractional float is refused
    rather than silently truncated."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"Nuclei timeout option must be a number of seconds, got {value!r}")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError(f"Nuclei timeout option must be a whole number of seconds, got {value!r}")
    seconds = int(value)
    if not 0 < seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"Nuclei timeout option must be between 1 and {MAX_TIMEOUT_SECONDS} seconds, "
            f"got {seconds}"
        )
    return seconds


def _selection_options(options: Mapping[str, object]) -> tuple[str | None, str | None]:
    """Return the (tags, template) the caller asked for, at most one of them set.

    Fails closed. A selector that is present but malformed — not a string, blank, or
    combined with another selector — raises instead of being ignored, because ignoring
    it runs nuclei with neither -tags nor -t: the full template set, the widest scan
    there is, in answer to a request for a narrow one. None counts as absent.
    """
    selected: dict[str, str] = {}
    for key in ("tags", "template", "templates"):
        value = options.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Nuclei {key!r} option must be a non-empty string, got {value!r}")
        if key == "tags" and not any(t.strip() for t in value.split(",")):
            raise ValueError(f"Nuclei 'tags' option names no tags: {value!r}")
        selected[key] = value
    if len(selected) > 1:
        raise ValueError(
            f"Nuclei options {sorted(selected)} are mutually exclusive; pass 'tags' or "
            f"one template, not both"
        )
    return selected.get("tags"), selected.get("template", selected.get("templates"))


def _stderr_tail(stderr: bytes | str | None) -> str:
    if isinstance(stderr, bytes):
        text = stderr.decode("utf-8", errors="replace")
    elif isinstance(stderr, str):
        text = stderr
    else:
        return ""
    return " ".join(text.split())[-STDERR_TAIL_CHARS:]


def _nuclei_target(request: ScanRequest) -> str:
    """Build the value handed to nuclei's `-u`, from the target the gate approved.

    The authorization gate never parses a URL down to a host, deliberately: nuclei's Go
    URL parser and Python's need only disagree about where the host ends for an
    allowlist check to pass on one host and the scan to hit another (see the
    parser-differential cases in tests/unit/test_authorization_matching.py). So this
    never parses a URL either. It re-checks the target independently of the gate, so a
    gate bug alone does not put an unapproved host in front of nuclei:

    - A bare target must be an IP address or a strict DNS hostname — no port, path,
      userinfo or fragment. Only then is a validated scheme and port *appended*, and
      appending those to a bare host cannot move the scan to a different host.
    - A URL target (containing `://`) is passed verbatim, and only when that exact
      string is a non-wildcard entry of the authorization's allowlist: the authorizer
      approved this URL, not a pattern that happened to match it.
    """
    target = request.target.strip()
    if not target:
        raise ValueError("Nuclei target is empty")
    if target.startswith("-"):
        # goflags would read it as a flag rather than a value.
        raise ValueError(f"Nuclei target {target!r} may not start with '-'")

    port_opt = request.options.get("port")
    scheme_opt = request.options.get("scheme")

    if "://" in target:
        # The authorizer allowlisted this exact URL string. Honour it verbatim and
        # refuse to rewrite it: combining it with port/scheme options would mean
        # building a target the gate never saw.
        if port_opt is not None or scheme_opt is not None:
            raise ValueError(
                f"Nuclei target {target!r} is already a URL; the 'port' and 'scheme' "
                f"options only apply to a bare host or IP target"
            )
        exact_entries = {
            entry.strip()
            for entry in request.authorization.allowlist
            if not entry.strip().startswith("*")
        }
        if target not in exact_entries:
            raise ValueError(
                f"Nuclei URL target {target!r} is not an exact allowlist entry; a URL is "
                f"only scanned when the authorizer allowlisted that exact string"
            )
        return target

    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(target)
    except ValueError:
        ip = None
        if not is_valid_hostname(target):
            raise ValueError(
                f"Nuclei target {target!r} is not an IP address or a valid hostname; pass "
                f"the port and scheme as the 'port' and 'scheme' options instead"
            ) from None

    host = f"[{target}]" if isinstance(ip, ipaddress.IPv6Address) else target

    if port_opt is not None:
        port = str(port_opt).strip()
        if not PORT_RE.match(port) or not 0 < int(port) < 65536:
            raise ValueError(f"Nuclei port option must be 1-65535, got {port_opt!r}")
        host = f"{host}:{int(port)}"

    if scheme_opt is not None:
        scheme = str(scheme_opt).strip().lower()
        if scheme not in APPROVED_SCHEMES:
            raise ValueError(
                f"Nuclei scheme option must be one of {sorted(APPROVED_SCHEMES)}, "
                f"got {scheme_opt!r}"
            )
        host = f"{scheme}://{host}"

    return host


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    content_type = "application/x-ndjson"

    @property
    def version_command(self) -> list[str]:  # type: ignore[override]
        exe = _resolve_nuclei_bin() or "nuclei"
        return [exe, "-version"]

    def is_available(self) -> bool:
        return _resolve_nuclei_bin() is not None

    def _execute(self, request: ScanRequest) -> str:
        # Caller-supplied flags are NOT accepted here — see the identical note in
        # nmap_adapter.py and DECISIONS.md D-017. nuclei's `-u` is a repeatable flag,
        # so an extra_args entry of `-u <other-host>` would add a second, unauthorized
        # target; `-l <file>` would redirect the whole scan to an arbitrary list.
        exe = _resolve_nuclei_bin() or "nuclei"
        cmd = [
            exe,
            "-u",
            _nuclei_target(request),
            "-jsonl",
            "-silent",
            "-duc",
            "-ni",
            "-no-stdin",
            # Drops the base64 `template-encoded` blob nuclei puts in every record.
            # It is a verbatim copy of a template that already lives in this repo (or
            # in the pinned templates archive), so it is pure duplication in the
            # artifact store, and it is the single largest field in a small finding.
            "-ot",
            # Keep ANSI escapes out of stderr so a captured error message is readable
            # in a log line and in a scan row's error_message column.
            "-nc",
            "-etags",
            EXCLUDE_TAGS,
        ]
        if request.options.get("omit_http_exchange", False):
            # Opt-in: drops the `request`/`response` pair from every record. Those
            # fields are nuclei's own evidence for the match, so they stay on by
            # default — but they also copy the target's response bodies verbatim into
            # the artifact store, and they are what makes a large scan's output breach
            # the parser's 64MB guard. `curl-command` survives either way, so a
            # finding stays reproducible.
            cmd.append("-or")
        tags_opt, template_opt = _selection_options(request.options)
        if tags_opt is not None:
            raw_tags = [t.strip().lower() for t in tags_opt.split(",") if t.strip()]
            for tag in raw_tags:
                if tag not in APPROVED_TAGS:
                    raise ValueError(
                        f"Nuclei tag {tag!r} is not in approved tags allowlist: "
                        f"{sorted(APPROVED_TAGS)}"
                    )
            cmd.extend(["-tags", ",".join(raw_tags)])
        elif template_opt is not None:
            t_str = template_opt.strip()
            candidate = Path(t_str)
            if not candidate.is_absolute():
                candidate = (REPO_ROOT / candidate).resolve()
            else:
                candidate = candidate.resolve()

            is_allowed = any(
                candidate.is_relative_to(allowed_dir) for allowed_dir in ALLOWED_TEMPLATE_DIRS
            )
            if not is_allowed:
                raise ValueError(
                    f"Nuclei template path {t_str!r} is outside allowed template directories"
                )
            if not candidate.is_file():
                raise ValueError(f"Nuclei template not found: {t_str}")

            cmd.extend(["-t", str(candidate)])

        timeout = _timeout_seconds(request.options.get("timeout", DEFAULT_TIMEOUT_SECONDS))
        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            # subprocess.run hands back what it had read so far on exc.stdout, but it
            # is deliberately not recorded: a ScanResult has no notion of a partial run,
            # so saving it would present whatever prefix of the template set finished
            # as a completed scan. Say so plainly instead of reporting an
            # empty-but-successful scan.
            raise ScannerTimeoutError(
                f"nuclei exceeded its {timeout}s budget against {request.target!r} and was "
                f"killed; its partial output was not recorded as a result. Raise "
                f"options['timeout'] or narrow options['tags'] rather than retrying."
            ) from exc
        except FileNotFoundError as exc:
            raise ScannerUnavailableError(
                f"nuclei binary not executable at {exe!r}: {exc}"
            ) from exc
        except OSError as exc:
            raise ScannerUnavailableError(f"could not start nuclei at {exe!r}: {exc}") from exc
        except subprocess.CalledProcessError as exc:
            # nuclei exits 1 for "no templates provided for scan" and 2 for an
            # unrecognised flag. Both are configuration faults that a retry repeats
            # verbatim, and CalledProcessError's own message carries only the exit
            # code — the reason is on stderr, so lift it into the error.
            raise ValueError(
                f"nuclei exited {exc.returncode} scanning {request.target!r}: "
                f"{_stderr_tail(exc.stderr)}"
            ) from exc

        # nuclei reports a target it could not reach (connection refused, filtered
        # port) on stderr and still exits 0 with no findings, so a total failure and a
        # clean empty result are the same ScanResult. Surface the difference in the log
        # at least; the artifact keeps the authoritative record either way.
        stderr_tail = _stderr_tail(result.stderr)
        if stderr_tail:
            logger.warning("nuclei stderr for target %s: %s", request.target, stderr_tail)

        # Decoded explicitly rather than via text=True: that flag applies
        # universal-newline translation, which would make the verbatim artifact
        # platform-dependent and its content hash unstable across Windows and Linux.
        return result.stdout.decode("utf-8", errors="replace")

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_nuclei_json(artifact, engagement_id=request.authorization.engagement_id)
