"""Nuclei adapter — vulnerability scanner integration.

LICENCE NOTE: Nuclei is MIT licensed by ProjectDiscovery. We invoke the binary
as a subprocess and parse its JSONL output. We never vendor or link Nuclei source code.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from .base import Observation, RawArtifact, ScannerAdapter, ScanRequest
from .nuclei_json import parse_nuclei_json, parse_run_timestamp

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


def _resolve_nuclei_bin() -> str | None:
    from apps.api.core.config import settings

    if settings.nuclei_path:
        p = Path(settings.nuclei_path)
        if p.is_file():
            return str(p)
    return shutil.which("nuclei")


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
            request.target,
            "-jsonl",
            "-silent",
            "-duc",
            "-ni",
            "-no-stdin",
            "-etags",
            EXCLUDE_TAGS,
        ]
        template_opt = request.options.get("template") or request.options.get("templates")
        tags_opt = request.options.get("tags")
        if tags_opt and isinstance(tags_opt, str) and tags_opt.strip():
            raw_tags = [t.strip().lower() for t in tags_opt.split(",") if t.strip()]
            for tag in raw_tags:
                if tag not in APPROVED_TAGS:
                    raise ValueError(
                        f"Nuclei tag {tag!r} is not in approved tags allowlist: "
                        f"{sorted(APPROVED_TAGS)}"
                    )
            cmd.extend(["-tags", ",".join(raw_tags)])
        elif template_opt and isinstance(template_opt, str) and template_opt.strip():
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

        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=request.options.get("timeout", 1800),
            check=True,
        )
        return result.stdout.decode("utf-8", errors="replace")

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_nuclei_json(artifact, engagement_id=request.authorization.engagement_id)
