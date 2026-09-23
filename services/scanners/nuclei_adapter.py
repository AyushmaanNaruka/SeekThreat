"""Nuclei adapter — vulnerability scanner integration.

LICENCE NOTE: Nuclei is MIT licensed by ProjectDiscovery. We invoke the binary
as a subprocess and parse its JSONL output. We never vendor or link Nuclei source code.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime

from .base import Observation, RawArtifact, ScannerAdapter, ScanRequest
from .nuclei_json import parse_nuclei_json, parse_run_timestamp


def _resolve_nuclei_bin() -> str | None:
    found = shutil.which("nuclei")
    if found:
        return found
    from pathlib import Path
    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "vendor" / "bin" / "nuclei.exe",
        repo_root / "vendor" / "bin" / "nuclei",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    version_command = ["nuclei", "-version"]
    content_type = "application/x-ndjson"

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
        ]
        template_opt = request.options.get("template") or request.options.get("templates")
        if "tags" in request.options and isinstance(request.options["tags"], str) and request.options["tags"].strip():
            cmd.extend(["-tags", request.options["tags"].strip()])
        elif template_opt and isinstance(template_opt, str) and template_opt.strip():
            t_str = template_opt.strip()
            from pathlib import Path
            repo_root = Path(__file__).resolve().parents[2]
            p = Path(t_str)
            if p.exists():
                cmd.extend(["-t", str(p.resolve())])
            elif (repo_root / t_str).exists():
                cmd.extend(["-t", str((repo_root / t_str).resolve())])
            elif t_str.endswith((".yaml", ".yml")) or "/" in t_str or "\\" in t_str:
                raise ValueError(f"Nuclei template not found: {t_str}")
            else:
                cmd.extend(["-t", t_str])

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
