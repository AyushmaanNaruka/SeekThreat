"""
Nmap adapter — reference implementation. Copy this shape for new scanners.

LICENCE NOTE: Nmap is under the NPSL, which interprets "derivative work" broadly.
We invoke the binary and parse its XML output. We never vendor or link Nmap source.
Keep it that way.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime

from .base import Observation, RawArtifact, ScannerAdapter, ScanRequest
from .nmap_xml import parse_nmap_xml, parse_run_timestamp

DEFAULT_PORTS = "22,80,443,8000,8080"
PORTS_REGEX = re.compile(r"^(?:-p-|[0-9,\-]+)$")


def _resolve_nmap_bin() -> str | None:
    from apps.api.core.config import settings

    if settings.nmap_path:
        from pathlib import Path

        p = Path(settings.nmap_path)
        if p.is_file():
            return str(p)
    return shutil.which("nmap")


class NmapAdapter(ScannerAdapter):
    name = "nmap"
    content_type = "application/xml"

    @property
    def version_command(self) -> list[str]:  # type: ignore[override]
        exe = _resolve_nmap_bin() or "nmap"
        return [exe, "--version"]

    def is_available(self) -> bool:
        return _resolve_nmap_bin() is not None

    def _execute(self, request: ScanRequest) -> str:
        # The argv is fixed except for the target. Caller-supplied flags are NOT
        # accepted: the authorization gate proves `request.target` is permitted, and
        # an extra flag can add a second target (`nmap -sV 1.2.3.4 <target>` scans
        # both) or redirect the scan entirely. Anything that can change what gets
        # scanned has to be something the gate saw. See DECISIONS.md D-017.
        exe = _resolve_nmap_bin() or "nmap"
        cmd = [exe]
        if request.options.get("no_ping", False):
            cmd.append("-Pn")  # treat hosts as up; needed on Windows without Npcap admin mode
        if request.options.get("service_detection", True):
            cmd.append("-sV")  # service/version detection
        cmd.append("-T4")  # faster timing

        ports_opt = request.options.get("ports", "")
        if isinstance(ports_opt, str) and ports_opt.strip():
            clean_ports = ports_opt.strip()
            if not PORTS_REGEX.match(clean_ports):
                raise ValueError(f"Invalid ports option {clean_ports!r}: must match ^[0-9,\\-]+$")
            cmd.extend(["-p", clean_ports])
        elif request.options.get("fast", False):
            cmd.append("-F")
        else:
            cmd.extend(["-p", DEFAULT_PORTS])

        cmd.extend(
            [
                "-oX",
                "-",
                "--",  # end of options: a target starting with '-' is not read as a flag
                request.target,
            ]
        )
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=request.options.get("timeout", 1800),
            check=True,
        )
        # Decoded explicitly, not via text=True: that flag applies universal-newline
        # translation, which would make the "verbatim" artifact platform-dependent and
        # its content hash unstable across Windows and Linux.
        return result.stdout.decode("utf-8", errors="replace")

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        # Scanners emit Observation only; Finding is services.normalize's output, built
        # from observations across scanners. Never assign severity here — that belongs
        # to services.enrichment.
        return parse_nmap_xml(artifact, engagement_id=request.authorization.engagement_id)
