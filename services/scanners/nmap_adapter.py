"""
Nmap adapter — reference implementation. Copy this shape for new scanners.

LICENCE NOTE: Nmap is under the NPSL, which interprets "derivative work" broadly.
We invoke the binary and parse its XML output. We never vendor or link Nmap source.
Keep it that way.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime

from .base import Observation, RawArtifact, ScannerAdapter, ScanRequest
from .nmap_xml import parse_nmap_xml, parse_run_timestamp


class NmapAdapter(ScannerAdapter):
    name = "nmap"
    version_command = ["nmap", "--version"]
    content_type = "application/xml"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def _execute(self, request: ScanRequest) -> str:
        # -oX - writes XML to stdout
        cmd = [
            "nmap",
            "-sV",  # service/version detection
            "-oX",
            "-",
            *request.options.get("extra_args", []),
            request.target,
        ]
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
