"""
Nmap adapter — reference implementation. Copy this shape for new scanners.

LICENCE NOTE: Nmap is under the NPSL, which interprets "derivative work" broadly.
We invoke the binary and parse its XML output. We never vendor or link Nmap source.
Keep it that way.
"""

from __future__ import annotations

import shutil
import subprocess

from .base import ScannerAdapter, ScanRequest


class NmapAdapter(ScannerAdapter):
    name = "nmap"
    version_command = ["nmap", "--version"]

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def _execute(self, request: ScanRequest) -> str:
        # -oX - writes XML to stdout
        cmd = [
            "nmap",
            "-sV",                       # service/version detection
            "-oX", "-",
            *request.options.get("extra_args", []),
            request.target,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=request.options.get("timeout", 1800),
            check=True,
        )
        return result.stdout

    def _parse(self, raw: str, request: ScanRequest) -> list:
        # TODO: parse XML into Finding + Asset objects from packages.schema.
        # Each Finding must carry source="nmap" and the raw XML fragment.
        # Do not assign severity here — that belongs to services.enrichment.
        raise NotImplementedError("Parse nmap XML into schema objects")
