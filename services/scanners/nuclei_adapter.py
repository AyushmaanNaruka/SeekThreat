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


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    version_command = ["nuclei", "-version"]
    content_type = "application/x-ndjson"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def _execute(self, request: ScanRequest) -> str:
        # Caller-supplied flags are NOT accepted here — see the identical note in
        # nmap_adapter.py and DECISIONS.md D-017. nuclei's `-u` is a repeatable flag,
        # so an extra_args entry of `-u <other-host>` would add a second, unauthorized
        # target; `-l <file>` would redirect the whole scan to an arbitrary list.
        cmd = [
            "nuclei",
            "-u",
            request.target,
            "-jsonl",
            "-silent",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=request.options.get("timeout", 1800),
            check=True,
        )
        return result.stdout.decode("utf-8", errors="replace")

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_nuclei_json(artifact, engagement_id=request.authorization.engagement_id)
