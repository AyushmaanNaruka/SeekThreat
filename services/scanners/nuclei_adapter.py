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
        cmd = [
            "nuclei",
            "-u",
            request.target,
            "-jsonl",
            "-silent",
            *request.options.get("extra_args", []),
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
