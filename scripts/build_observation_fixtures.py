"""Build observation fixtures for the lab hosts not yet covered by a real scan capture.

`tests/fixtures/observations/lab_baseline.json` is a real capture of nmap output against
two of the lab's ten hosts (dvwa, juiceshop). Docker Hub image pulls for the other eight
hosts' images are currently failing on the development machine (DECISIONS.md D-018/D-019),
so nobody can capture real scans of them right now. This script closes that gap
*synthetically*: it takes hand-authored nmap XML / nuclei NDJSON (written to look like
real tool output, with every host/port/service/CVE fact copied verbatim from
`lab/ground_truth.yaml`) and runs it through the actual parsers
(`services/scanners/nmap_xml.py`, `services/scanners/nuclei_json.py`), so the resulting
`Observation` objects are provably parser output, not fabricated data dressed up as
observations.

It never constructs an Observation by hand, and it never touches lab_baseline.xml,
lab_baseline.jsonl or lab_baseline.json — those are real captures and stay untouched.

See tests/fixtures/observations/README.md for which files are real and which are
synthetic, and DECISIONS.md D-018/D-019 for why the real captures could not be extended.

Usage:
    python scripts/build_observation_fixtures.py
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from packages.schema.models.observation import RawArtifact, ScanResult
from services.scanners.nmap_xml import parse_nmap_xml
from services.scanners.nmap_xml import parse_run_timestamp as parse_nmap_run_timestamp
from services.scanners.nuclei_json import parse_nuclei_json
from services.scanners.nuclei_json import parse_run_timestamp as parse_nuclei_run_timestamp

REPO_ROOT = Path(__file__).resolve().parent.parent
NMAP_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "nmap"
NUCLEI_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "nuclei"
OBSERVATION_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "observations"

# Same engagement as lab_baseline.json, since these are the same lab configuration
# ("baseline" in lab/ground_truth.yaml), just additional synthetic scan runs against it.
ENGAGEMENT_ID = "eng-lab-baseline"

# (source nmap XML fixture, output observations fixture)
NMAP_RUNS: tuple[tuple[str, str], ...] = (
    ("lab_dmz_extended.xml", "lab_dmz_extended.json"),
    ("lab_internal.xml", "lab_internal.json"),
    ("lab_data.xml", "lab_data.json"),
)

# (source nuclei NDJSON fixture, output observations fixture)
NUCLEI_RUNS: tuple[tuple[str, str], ...] = (("lab_extended.jsonl", "lab_extended_nuclei.json"),)


def _artifact(scanner: str, content_type: str, raw: str, captured_at: datetime) -> RawArtifact:
    """Build a RawArtifact the same way ScannerAdapter._artifact does.

    Mirrors services/scanners/base.py::ScannerAdapter._artifact exactly (same sha256
    scheme over scanner name, content type and raw content) so these fixture ids are
    computed identically to how a real adapter would compute them for the same tool
    output — not a bespoke hashing scheme invented for this script.
    """
    digest = hashlib.sha256(
        f"{scanner}\x00{content_type}\x00".encode() + raw.encode("utf-8")
    ).hexdigest()
    return RawArtifact(
        artifact_id=f"sha256:{digest}",
        scanner=scanner,
        content=raw,
        content_type=content_type,
        captured_at=captured_at,
    )


def _build_nmap_scan_result(xml_path: Path) -> ScanResult:
    raw = xml_path.read_text(encoding="utf-8")
    captured_at = parse_nmap_run_timestamp(raw)
    artifact = _artifact("nmap", "application/xml", raw, captured_at)
    observations = parse_nmap_xml(artifact, engagement_id=ENGAGEMENT_ID)
    return ScanResult(artifact=artifact, observations=observations)


def _build_nuclei_scan_result(jsonl_path: Path) -> ScanResult:
    raw = jsonl_path.read_text(encoding="utf-8")
    captured_at = parse_nuclei_run_timestamp(raw)
    artifact = _artifact("nuclei", "application/x-ndjson", raw, captured_at)
    observations = parse_nuclei_json(artifact, engagement_id=ENGAGEMENT_ID)
    return ScanResult(artifact=artifact, observations=observations)


def _write(scan_result: ScanResult, out_path: Path) -> None:
    out_path.write_text(scan_result.model_dump_json(indent=2) + "\n", encoding="utf-8")


def main() -> None:
    OBSERVATION_FIXTURES.mkdir(parents=True, exist_ok=True)

    for xml_name, out_name in NMAP_RUNS:
        scan_result = _build_nmap_scan_result(NMAP_FIXTURES / xml_name)
        _write(scan_result, OBSERVATION_FIXTURES / out_name)
        print(f"{xml_name} -> {out_name}: {len(scan_result.observations)} observations")

    for jsonl_name, out_name in NUCLEI_RUNS:
        scan_result = _build_nuclei_scan_result(NUCLEI_FIXTURES / jsonl_name)
        _write(scan_result, OBSERVATION_FIXTURES / out_name)
        print(f"{jsonl_name} -> {out_name}: {len(scan_result.observations)} observations")


if __name__ == "__main__":
    main()
