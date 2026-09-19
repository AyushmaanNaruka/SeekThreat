# Task 5 Walkthrough — Second Core Scanner: Nuclei Adapter

> **Layer:** 1 (Collection)  
> **Task:** 5 of 7  
> **Status:** ✅ Complete — 164/164 tests passing (+11 new Nuclei unit tests, +3 architecture gate tests for NucleiAdapter)  
> **Reference:** [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) (MIT License)  
> **Files touched:** 5 new files, 3 modified  

---

## 1. Goal

Add **Nuclei** as the second core scanner adapter, following the same contract as `NmapAdapter`:

1. Invoke the binary as a subprocess without vendoring source code (Nuclei MIT licence).
2. Parse its NDJSON output into `Observation` records in a pure, deterministic function.
3. Emit `ObservationKind.VULN_CANDIDATE` observations, preserving raw tool metadata without assigning risk scores (scoring lives in `services.enrichment`).
4. Get automatically discovered and gate-tested by `tests/architecture/test_authorization_gate.py` — zero changes to that test file.

---

## 2. Files Delivered & Modified

| File | Type | Purpose |
|---|:---:|---|
| [`services/scanners/nuclei_adapter.py`](file:///e:/SeekThreat/SeekThreat/services/scanners/nuclei_adapter.py) | New | `NucleiAdapter(ScannerAdapter)` subclass — subprocess invocation and parse delegation. |
| [`services/scanners/nuclei_json.py`](file:///e:/SeekThreat/SeekThreat/services/scanners/nuclei_json.py) | New | Pure NDJSON/JSON-array parser → `tuple[Observation, ...]`. |
| [`services/scanners/__init__.py`](file:///e:/SeekThreat/SeekThreat/services/scanners/__init__.py) | Modified | Exports `NucleiAdapter`, `parse_nuclei_json`, `NucleiParseError`. |
| [`apps/api/tasks/scans.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/scans.py) | Modified | Adds `elif scanner == "nuclei"` dispatch branch in `execute_scan`. |
| [`tests/fixtures/nuclei/`](file:///e:/SeekThreat/SeekThreat/tests/fixtures/nuclei/) | New | 6 fixture files: `lab_baseline.jsonl`, `single_cve.jsonl`, `empty.jsonl`, `json_array.json`, `malformed.jsonl`, `malicious_attributes.jsonl`. |
| [`tests/unit/test_nuclei_json.py`](file:///e:/SeekThreat/SeekThreat/tests/unit/test_nuclei_json.py) | New | 11 unit tests covering parsing, CVE extraction, edge cases, and adapter mock. |
| [`DECISIONS.md`](file:///e:/SeekThreat/SeekThreat/DECISIONS.md) | Modified | Added ADR **D-015** documenting Nuclei + NDJSON design decisions. |
| [`docs/mayank_implementation/build.md`](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/build.md) | Modified | Task 5 marked complete; checklist table updated to 164/164 tests. |

---

## 3. Design Walk-Through

### 3.1 NucleiAdapter (`services/scanners/nuclei_adapter.py`)

Follows the exact shape of `NmapAdapter`:

```python
class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    version_command = ["nuclei", "-version"]
    content_type = "application/x-ndjson"

    def _execute(self, request: ScanRequest) -> str:
        cmd = ["nuclei", "-u", request.target, "-jsonl", "-silent",
               *request.options.get("extra_args", [])]
        result = subprocess.run(cmd, capture_output=True,
                                timeout=request.options.get("timeout", 1800), check=True)
        return result.stdout.decode("utf-8", errors="replace")

    def _captured_at(self, raw: str) -> datetime:
        return parse_run_timestamp(raw)

    def _parse(self, artifact: RawArtifact, request: ScanRequest) -> tuple[Observation, ...]:
        return parse_nuclei_json(artifact, engagement_id=request.authorization.engagement_id)
```

**Key flags used (informed by the Nuclei repo):**
- `-u <target>`: Single URL/IP/hostname scan target.
- `-jsonl`: One JSON object per line (NDJSON), safe for streaming and partial failures.
- `-silent`: Suppresses progress banners so stdout is pure NDJSON.

### 3.2 Pure Parser (`services/scanners/nuclei_json.py`)

`parse_nuclei_json(artifact, engagement_id) -> tuple[Observation, ...]`:

- Handles both **NDJSON** (line-by-line JSON objects) and **JSON arrays** in a single `_load_records()` function.
- Maps each finding to `ObservationKind.VULN_CANDIDATE`.
- Populates `attributes` dict faithfully from the Nuclei JSON schema:

| Attribute Key | Nuclei JSON Field |
|---|---|
| `template_id` | `template-id` |
| `template_name` | `info.name` |
| `scanner_severity` | `info.severity` |
| `type` | `type` (e.g. `"http"`, `"network"`) |
| `host` | `host` |
| `matched_at` | `matched-at` |
| `ip` | `ip` |
| `description` | `info.description` |
| `cve_ids` | `info.classification.cve-id` |
| `cwe_ids` | `info.classification.cwe-id` |
| `cvss_score` | `info.classification.cvss-score` |
| `cvss_metrics` | `info.classification.cvss-metrics` |
| `epss_score` | `info.classification.epss-score` |
| `matcher_name` | `matcher-name` |
| `extracted_results` | `extracted-results` |
| `curl_command` | `curl-command` |

- **Confidence mapping:** `critical/high → HIGH`, `medium/low → MEDIUM`, `info/missing → LOW`.
- **Control-character sanitization:** strips `\x00–\x1f` from all string attributes.
- **Truncation:** any attribute exceeding 512 chars is truncated with `"…[truncated]"` marker.
- **Determinism:** findings are sorted by `(subject, template_id, observation_id)` so identical artifacts always produce byte-identical observations.
- **Content-addressed IDs:** sha256 of `(namespace, engagement_id, scanner, artifact_id, kind, subject, canonical_attrs, observed_at)` — same as nmap parser.

### 3.3 Authorization Gate Auto-Discovery

`tests/architecture/test_authorization_gate.py` discovers all concrete `ScannerAdapter` subclasses by importing every module under `services.scanners`:

```
Collected adapters: [NmapAdapter, NucleiAdapter]
```

Tests run 3 authorization gate checks × 2 adapters = 6 parametrized tests + 1 discovery guard = **7 total** — all passing with zero code changes to the architecture test.

---

## 4. Test Fixtures

| Fixture | Purpose |
|---|---|
| `lab_baseline.jsonl` | 3-finding realistic scan: Log4j CVE-2021-44228 (critical), Apache CVE-2021-41773 (high), nginx version detect (info) |
| `single_cve.jsonl` | One Log4j finding with full metadata including `curl-command` |
| `empty.jsonl` | Zero findings → `()` |
| `json_array.json` | JSON array format → same parse result as equivalent NDJSON |
| `malformed.jsonl` | Truncated JSON → `NucleiParseError` |
| `malicious_attributes.jsonl` | Control characters + 600-char description → sanitized and truncated |

---

## 5. Verification Results

### Nuclei Unit Tests
```bash
python -m pytest tests/unit/test_nuclei_json.py -v
# 11 passed in 3.28s
```

### Architecture Gate (NucleiAdapter auto-discovered)
```bash
python -m pytest tests/architecture/test_authorization_gate.py -v
# 7 passed in 1.86s
```

### Full Repository Test Suite
```bash
python -m pytest tests/ -v
# 164 passed in 10.97s
```

---

## 6. Next Steps

**Task 6** — Lab Expansion & Ground Truth Baseline (`lab/`):
- Expand `lab/docker-compose.yml` to 8–12 hosts across 3 subnets (`dmz`, `internal`, `data`).
- Create `lab/ground_truth.yaml` with every host, service, version, and expected CVE.
