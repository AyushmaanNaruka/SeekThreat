# Level 3 of Layer 2 Second Part — Walkthrough

**Level:** 3 of 5 — *Real Source Implementations*
**Branch:** mayank_level2_second
**Completed:** 2026-10-05
**Decision logged:** D-034
**CI:** ruff clean · pytest 75/75

---

## What Level 3 does

Level 3 replaces stub load() methods in secondary.py with real local-mirror readers
and wires them into FusionEngine. It adds:

1. **VulnrichmentSource** — reads CISA SSVC decision-point data; supplies CVSS, CWE, and
   description as the first fallback after CVE.org.
2. **EUVDSource** — reads ENISA European Vulnerability Database JSON as the second fallback.
3. **ExploitDBSource** — maps CVE IDs to ExploitDB IDs (e.g. `EDB-50592`).
   Hard Rule 4 enforced: IDs and boolean flag only, never exploit code.
4. **MetasploitSource** — maps CVE IDs to module names (e.g.
   `exploit/multi/http/log4shell_header_injection`).
   Hard Rule 4 enforced: module names only, no Ruby source code.
5. **FeedSyncer secondary methods** — `sync_vulnrichment()`, `sync_euvd()`,
   `sync_exploitdb()`, `sync_metasploit()`.
6. **FusionEngine wiring** — secondary sources joined into per-field fallback chain and
   exploit-availability signal.
7. **Synthetic fixtures** for every new source (marked `"_synthetic": true`).
8. **Unit and integration tests** — 75 tests, all passing.

---

## File map

| File | Role | Added / Changed |
|---|---|---|
| `services/enrichment/sources/secondary.py` | Real loaders: Vulnrichment, EUVD, ExploitDB, Metasploit | Changed |
| `services/enrichment/sources/sync.py` | FeedSyncer secondary sync methods + upstream URLs | Changed |
| `services/enrichment/sources/__init__.py` | Exports for all new record classes | Changed |
| `services/enrichment/fusion.py` | `_exploit_fields()`, secondary sources in constructor and `fuse()` | Changed |
| `tests/unit/test_vulnrichment_source.py` | 7 unit tests for VulnrichmentSource | Added |
| `tests/unit/test_euvd_source.py` | 6 unit tests for EUVDSource | Added |
| `tests/unit/test_exploitdb_source.py` | 6 unit tests for ExploitDBSource | Added |
| `tests/unit/test_metasploit_source.py` | 6 unit tests for MetasploitSource | Added |
| `tests/unit/test_enrichment_fallback.py` | Integration: full chain + exploit availability | Changed |
| `tests/unit/test_feed_sync.py` | Secondary sync tests added | Changed |
| `tests/fixtures/enrichment/vulnrichment_sample.json` | Synthetic fixture (3 CVEs) | Added |
| `tests/fixtures/enrichment/euvd_sample.json` | Synthetic fixture (2 CVEs) | Added |
| `tests/fixtures/enrichment/exploitdb_sample.json` | Synthetic fixture (EDB-IDs for 3 CVEs) | Added |
| `tests/fixtures/enrichment/metasploit_sample.json` | Synthetic fixture (2 CVEs → module names) | Added |
| `tests/fixtures/enrichment/README.md` | Fixture catalogue updated with 4 new entries | Changed |
| `THIRD_PARTY.md` | 4 new source entries (licence-checked) | Changed |
| `DECISIONS.md` | D-034 logged | Changed |

---

## Architecture — fallback chain after Level 3

`
Per-field fallback order (CVSS, CWE, description each resolve independently):

  CVE.org          (Source.CVE_ORG,       Confidence.HIGH)
    ↓ field missing?
  Vulnrichment     (Source.VULNRICHMENT,  Confidence.MEDIUM)
    ↓ field missing?
  EUVD             (Source.EUVD,          Confidence.MEDIUM)
    ↓ still missing?
  DERIVED          (Source.DERIVED,       Confidence.LOW — placeholder, labelled)

Exploit availability (parallel signals, not part of the CVSS/CWE fallback chain):

  ExploitDB mirror loaded?
    YES → has_public_exploit = True/False (HIGH), exploit_ids list (HIGH)
    NO  → has_public_exploit = None (DERIVED/LOW, "status unknown")

  Metasploit mirror loaded?
    YES → has_metasploit_module = True/False (HIGH), metasploit_modules list (HIGH)
    NO  → has_metasploit_module = None (DERIVED/LOW, "status unknown")
`

**Key constraint:** Each field resolves *independently*.
CVSS can come from Vulnrichment while CWE comes from CVE.org.
Provenance is per-field, never per-finding.

---

## Section-by-section walkthrough

### 3.1 — VulnrichmentSource

**Files:**
- Implementation: `services/enrichment/sources/secondary.py` (class `VulnrichmentSource`)
- Tests: `tests/unit/test_vulnrichment_source.py`
- Fixture: `tests/fixtures/enrichment/vulnrichment_sample.json`

`VulnrichmentSource.load()` reads a JSON mirror that supports two layouts:

- **Flat keyed dict** — `{ "CVE-2021-44228": { "cveId": "…", "cvss_score": 10.0 } }`
  (the format our `FeedSyncer` writes after normalisation).
- **CVE v5 container** — `{ "cveMetadata": {…}, "containers": { "adp": […] } }`
  (upstream CISA Vulnrichment format with ADP enrichment blocks).

`_parse_record()` normalises both layouts. For CVE v5, it walks the `adp` containers:

`python
for adp in adps:
    for metric in adp.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss_score = _safe_float(mdata["baseScore"])
                cvss_vector = mdata["vectorString"]
        if not ssvc_decision and "other" in metric:
            ssvc_decision = content["decision"]   # SSVC from other.content.decision
    for pt in adp.get("problemTypes", []):
        cwe_ids.append(desc["cweId"])             # CWE from problemTypes.descriptions
`

**Tests (7):**

| Test | Verifies |
|---|---|
| `test_load_from_mirror_file` | `is_loaded` True, record count ≥ 3 |
| `test_lookup_by_cve_id` | CVSS score, vector, CWE, SSVC, description all returned |
| `test_lookup_case_insensitive` | `cve-2021-44228` normalised to `CVE-2021-44228` |
| `test_lookup_missing_returns_none` | Unknown CVE → `None`, no exception |
| `test_missing_cache_file_graceful` | Absent file → loaded=False, count=0 |
| `test_malformed_json_graceful` | Truncated JSON → clears cache, does not crash |
| `test_parse_cvev5_adp_container_format` | Parses real upstream CVE v5 ADP layout |

---

### 3.2 — EUVDSource

**Files:**
- Implementation: `services/enrichment/sources/secondary.py` (class `EUVDSource`)
- Tests: `tests/unit/test_euvd_source.py`
- Fixture: `tests/fixtures/enrichment/euvd_sample.json`

ENISA EUVD is a beta source — the loader is intentionally permissive. It accepts field
aliases (`cvss_score` or `cvssBaseScore`; `description` or `summary`) and silently
returns `None` for missing records.

**Tests (6):**

| Test | Verifies |
|---|---|
| `test_load_from_mirror_file` | `is_loaded`, record count |
| `test_lookup_returns_record` | CVSS, CWE, description; Source=EUVD, Confidence=MEDIUM |
| `test_lookup_case_insensitive` | Case normalisation |
| `test_lookup_missing_returns_none` | Unknown CVE → `None` |
| `test_missing_cache_file_graceful` | Absent file → loaded=False |
| `test_malformed_json_graceful` | Malformed JSON → no crash |

---

### 3.3 — Fallback chain integration test

**File:** `tests/unit/test_enrichment_fallback.py` — class `TestFullFallbackChainIntegration`

Builds a `FusionEngine` from synthetic fixture files on disk:

`python
engine = FusionEngine(
    cve_org=CVEOrgSource(cache_file=FIXTURES_DIR / "cve_org_sample.json"),
    cisa_kev=CISAKevSource(cache_file=FIXTURES_DIR / "cisa_kev_sample.json"),
    first_epss=FirstEPSSSource(cache_file=FIXTURES_DIR / "epss_v4_sample.json"),
    vulnrichment=VulnrichmentSource(cache_file=FIXTURES_DIR / "vulnrichment_sample.json"),
    euvd=EUVDSource(cache_file=FIXTURES_DIR / "euvd_sample.json"),
)
`

Verifies all four positions in the fallback chain:

| Position | CVE tested | Expected source | Confidence |
|---|---|---|---|
| 1. Primary | `CVE-2021-44228` | `CVE_ORG` | HIGH |
| 2. Vulnrichment fallback | `CVE-2025-0001` | `VULNRICHMENT` | MEDIUM |
| 3. EUVD fallback | `CVE-2025-0002` | `EUVD` | MEDIUM |
| 4. Derived placeholder | `CVE-2025-9999` | `DERIVED` | LOW |

The fixtures for `CVE-2025-0001` and `CVE-2025-0002` are deliberately absent from
`cve_org_sample.json` to exercise each fallback position in isolation.

Also added: class `TestExploitAvailabilityIntegration` — two tests:

- `test_exploit_signals_when_mirrors_loaded`: Log4Shell gets
  `has_public_exploit=True` (ExploitDB), `exploit_ids=["EDB-50592","EDB-50593"]`,
  `has_metasploit_module=True`, `metasploit_modules=[...]`.
- `test_exploit_signals_when_mirrors_unloaded`: Absent mirror files yield
  `has_public_exploit=None` (DERIVED/LOW) — not False, because absent ≠ confirmed absent.

---

### 3.4 — ExploitDBSource

**Files:**
- Implementation: `services/enrichment/sources/secondary.py` (class `ExploitDBSource`)
- Tests: `tests/unit/test_exploitdb_source.py`
- Fixture: `tests/fixtures/enrichment/exploitdb_sample.json`

The loader handles two mirror formats:

- **JSON** — `{ "CVE-…": { "exploit_ids": ["EDB-50592"], "has_public_exploit": true } }`
  written by `FeedSyncer.sync_exploitdb()`.
- **CSV** — `files_exploits.csv` (ExploitDB GitLab export). Parses the `codes` column
  for CVE references using `CVE_PATTERN`, formats each ID as `EDB-{id}`.

`python
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
`

Hard Rule 4 enforcement:
- `ExploitDBRecord` has **no** `code`, `payload`, or `exploit_body` attribute.
- CSV parser reads **only** `id` and `codes` columns; all other columns ignored.
- Tests assert those attributes do not exist on the record.

**Tests (6):**

| Test | Verifies |
|---|---|
| `test_load_from_mirror_file` | `is_loaded`, count |
| `test_lookup_record_ids_only` | `exploit_ids`, `has_public_exploit`, no code attrs |
| `test_lookup_case_insensitive` | Lower-case CVE ID works |
| `test_lookup_missing_returns_none` | Unknown CVE → `None` |
| `test_missing_cache_file_graceful` | Absent file → count=0 |
| `test_load_from_csv_mirror` | CSV round-trip: `EDB-50592` maps to `CVE-2021-44228` |

---

### 3.5 — MetasploitSource

**Files:**
- Implementation: `services/enrichment/sources/secondary.py` (class `MetasploitSource`)
- Tests: `tests/unit/test_metasploit_source.py`
- Fixture: `tests/fixtures/enrichment/metasploit_sample.json`

Parses two layouts:

- **Rapid7 native** — `{ "exploit/multi/http/log4shell_header_injection": { "references": ["CVE-2021-44228"] } }`
  Detected when the first non-`_` key's value has a `"references"` key.
  Inverted: module-to-CVEs becomes CVE-to-modules.
- **Pre-keyed** — `{ "CVE-…": { "module_names": ["exploit/…"] } }`
  Written by `FeedSyncer.sync_metasploit()`.

Detection heuristic:

`python
first_key = next((k for k in data if not k.startswith("_")), "")
first_val = data.get(first_key)
if isinstance(first_val, dict) and "references" in first_val:
    # Rapid7 native format — invert to CVE → [module_names]
`

Hard Rule 4 enforcement:
- `MetasploitRecord` has **only** `module_names` (list of strings) and
  `has_metasploit_module` (bool).
- Parser reads **only** the `references` list from each module entry; ignores
  `path`, `rank`, `arch`, etc.

**Tests (6):**

| Test | Verifies |
|---|---|
| `test_load_from_mirror_file` | `is_loaded`, count |
| `test_lookup_record_module_names_only` | Names list, boolean flag, no code attrs |
| `test_lookup_case_insensitive` | Case normalisation |
| `test_lookup_missing_returns_none` | Unknown CVE → `None` |
| `test_missing_cache_file_graceful` | Absent file |
| `test_load_rapid7_native_format` | Inverts `module → [CVE,…]` into `CVE → [module,…]` |

---

### 3.6 — FeedSyncer secondary methods

**File:** `services/enrichment/sources/sync.py`

| Method | Upstream URL constant | Format written to mirror |
|---|---|---|
| `sync_vulnrichment()` | `DEFAULT_VULNRICHMENT_URL` | JSON dict keyed by CVE ID |
| `sync_euvd()` | `DEFAULT_EUVD_URL` | JSON as-returned by ENISA API |
| `sync_exploitdb()` | `DEFAULT_EXPLOITDB_URL` | JSON `{ CVE: {exploit_ids, …} }` |
| `sync_metasploit()` | `DEFAULT_METASPLOIT_URL` | JSON `{ CVE: {module_names, …} }` |

`sync_exploitdb()` auto-detects response format:

`python
if text.strip().startswith("{") or text.strip().startswith("["):
    payload = response.json()   # upstream returned JSON already
else:
    reader = csv.DictReader(io.StringIO(text))   # parse files_exploits.csv
    # extract id + codes → normalise to {CVE: {exploit_ids}} dict
`

All four methods delegate to `SourceSynchronizer.sync_from_data()` for atomic
write (temp file → rename), so a download failure never corrupts the existing mirror.

`sync_all(include_secondary=True)` runs all seven sources.

**Upstream licence verification:**

| Source | Licence | Decision |
|---|---|---|
| CISA Vulnrichment | CC0 / Public Domain | ✅ Allowed |
| ENISA EUVD | Open Data / EUPL | ✅ Allowed (data, not code) |
| ExploitDB Metadata | Public Metadata | ✅ IDs only (Hard Rule 4) |
| Rapid7 Metasploit | BSD-3-Clause | ✅ Allowed; no AGPL/GPL |

All four entries recorded in `THIRD_PARTY.md`.

---

### FusionEngine integration

**File:** `services/enrichment/fusion.py`

#### Constructor

`python
def __init__(self, …, vulnrichment, euvd, exploitdb, metasploit, cache_dir):
    self.vulnrichment = vulnrichment or (
        VulnrichmentSource(cache_file=_path(Source.VULNRICHMENT))
        if cache_dir is not None else None
    )
    # same pattern for euvd, exploitdb, metasploit
`

When `cache_dir` is provided, all four secondary sources are instantiated automatically.
When `cache_dir` is `None` and no explicit source is passed, secondary sources are
`None` — backwards-compatible with callers that only pass primary sources.

#### `_chain_records()` — per-field fallback chain

Returns `[CVEOrgRecord?, VulnrichmentRecord?, EUVDRecord?]` for a CVE ID.
`fuse()` iterates this chain per field and takes the first non-empty value.

#### `_exploit_fields()` — parallel exploit signals

`python
if self.exploitdb is not None:
    if not self.exploitdb.is_loaded:
        out["has_public_exploit"] = Attributed(None, DERIVED/LOW)  # unknown
    else:
        edb_ids = [id for cve in cve_ids for rec in [exploitdb.lookup(cve)] …]
        out["has_public_exploit"] = Attributed(bool(edb_ids), EXPLOITDB/HIGH)
        if edb_ids:
            out["exploit_ids"] = Attributed(sorted(edb_ids), EXPLOITDB/HIGH)

# Identical pattern for metasploit → has_metasploit_module + metasploit_modules
`

An unloaded mirror yields `value=None` (unknown), **not** `value=False`.
This mirrors the `in_kev` pattern: absent data ≠ confirmed absence.

---

## Synthetic fixtures

All fixtures carry `"_synthetic": true` and `"_comment"` keys. Loaders skip keys
prefixed with `_`.

| Fixture | CVEs covered | Exercises |
|---|---|---|
| `vulnrichment_sample.json` | `CVE-2021-44228`, `CVE-2021-41773`, `CVE-2025-0001` | SSVC, CVSS, CWE fallback |
| `euvd_sample.json` | `CVE-2025-0002`, `CVE-2022-22947` | EUVD-only CVSS fallback |
| `exploitdb_sample.json` | `CVE-2021-44228`, `CVE-2021-41773`, `CVE-2022-22947` | Multi-EDB-ID mapping |
| `metasploit_sample.json` | `CVE-2021-44228`, `CVE-2021-41773` | Rapid7 native + pre-keyed formats |

---

## Level 3 checklist — all items verified

| Item | Status |
|---|---|
| Vulnrichment reader is real (not a stub) | ✅ |
| EUVD reader is real (not a stub) | ✅ |
| Fallback chain tested end-to-end with per-field provenance | ✅ |
| ExploitDB returns IDs only (Hard Rule 4 satisfied) | ✅ |
| Metasploit returns module names only (Hard Rule 4 satisfied) | ✅ |
| All new fixtures marked `"_synthetic": true` | ✅ |
| New dependency licences checked and in `THIRD_PARTY.md` | ✅ |
| `ruff check` clean | ✅ |
| `pytest` 75/75 passed | ✅ |
| D-034 logged in `DECISIONS.md` | ✅ |

---

## Constraints respected

| Constraint | How enforced |
|---|---|
| No network on request path | `FeedSyncer` is the only network-touching class; sources read mirror files |
| Hard Rule 4 — ExploitDB | Record model has no exploit code fields; CSV parser ignores `file` column |
| Hard Rule 4 — Metasploit | Record model has no code fields; parser ignores all but `references` |
| No AGPL/GPL code | All four sources are CC0 / public domain / BSD / open data |
| Tests first | Unit tests for each source written before `load()` implementations |
| Every field attributed | All new fields wrapped in `Attributed[EnrichmentValue]` with full `Provenance` |

---

## What Level 4 builds on this

Level 4 (NVD-Only Baseline Eval) runs `FusionEngine` in two configurations:

1. **CVE.org-only** — secondary sources absent; represents the NVD-era baseline.
2. **Full multi-source** — all seven sources loaded from mirror files.

It counts filled vs. placeholder fields per configuration and reports the coverage
improvement. Level 3 makes this measurement meaningful: without real secondary source
readers the eval harness has nothing to compare against.

---

_Walkthrough written 2026-10-05 after verifying all 75 tests passing and ruff clean._
