# Walkthrough - Task 2: Source Client Architecture & Offline Local Cache (Track 2 — Enrichment)

> **Document:** `docs/mayank_implementation/task_2_level_2_walkthrough.md`  
> **Topic:** Task 2 (Track 2 Enrichment — Source Client Architecture & Offline Local Cache) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

In accordance with [level2_status.md](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_status.md#L103) and the foundational rules of [services/enrichment/README.md](file:///e:/SeekThreat/SeekThreat/services/enrichment/README.md#L32), **Task 2** implements the client architecture and local mirror storage for our threat intelligence sources.

### Core Constraints & Design Decisions

1. **Zero request-time API calls (Rule 5):** Intelligence sources are mirrored locally on disk or memory cache. The enrichment pipeline queries local copies only; it never opens network sockets or issues HTTP requests during scan enrichment or API request servicing.
2. **Prioritized intelligence sources:** We implemented the three MVP intelligence feeds required to deliver an end-to-end enrichment pipeline:
   - **CVE.org (Priority 1):** Canonical record, CNA-supplied CVSS/CWE — the new primary source following NVD's enrichment reduction.
   - **CISA KEV (Priority 3):** Confirmed active exploitation in the wild.
   - **FIRST EPSS v4 (Priority 4):** Empirical exploitation probability score and percentile ranking.
3. **Mandatory provenance wrapping (Rule 1):** Every field emitted by our source records provides helper methods returning `Attributed[EnrichmentValue]` containers, ensuring unattributed values are unrepresentable.
4. **Affirmative negative signals:** For authoritative catalogs like CISA KEV, querying a vulnerability not in the catalog returns an affirmative negative record (`is_in_kev: False`, `Confidence.HIGH`) rather than empty data.

---

## 2. What Was Built

### A. Source Base Contract & Record Models
* **[services/enrichment/sources/base.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/base.py)**:
  * `BaseSourceRecord`: Common Pydantic v2 base model holding `cve_id`, `source: Source`, `confidence: Confidence`, `retrieved_at: datetime`, and `raw_payload`.
    * Provides `to_attributed(value, note=...)` to automatically package values into `Attributed[EnrichmentValue]` with immutable `Provenance`.
  * `BaseEnrichmentSource[RecordT]`: Abstract base class managing local cache loading (`load()`), cached lookups (`lookup(cve_id)`), index count (`count()`), and cache clearing (`clear()`).
  * Enforces the zero-network-call invariant during `lookup()`.

---

### B. MVP Source Clients
* **[services/enrichment/sources/cve_org.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/cve_org.py)** (`CVEOrgSource`):
  * **Priority:** 1 (Primary source per README).
  * **Parser:** Ingests official CVE Services v5.1 JSON records.
  * **Extracted Attributes:**
    * CNA title and English descriptions.
    * CVSS base score, vector string, version (`4.0`, `3.1`, `3.0`, `2.0`), and base severity.
    * CWE identifier list (`problemTypes`).
  * **Attributed Helpers:** `get_attributed_cvss()`, `get_attributed_vector()`, `get_attributed_cwe()`, and `get_attributed_description()`.
  * **Features:** Case-insensitive lookups, flexible loading (accepts either a CVE map `{"CVE-XXXX": {...}}` or lists/single records).

* **[services/enrichment/sources/cisa_kev.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/cisa_kev.py)** (`CISAKevSource`):
  * **Priority:** 3 (Confirmed active exploitation).
  * **Parser:** Ingests CISA Known Exploited Vulnerabilities catalog JSON.
  * **Extracted Attributes:** `is_in_kev: bool`, `vendor_project`, `product`, `vulnerability_name`, `date_added`, `required_action`, `due_date`, and `known_ransomware_campaign_use`.
  * **Affirmative Negative Record:** When a CVE is not in the KEV catalog, `lookup()` returns a valid `CISAKevRecord` with `is_in_kev=False` and `Confidence.HIGH`.
  * **Attributed Helpers:** `get_attributed_is_in_kev()`, `get_attributed_date_added()`, and `get_attributed_ransomware_use()`.

* **[services/enrichment/sources/epss.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/epss.py)** (`FirstEPSSSource`):
  * **Priority:** 4 (Exploitation probability).
  * **Parser:** Ingests FIRST EPSS v4 scoring feed JSON.
  * **Extracted Attributes:** `epss: float` (probability between 0.0 and 1.0), `percentile: float` (percentile ranking between 0.0 and 1.0), and calculation `date`.
  * **Attributed Helpers:** `get_attributed_epss()` and `get_attributed_percentile()`.

---

### C. Background Synchronization Coordinator
* **[services/enrichment/sources/sync.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/sync.py)**:
  * `SourceSynchronizer`: Atomically writes an already-fetched feed payload to its local mirror file (`MIRROR_FILENAMES`). It does **not** download feeds, and no scheduled job invokes it yet.
  * `sync_from_data(source, data, count)`: Writes feed data to a temporary file (`.tmp`) and performs an atomic filesystem replace, preventing race conditions or corrupted cache files if an update is interrupted.
  * `get_source_path(source)`: Generates standardized cache file paths (`cve_org.json`, `cisa_kev.json`, `epss_v4.json`).

---

### D. Secondary Source Stubs
* **[services/enrichment/sources/secondary.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/secondary.py)**:
  * Clean, typed stubs defining the roadmap for secondary sources in exact priority order:
    1. `VulnrichmentSource` (Priority 2) - CISA SSVC decision points, CWE, CVSS.
    2. `NVDSource` (Priority 5) - NVD 2.0 fallback.
    3. `EUVDSource` (Priority 6) - ENISA European Vulnerability Database.
    4. `OSVSource` (Priority 7) - OSV.dev package vulnerabilities.
    5. `GHSASource` (Priority 8) - GitHub Security Advisories.
    6. `ExploitDBSource` (Priority 9) - Public exploit existence.
    7. `MetasploitSource` (Priority 10) - Exploit maturity signals.

---

### E. Package Export Interface
* **[services/enrichment/sources/__init__.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/__init__.py)**:
  * Clean exports for all client classes, record models, and synchronizer utilities.

---

## 3. Verification & Test Results

### Unit Test Execution
We implemented dedicated unit tests covering all source clients and operational invariants:
```bash
python -m pytest tests/unit/test_enrichment_sources.py -v
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 11 items

tests\unit\test_enrichment_sources.py::TestCVEOrgSource::test_cve_org_source_loading_and_lookup PASSED [  9%]
tests\unit\test_enrichment_sources.py::TestCVEOrgSource::test_cve_org_case_insensitivity PASSED [ 18%]
tests\unit\test_enrichment_sources.py::TestCVEOrgSource::test_cve_org_missing_cve_returns_none PASSED [ 27%]
tests\unit\test_enrichment_sources.py::TestCVEOrgSource::test_cve_org_attributed_conversion PASSED [ 36%]
tests\unit\test_enrichment_sources.py::TestCISAKevSource::test_cisa_kev_source_loading_and_lookup PASSED [ 45%]
tests\unit\test_enrichment_sources.py::TestCISAKevSource::test_cisa_kev_negative_affirmative_record PASSED [ 54%]
tests\unit\test_enrichment_sources.py::TestFirstEPSSSource::test_epss_source_loading_and_lookup PASSED [ 63%]
tests\unit\test_enrichment_sources.py::TestFirstEPSSSource::test_epss_missing_cve_returns_none PASSED [ 72%]
tests\unit\test_enrichment_sources.py::TestSourcePrioritiesAndIsolation::test_source_priorities_match_readme PASSED [ 81%]
tests\unit\test_enrichment_sources.py::TestSourcePrioritiesAndIsolation::test_lookup_performs_zero_network_calls PASSED [ 90%]
tests\unit\test_enrichment_sources.py::TestSourceSynchronizer::test_synchronizer_atomic_sync PASSED [100%]

============================= 11 passed in 0.67s ==============================
```

### Full Regression & Architecture Guard Execution
- Entire unit test suite: **248 passed, 1 skipped** (`python -m pytest tests/unit/`).
- Architecture gates: **11 passed** (`python -m pytest tests/architecture/`).

---

## 4. Next Step

With Task 1 (Fixtures) and Task 2 (Source Clients) completed and tested, we are ready to move to **Task 3: Multi-Source Fusion Engine & Fallback Chain (`services/enrichment/fusion.py`)**, which will query these source clients, execute the fallback chain (`CVE.org -> Vulnrichment -> EUVD -> derived`), and populate `EnrichedFinding.fields` wrapped in `Attributed[EnrichmentValue]`.
