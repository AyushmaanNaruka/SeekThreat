# Walkthrough - Task 3: Multi-Source Fusion Engine & Fallback Chain (Track 2 — Enrichment)

> **Document:** `docs/mayank_implementation/task_3_level_2_walkthrough.md`  
> **Topic:** Task 3 (Track 2 Enrichment — Multi-Source Fusion Engine & Fallback Chain) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

In accordance with [level2_status.md](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_status.md#L131) and the core architectural rules of [services/enrichment/README.md](file:///e:/SeekThreat/SeekThreat/services/enrichment/README.md#L32), **Task 3** delivers SeekThreat's multi-source intelligence fusion engine.

### The Research Contribution & Architectural Context

In April 2026, the NVD ceased enriching approximately 80–85% of incoming and historical CVEs, leaving over 29,000 vulnerabilities marked "Not Scheduled." Conventional vulnerability scanners and assessment platforms that query NVD directly now return empty metrics for the majority of discovered issues.

**SeekThreat's Fusion Engine (`services/enrichment/fusion.py`)** solves this problem by fusing multi-source threat intelligence with explicit fallback hierarchies and strict provenance attribution:
1. **Fallback Chain (Rule 2):** `CVE.org -> CISA Vulnrichment -> ENISA EUVD -> derived`. If a primary source lacks metrics, the engine descends deterministically down the priority chain. When all external sources lack CVSS, the engine synthesizes a derived baseline clearly marked as `Source.DERIVED` and `Confidence.LOW`.
2. **Mandatory Provenance Wrapping (Rule 1):** Every enriched attribute is wrapped in an [Attributed[EnrichmentValue]](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L62) container. Because `Attributed` requires both a value and a non-null [Provenance](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L43) object, unattributed values are structurally unrepresentable in the system.
3. **Multi-CVE Aggregation:** When a scanner finding correlates with multiple CVEs (e.g., Spring Cloud Gateway Actuator injection paired with Spring4Shell), the engine deterministically selects the maximum CVSS severity, aggregates the union of CWE identifiers, detects affirmative CISA KEV membership, and selects the peak EPSS exploit probability while citing the specific CVE responsible for each metric.
4. **Heuristic Non-CVE Findings:** Scanner observations without CVE identifiers (e.g., obsolete TLS ciphers or self-signed certificates) degrade gracefully into derived baseline scores with clear explanatory notes.

---

## 2. What Was Built

### A. Fusion Engine Implementation
* **[services/enrichment/fusion.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/fusion.py)**:
  * `FusionEngine`:
    * Accepts mirrored source clients: `CVEOrgSource`, `CISAKevSource`, `FirstEPSSSource`, and optional secondary clients (`VulnrichmentSource`, `EUVDSource`).
    * `fuse(finding: Finding) -> dict[str, Attributed[EnrichmentValue]]`: Ingests a raw scanner `Finding` and produces an attributed intelligence dictionary.
    * `fuse_to_enriched_finding(finding: Finding) -> EnrichedFinding`: Packages the finding and fused fields into the domain model.
  * `_resolve_cvss_and_cwe(cve_id)`: Implements the exact 4-tier fallback chain:
    1. **Primary (CVE.org):** If the canonical CNA record supplies CVSS, adopts with `Source.CVE_ORG` and `Confidence.HIGH`.
    2. **Secondary (CISA Vulnrichment):** If CVE.org lacks CVSS, checks Vulnrichment (`Source.VULNRICHMENT`, `Confidence.MEDIUM`).
    3. **Tertiary (ENISA EUVD):** If Vulnrichment is empty, checks EUVD (`Source.EUVD`, `Confidence.MEDIUM`).
    4. **Quaternary (Derived Fallback):** If all upstream sources lack metrics, synthesizes a baseline fallback with `Source.DERIVED`, `Confidence.LOW`, and an explanatory note.
  * Standard fused fields populated:
    * `cvss_score`: float base score (`Attributed[EnrichmentValue]`).
    * `cvss_vector`: string vector string (`Attributed[EnrichmentValue]`).
    * `cwe_ids`: list of CWE identifiers (`Attributed[EnrichmentValue]`).
    * `in_kev`: boolean confirmed active exploitation flag (`Attributed[EnrichmentValue]`).
    * `kev_date_added`: date added to KEV catalog if in KEV (`Attributed[EnrichmentValue]`).
    * `ransomware_use`: known ransomware campaign usage if in KEV (`Attributed[EnrichmentValue]`).
    * `epss_score`: FIRST EPSS v4 probability score (`Attributed[EnrichmentValue]`).
    * `epss_percentile`: FIRST EPSS v4 percentile ranking (`Attributed[EnrichmentValue]`).
    * `summary`: textual summary extracted from canonical CVE descriptions or scanner titles (`Attributed[EnrichmentValue]`).

---

### B. Secondary Source Records Enhancement
* **[services/enrichment/sources/secondary.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/sources/secondary.py)**:
  * Updated `VulnrichmentRecord` and `EUVDRecord` models to provide `cvss_score`, `cvss_vector`, and `cwe_ids` fields, enabling end-to-end fallback chain testing across secondary sources.

---

### C. Package Module Exports
* **[services/enrichment/__init__.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/__init__.py)**:
  * Clean top-level exports for `FusionEngine` and the `fuse_finding()` convenience function.

---

## 3. Verification & Test Results

### Unit Test Execution
We implemented 10 comprehensive unit tests in [tests/unit/test_enrichment_fallback.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_enrichment_fallback.py) covering all fallback branches, multi-CVE aggregation, and provenance invariants:
```bash
python -m pytest tests/unit/test_enrichment_fallback.py -v
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 10 items

tests\unit\test_enrichment_fallback.py::TestFallbackChain::test_cve_org_primary_selected_when_present PASSED [ 10%]
tests\unit\test_enrichment_fallback.py::TestFallbackChain::test_fallback_to_vulnrichment_when_cve_org_lacks_cvss PASSED [ 20%]
tests\unit\test_enrichment_fallback.py::TestFallbackChain::test_fallback_to_euvd_when_cve_org_and_vulnrichment_lack_cvss PASSED [ 30%]
tests\unit\test_enrichment_fallback.py::TestFallbackChain::test_fallback_to_derived_when_all_sources_lack_cvss PASSED [ 40%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_log4shell_fusion PASSED [ 50%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_multi_cve_aggregation_selects_max_severity PASSED [ 60%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_non_kev_moderate_finding PASSED [ 70%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_heuristic_non_cve_finding_fusion PASSED [ 80%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_every_field_wrapped_in_attributed PASSED [ 90%]
tests\unit\test_enrichment_fallback.py::TestFusionIntelligenceOutputs::test_fuse_to_enriched_finding PASSED [100%]

============================= 10 passed in 0.48s ==============================
```

### Full Regression & Architecture Guard Execution
- Entire unit test suite: **258 passed, 1 skipped** (`python -m pytest tests/unit/`).
- Architecture gates: **11 passed** (`python -m pytest tests/architecture/`).

---

## 4. Next Step

With Tasks 1, 2, and 3 complete, we have verified multi-source intelligence retrieval and fusion. We can now proceed to **Task 4: Exposure Risk Score (ERS) Engine (`services/enrichment/ers.py` & D-008)**, implementing the additive, self-explaining composite risk calculation with hand-tuned weights, strictly guarding against multiplying EPSS by CVSS.
