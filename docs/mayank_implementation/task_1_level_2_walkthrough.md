# Walkthrough - Task 1: Fixtures & Baseline Test Harness (Track 2 — Enrichment)

> **Document:** `docs/mayank_implementation/task_1_level_2_walkthrough.md`  
> **Topic:** Task 1 (Track 2 Enrichment — Offline Fixtures & Baseline Test Harness) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

In accordance with [level2_status.md](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_status.md#L79), **Task 1** establishes the foundation for **Track 2 (Enrichment)** in `services/enrichment/`.

Because Track 1 (Collection) and Track 2 (Enrichment) run in parallel, Track 2 cannot wait for live scanner pipelines to emit findings. Following the precedent established during Layer 1 (where the observations endpoint and dashboard were parallelized against snapshotted observation fixtures), Track 2 is built and tested against hand-crafted [Finding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L22) domain objects and offline intelligence feeds.

This task delivered:
1. **Realistic, schema-compliant `Finding` fixtures** covering all critical vulnerability archetypes (single-CVE, multi-CVE, NVD-unenriched recent CVEs, non-KEV vulnerabilities, and scanner heuristics without CVEs).
2. **Offline sample feeds for the 3 MVP intelligence sources** (CVE.org v5.1, CISA KEV, and FIRST EPSS v4) formatted to their official schemas.
3. **Automated unit test coverage** verifying schema invariants, data integrity, and cross-fixture coherence.

---

## 2. What Was Built

### A. Hand-Built Finding Fixtures
* **[tests/fixtures/findings/baseline_findings.py](file:///e:/SeekThreat/SeekThreat/tests/fixtures/findings/baseline_findings.py)**:
  * Emits typed [Finding](file:///e:/SeekThreat/SeekThreat/packages/schema/models/finding.py#L22) objects satisfying all Pydantic v2 invariants:
    * Non-empty `observation_ids` (enforced by `@field_validator`).
    * Timezone-aware UTC `detected_at` timestamps (enforced by `require_aware`).
  * Representative test fixtures:
    * `FINDING_LOG4SHELL` (`CVE-2021-44228`): Critical RCE, present in CISA KEV, top-percentile EPSS (`>0.97`).
    * `FINDING_APACHE_PATH_TRAVERSAL` (`CVE-2021-41773`): Apache 2.4.49 path traversal / RCE from lab ground truth, present in KEV.
    * `FINDING_SPRING_GATEWAY_RCE` (`CVE-2022-22947`, `CVE-2022-22965`): Multi-CVE finding bundling Spring Cloud Gateway code injection and Spring4Shell to test multi-CVE fusion aggregation.
    * `FINDING_NVD_UNENRICHED_RECENT` (`CVE-2024-23897`): Jenkins CLI arbitrary file read, simulating the post-April 2026 NVD enrichment gap where CVE.org CNA provides CVSS v3.1 metrics while NVD is empty.
    * `FINDING_NON_KEV_MODERATE` (`CVE-2020-7699`): express-fileupload prototype pollution, moderate EPSS (`~0.14`), explicitly **not** in KEV.
    * `FINDING_HEURISTIC_NO_CVE`: Scanner heuristic finding (`cve_ids=[]`, weak TLS/ciphers) to verify graceful degradation when no CVE identifier exists.
  * Accessor helpers: `get_baseline_findings() -> list[Finding]` and `get_baseline_findings_by_id() -> dict[str, Finding]`.

---

### B. Offline Intelligence Sample Feeds
* **[tests/fixtures/enrichment/cve_org_sample.json](file:///e:/SeekThreat/SeekThreat/tests/fixtures/enrichment/cve_org_sample.json)**:
  * Structured in official **CVE Services v5.1 / cvelistV5** JSON format.
  * Maps CVE IDs to container records including `cveMetadata`, CNA `title`, `descriptions`, `metrics` (CVSS v3.1 `baseScore`, `vectorString`, and `baseSeverity`), and `problemTypes` (`cweId`).
* **[tests/fixtures/enrichment/cisa_kev_sample.json](file:///e:/SeekThreat/SeekThreat/tests/fixtures/enrichment/cisa_kev_sample.json)**:
  * Structured in official **CISA Known Exploited Vulnerabilities (KEV)** catalog JSON format (`catalogVersion: "2024.09.20"`).
  * Includes positive KEV entries (`CVE-2021-44228`, `CVE-2021-41773`, `CVE-2022-22947`, `CVE-2024-23897`) with `dateAdded`, `requiredAction`, `dueDate`, and `knownRansomwareCampaignUse`.
  * Omits non-KEV vulnerabilities (`CVE-2020-7699`, `CVE-2020-15778`) to provide negative test cases.
* **[tests/fixtures/enrichment/epss_v4_sample.json](file:///e:/SeekThreat/SeekThreat/tests/fixtures/enrichment/epss_v4_sample.json)**:
  * Structured in official **FIRST EPSS v4** API response format (`version: "v4"`).
  * Covers the full spectrum of probability tiers:
    * Very High probability: Log4Shell (`0.97543`, 99.9th percentile).
    * High probability: Apache traversal (`0.94120`), Spring Cloud Gateway (`0.89510`), Spring4Shell (`0.94210`), Jenkins CLI (`0.78120`).
    * Moderate probability: express-fileupload (`0.14250`, 78.5th percentile).
    * Low probability: OpenSSH scp (`0.00420`, 12.5th percentile).

---

### C. Automated Test Suite
* **[tests/unit/test_enrichment_fixtures.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_enrichment_fixtures.py)**:
  * `TestBaselineFindingFixtures`:
    * Validates all 6 baseline findings against Pydantic schema requirements.
    * Verifies non-empty `observation_ids` and timezone-aware `detected_at`.
    * Asserts negative validation: creating a finding with `observation_ids=[]` raises `ValueError`.
  * `TestEnrichmentSampleFeeds`:
    * Asserts `cve_org_sample.json` contains valid CVE records with CVSS v3.1 base scores and CWE IDs.
    * Asserts `cisa_kev_sample.json` accurately differentiates KEV vs non-KEV entries.
    * Asserts `epss_v4_sample.json` has valid v4 floats and percentile distribution.
    * Verifies cross-referencing: every CVE present in baseline findings is fully indexed across all sample feeds.

---

## 3. Verification & Test Results

### Unit Test Execution
```bash
python -m pytest tests/unit/test_enrichment_fixtures.py -v
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 10 items

tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_all_baseline_findings_are_valid_findings PASSED [ 10%]
tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_finding_map_keys_match_ids PASSED [ 20%]
tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_single_cve_finding PASSED [ 30%]
tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_multi_cve_finding PASSED [ 40%]
tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_heuristic_non_cve_finding PASSED [ 50%]
tests\unit\test_enrichment_fixtures.py::TestBaselineFindingFixtures::test_finding_raises_on_empty_observations PASSED [ 60%]
tests\unit\test_enrichment_fixtures.py::TestEnrichmentSampleFeeds::test_cve_org_sample_feed_validity PASSED [ 70%]
tests\unit\test_enrichment_fixtures.py::TestEnrichmentSampleFeeds::test_cisa_kev_sample_feed_validity PASSED [ 80%]
tests\unit\test_enrichment_fixtures.py::TestEnrichmentSampleFeeds::test_epss_v4_sample_feed_validity PASSED [ 90%]
tests\unit\test_enrichment_fixtures.py::TestEnrichmentSampleFeeds::test_fixture_cross_referencing PASSED [100%]

============================= 10 passed in 0.31s ==============================
```

### Full Regression & Architecture Guard Execution
- Entire unit test suite: **237 passed, 1 skipped** (`python -m pytest tests/unit/`).
- Architecture gates: **11 passed** (`python -m pytest tests/architecture/`).

---

## 4. Next Step

With Task 1 complete, the test harness is in place. We can proceed directly to **Task 2: Source Client Architecture & Offline Local Cache (`services/enrichment/sources/`)**, building the local-mirror source clients for CVE.org, CISA KEV, and FIRST EPSS v4.
