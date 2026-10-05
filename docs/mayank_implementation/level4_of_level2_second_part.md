# Level 4 of Layer 2 Second Part ? Walkthrough

**Level:** 4 of 5 ? *NVD-Only Baseline Eval (Layer 2 "Done When")*  
**Branch:** mayank_level2_second  
**Completed:** 2026-10-05  
**Decision logged:** D-035  
**CI:** ruff clean ? pytest 67/67 (enrichment suite) / 542 passed  

---

## What Level 4 does

Level 4 satisfies the Layer 2 "Done When" criterion: **enrichment coverage measured against an NVD-only baseline**.
It builds the evaluation harness in `evals/` and executes a fully offline benchmark without fabricating metrics:

1. **Metric Definition (`evals/enrichment_coverage.md`)**: Formalizes the enrichment coverage metric across 6 intelligence dimensions: CVSS score, CWE taxonomy, description, EPSS probability, CISA KEV exploitation status, and weaponized exploit presence (ExploitDB/Metasploit).
2. **Golden Baseline Dataset (`evals/golden/enrichment_baseline.json`)**: Curates 50 CVE inputs across 5 distinct analytical cohorts (NVD Control, NVD Gaps, CISA KEV Exploited, High EPSS / No NVD CVSS, and Weaponized Exploit Entries).
3. **NVDSource & NVDRecord (`services/enrichment/sources/secondary.py`)**: Replaces the stub with a complete JSON mirror loader supporting both flat and official NVD 2.0 API structures; integrates `NVDSource` into `FusionEngine` fallback chain (Priority 5) and baseline configuration.
4. **Offline Evaluation Harness (`evals/enrichment_coverage.py`)**: Executes both NVD-only baseline and SeekThreat multi-source fusion over the dataset, computes per-field and overall coverage metrics, generates structured JSON, and renders human-readable Markdown reports.
5. **Real Offline Measurement (`evals/results/enrichment_coverage_results.md` & `.json`)**: Executes harness over synthetic fixtures, reporting real measured coverage: **4.0% baseline vs 44.7% multi-source (+40.7 pp gain)**. Fully compliant with `evals/README.md` provenance disclosure rules.
6. **Automated Verification (`tests/unit/test_enrichment_coverage_eval.py` & `test_nvd_source.py`)**: 12 new unit tests ensuring harness correctness, placeholder filtering, and NVD source parsing.

---

## File map

| File | Role | Added / Changed |
|---|---|---|
| `evals/enrichment_coverage.md` | Formal metric specification and formula documentation | Added |
| `evals/golden/enrichment_baseline.json` | 50-CVE evaluation dataset spanning 5 cohorts | Added |
| `evals/enrichment_coverage.py` | Offline evaluation harness CLI and reporting engine | Added |
| `evals/results/enrichment_coverage_results.md` | Actual measured Markdown evaluation results report | Added |
| `evals/results/enrichment_coverage_results.json` | Structured JSON results output from harness execution | Added |
| `services/enrichment/sources/secondary.py` | `NVDRecord` and real `NVDSource` mirror loader | Changed |
| `services/enrichment/sources/__init__.py` | Export `NVDRecord` | Changed |
| `services/enrichment/fusion.py` | Integrate `NVDSource` into fallback chain and engine constructor | Changed |
| `tests/fixtures/enrichment/nvd_sample.json` | Synthetic NVD 2.0 mirror sample fixture | Added |
| `tests/unit/test_nvd_source.py` | 6 unit tests for NVDSource loader and parsing | Added |
| `tests/unit/test_enrichment_coverage_eval.py` | 6 unit tests for evaluation harness and metric calculation | Added |
| `tests/unit/test_feed_sync.py` | Formatting & line length fixes | Changed |
| `DECISIONS.md` | Logged D-035 (Evaluation methodology & baseline comparison) | Changed |
| `docs/mayank_implementation/level4_of_level2_second_part.md` | This walkthrough document | Added |

---

## Architecture & Evaluation Methodology

### Evaluation Configurations

```
Finding (CVE ID)
       ?
       ??????????????????????????????????????????????????????????????????????
       ?                                 ?                                  ?
[NVD-Only Baseline Engine]    [SeekThreat Multi-Source Engine]      [Placeholder Detection]
   ? NVDSource (nvd_sample)      ? CVEOrgSource (cve_org_sample)        ? Source.DERIVED == Low
   ? Unloaded KEV (None/DERIVED) ? CISAKevSource (cisa_kev_sample)      ? CVSS == 5.0 (placeholder)
   ? Unloaded EPSS (0.001)       ? FirstEPSSSource (epss_v4_sample)     ? CWE == ["CWE-Other"]
   ? Unloaded EDB/MSF (None)     ? VulnrichmentSource (sample)          ? EPSS == 0.001 (placeholder)
                                 ? EUVDSource (euvd_sample)             ? in_kev == None (unknown)
                                 ? ExploitDBSource (sample)             ? exploit == None (unknown)
                                 ? MetasploitSource (sample)
                                 ? NVDSource (nvd_sample)
```

### Measured Fields & Non-Placeholder Criteria

1. **`cvss_score`**: Attributed score from an authoritative feed. DERIVED/LOW placeholders (5.0) count as empty (0).
2. **`cwe_ids`**: Specific CWE identifier list. DERIVED/LOW fallback (`["CWE-Other"]`) counts as empty (0).
3. **`summary`**: Authoritative vulnerability description. Empty strings or generic placeholders count as empty (0).
4. **`epss_score`**: Numeric probability from FIRST EPSS v4. Unloaded placeholder (0.001) counts as empty (0).
5. **`in_kev`**: Definite boolean (`True` or `False`) with `Source.KEV`, `Confidence.HIGH`. Unloaded unknown (`None`, `Source.DERIVED`) counts as empty (0).
6. **`exploit_availability`**: Definite boolean (`True` or `False`) with `Source.EXPLOITDB` or `Source.METASPLOIT`. Unloaded status (`None`, `Source.DERIVED`) counts as empty (0).

---

## Measured Evaluation Results

Executed on **2026-10-05** using `python evals/enrichment_coverage.py`:

### Executive Summary

| Metric | NVD-Only Baseline | SeekThreat Multi-Source | Improvement |
|---|---|---|---|
| **Overall Coverage** | **4.0%** | **44.7%** | **+40.7 pp** |

Total evaluated field instances across 50 CVEs: **300 field instances**.

### Per-Field Intelligence Breakdown

| Field Identifier | Intelligence Dimension | NVD Baseline | Multi-Source | Coverage Gain |
|---|---|---|---|---|
| `cvss_score` | Severity (CVSS) | 8.0% (4/50) | 18.0% (9/50) | **+10.0 pp** |
| `cwe_ids` | Weakness Taxonomy (CWE) | 8.0% (4/50) | 18.0% (9/50) | **+10.0 pp** |
| `summary` | Description | 8.0% (4/50) | 18.0% (9/50) | **+10.0 pp** |
| `epss_score` | Exploit Probability (EPSS) | 0.0% (0/50) | 14.0% (7/50) | **+14.0 pp** |
| `in_kev` | Active Exploitation (KEV) | 0.0% (0/50) | 100.0% (50/50) | **+100.0 pp** |
| `exploit_availability` | Exploit Presence (EDB/MSF) | 0.0% (0/50) | 100.0% (50/50) | **+100.0 pp** |

### Cohort Analysis

| Cohort Identifier | Focus / Gap Addressed | Baseline | Multi-Source | Gain |
|---|---|---|---|---|
| `cohort_a_nvd_control` | Control group: historic CVEs with full NVD analysis | 20.0% | 60.0% | **+40.0 pp** |
| `cohort_b_nvd_gap` | NVD backlog/un-enriched CVEs filled by CVE.org/CISA | 0.0% | 45.0% | **+45.0 pp** |
| `cohort_c_cisa_kev` | Known exploited vulnerabilities in CISA KEV catalog | 0.0% | 40.0% | **+40.0 pp** |
| `cohort_d_high_epss_no_nvd` | High exploitation probability vulnerabilities | 0.0% | 45.0% | **+45.0 pp** |
| `cohort_e_weaponized_exploit` | Public exploits in ExploitDB and Metasploit | 0.0% | 33.3% | **+33.3 pp** |

---

## Constraint Verification

| Constraint | Status | Verification |
|---|---|---|
| Never report unmeasured metrics (`evals/README.md`) | PASSED | All metrics were computed via `evals/enrichment_coverage.py`. Reports explicitly state: *"Measured against synthetic fixture files (`tests/fixtures/enrichment/`)."* |
| Zero network calls on request path (Rule 5) | PASSED | Execution operates 100% offline using local JSON fixtures. Network sockets not touched. |
| Exploit availability IDs only (Hard Rule 4) | PASSED | ExploitDB and Metasploit records store IDs/module names only, no exploit bodies or code. |
| Deterministic fallback chains | PASSED | Fallback chain `CVE.org -> Vulnrichment -> NVD -> EUVD -> Derived` executes deterministically with full provenance. |
| Code quality | PASSED | `python -m ruff check` clean; `pytest` passes across all test suites. |

---

## Decisions Logged

- **D-035**: *Enrichment coverage eval methodology: offline NVD-only baseline comparison*. Formalized the 6-dimension evaluation framework, golden dataset structure, and provenance transparency policy.
