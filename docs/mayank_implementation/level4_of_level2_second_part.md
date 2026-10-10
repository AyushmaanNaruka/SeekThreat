# Level 4 of Layer 2 Second Part — Walkthrough

**Level:** 4 of 5 — *NVD-Only Baseline Eval (Layer 2 "Done When")*  
**Branch:** mayank_level2_second  
**Completed:** 2026-10-05 (harness); corrected in PR #18 review  
**Decision logged:** D-035  
**Status:** harness built; **coverage not yet measured** (no real mirrors have been evaluated)

---

## What Level 4 does

Level 4 builds the harness for the Layer 2 "Done When" criterion: **enrichment coverage measured against an NVD-only baseline**. It does not yet satisfy that criterion. The only run so far is a synthetic smoke test on hand-authored fixtures.

1. **Metric definition (`evals/enrichment_coverage.md`)**: headline coverage over four intelligence fields (`cvss_score`, `cwe_ids`, `summary`, `epss_score`). `in_kev` and `exploit_availability` are reported separately as "mirror loaded" plus positive-hit rate, because a loaded mirror answers every lookup with a definite True/False.
2. **Input dataset (`evals/golden/enrichment_baseline.json`)**: 50 CVE IDs in five cohorts. It is marked `_synthetic: true` and `"verification": "unverified"`: the cohort labels are hypotheses that nobody has checked against live NVD.
3. **NVDSource & NVDRecord (`services/enrichment/sources/secondary.py`)**: a JSON mirror loader for flat and NVD 2.0 API shapes. It parses CVSS, CWE and description only, not the NVD 2.0 CISA KEV fields (`cisaExploitAdd` etc.). NVD sits in the fusion chain at the position given by `services/enrichment/fusion.py` `_CHAIN_ORDER`. The source's own `priority` attribute is 5, which is not the same thing as its chain position.
4. **Offline harness (`evals/enrichment_coverage.py`)**: runs the NVD-only baseline engine and the multi-source engine over the dataset and writes JSON and Markdown reports. It detects synthetic mirrors from their `_synthetic` key. For real mirrors it records each file's sha256, mtime and `synced_at`.
5. **Synthetic smoke test (`evals/results/enrichment_coverage_results.{md,json}`)**: the harness run on `tests/fixtures/enrichment/`, under a banner saying it is not a measurement of the platform. Read the numbers from those files. They describe which CVEs the fixtures happen to contain.
6. **Tests (`tests/unit/test_enrichment_coverage_eval.py`, `tests/unit/test_nvd_source.py`)**: placeholder exclusion, headline/signal separation, baseline isolation (NVD only), pinned per-field counts on the fixtures, and a check that the committed results match a fresh run.

An earlier version of this walkthrough reported a headline gain from the fixture run as a "real offline measurement". That was withdrawn. The fixtures are synthetic. Most of the gain came from KEV and exploit fields counting a definite False as "filled". And the baseline's 0% on KEV, EPSS and exploit fields is true by construction, because those sources are not loaded in the baseline.

---

## File map

| File | Role | Added / Changed |
|---|---|---|
| `evals/enrichment_coverage.md` | Metric specification | Added |
| `evals/golden/enrichment_baseline.json` | 50-CVE input list, 5 hypothesised cohorts (unverified) | Added |
| `evals/enrichment_coverage.py` | Offline harness CLI and report generator | Added |
| `evals/results/enrichment_coverage_results.md` | Synthetic smoke-test report (not a measurement) | Added |
| `evals/results/enrichment_coverage_results.json` | Synthetic smoke-test JSON output | Added |
| `services/enrichment/sources/secondary.py` | `NVDRecord` and real `NVDSource` mirror loader | Changed |
| `services/enrichment/sources/__init__.py` | Export `NVDRecord` | Changed |
| `services/enrichment/fusion.py` | Integrate `NVDSource` into fallback chain and engine constructor | Changed |
| `tests/fixtures/enrichment/nvd_sample.json` | Synthetic NVD mirror fixture | Added |
| `tests/unit/test_nvd_source.py` | NVDSource loader and parsing tests | Added |
| `tests/unit/test_enrichment_coverage_eval.py` | Harness tests | Added |
| `DECISIONS.md` | D-035 (evaluation methodology) | Changed |
| `docs/mayank_implementation/level4_of_level2_second_part.md` | This walkthrough | Added |

---

## Evaluation configurations

```
Finding (CVE ID)
       |
       +---------------------------------+
       |                                 |
[NVD-only baseline engine]      [Multi-source engine]
   - NVDSource (loaded)            - CVEOrgSource
   - CVE.org: not loaded           - VulnrichmentSource
   - KEV: not loaded               - NVDSource
   - EPSS: not loaded              - EUVDSource
   - Vulnrichment/EUVD: absent     - FirstEPSSSource
   - ExploitDB/Metasploit: absent  - CISAKevSource
                                   - ExploitDBSource, MetasploitSource
```

Chain order for CVSS, CWE and description is `_CHAIN_ORDER` in `services/enrichment/fusion.py`, followed by derived placeholders. Every report records the order it ran with (`fusion_chain_order`).

### Field criteria

- **Headline (`cvss_score`, `cwe_ids`, `summary`, `epss_score`)**: filled when present, non-empty, and provenance is neither `Source.DERIVED` nor `Confidence.LOW`. No value-based checks: a real CVSS 5.0 or EPSS 0.001 counts.
- **Signals (`in_kev`, `exploit_availability`)**: reported per engine as mirror loaded (yes/no), with positive / negative / unknown counts. The positive-hit rate is reported only when the mirror is loaded.

### Baseline limitation

The baseline parses only NVD CVSS, CWE and description. The real NVD API 2.0 includes CISA KEV fields, which `NVDSource` ignores. The baseline's missing KEV signal is a limit of this harness, not a property of NVD.

---

## Running it

```
python evals/enrichment_coverage.py --help
python evals/enrichment_coverage.py                 # fixtures -> evals/results/ (synthetic)
python evals/enrichment_coverage.py --cache-dir <real mirror dir> \
    --output-json <path> --output-md <path>         # real mirrors (not yet done)
```

---

## Constraint check

| Constraint | Status | Basis |
|---|---|---|
| Never report unmeasured metrics (`evals/README.md`) | **Was violated; corrected.** | The first version presented fixture output as a measurement. Reports now open with the synthetic banner, and `evals/README.md` lists the metric as not yet measured. |
| Offline (enrichment README rule 5: mirror locally, no API calls on the request path) | Holds by construction | The harness reads local files only. `tests/unit/test_offline_mirror.py` guards the sources. No test isolates the harness's network use specifically. |
| Exploit metadata IDs only (Hard Rule 4) | Holds for the readers | `test_exploitdb_source.py` and `test_metasploit_source.py` assert that records carry IDs/module names only. |
| Deterministic fallback chain | Holds | Same inputs give the same fused fields. The committed results are checked against a fresh run in `test_enrichment_coverage_eval.py`. |
| Layer 2 "Done When" (coverage measured vs NVD-only) | **Not met** | Needs a run on dated real mirrors and a verified CVE list. |

---

## Decisions logged

- **D-035**: *Enrichment coverage eval methodology: offline NVD-only baseline comparison*. Defines the metric, the headline/signal split, synthetic detection, and the open work needed for a real measurement.
