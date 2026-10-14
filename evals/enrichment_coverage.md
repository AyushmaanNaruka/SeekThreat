# Enrichment Coverage Evaluation Metric Specification

> **Status:** measured once on real mirrors 2026-10-11 (see
> `evals/results/enrichment_coverage_real.md` and its caveats: the four-field gain is entirely
> EPSS, excluding EPSS the gain is +0.0 pp, and the 50 CVEs are hand-picked with batch-attested
> labels). `evals/results/enrichment_coverage_results.*` is a separate synthetic smoke test on
> hand-authored fixtures (`tests/fixtures/enrichment/`, every file `_synthetic: true`). The
> harness also reports a three-field "excluding EPSS" headline, because the baseline never
> loads EPSS.

## 1. Overview and Objective

An NVD-only scanning strategy depends on NVD having analysed a CVE (CVSS, CWE, description).
SeekThreat's fusion engine queries several mirrored sources with per-field provenance and a
deterministic fallback chain. The chain order is whatever `services/enrichment/fusion.py`
`_CHAIN_ORDER` says; at the time of writing:

`CVE.org -> CISA Vulnrichment -> NVD 2.0 -> ENISA EUVD -> Derived`

The harness records the chain it actually ran with in every report (`fusion_chain_order`).

This specification defines the **Enrichment Coverage Metric**: how many CVEs get real (non-
placeholder) intelligence under the multi-source engine versus an NVD-only baseline engine.

---

## 2. Core Metric Definitions

### 2.1 Headline fields

Headline coverage counts four intelligence fields:

| Field | Dimension | "Filled" means |
|---|---|---|
| `cvss_score` | Severity | Present, and provenance is not `Source.DERIVED` and not `Confidence.LOW` |
| `cwe_ids` | Weakness taxonomy | Same, and the list is non-empty |
| `summary` | Description | Same, and the string is non-blank |
| `epss_score` | Exploitation probability | Same |

Placeholders are identified **by provenance only**, never by value. Fusion's placeholders are
attributed `Source.DERIVED` / `Confidence.LOW`; a real CVSS of 5.0 or a real EPSS of 0.001 is
data and counts as filled.

### 2.2 Signal fields (reported separately, not in the headline)

| Field | Reported as |
|---|---|
| `in_kev` | Mirror loaded (yes/no) and positive-hit rate (`True` from `Source.KEV`) |
| `exploit_availability` | Mirror loaded (yes/no) and positive-hit rate (`True` from `Source.EXPLOITDB` or `Source.METASPLOIT`) |

A loaded KEV/ExploitDB/Metasploit mirror answers every lookup with a definite `True` or
`False`, so "has a definite value" only measures whether the mirror file exists. Counting a
definite `False` as coverage would make these fields 100% whenever the file is present, so they
are excluded from the headline.

### 2.3 Formulas

For N CVEs, headline field j in {1..4}, engine M:

- `filled(i, j, M)` is 1 if field j of CVE i is filled (2.1), else 0.
- `Coverage_j(M) = sum_i filled(i, j, M) / N * 100%`
- `Coverage(M) = sum_i sum_j filled(i, j, M) / (4 * N) * 100%`
- `Delta = Coverage(M_multi) - Coverage(M_nvd)`, in percentage points (may be negative).

Signal fields: `positive_rate(M) = #positive / N * 100%`, reported only when the mirror is
loaded in M; otherwise "not loaded".

---

## 3. Evaluation Configurations

### 3.1 NVD-only baseline (M_nvd)
- **Loaded:** `NVDSource` only.
- **Not loaded / absent:** CVE.org, Vulnrichment, EUVD, EPSS, KEV, ExploitDB, Metasploit.

**Limitation.** The baseline engine parses only NVD CVSS, CWE and description. The real NVD
API 2.0 also publishes CISA KEV fields (`cisaExploitAdd`, `cisaActionDue`,
`cisaRequiredAction`, `cisaVulnerabilityName`), which `NVDSource` does not parse. The baseline's
missing KEV signal is therefore a property of this harness, not of NVD, and is reported as
"not loaded", not 0%. EPSS and exploit availability are likewise not loaded by construction.

### 3.2 Multi-source fusion (M_multi)
- **Chain sources:** `CVEOrgSource`, `VulnrichmentSource`, `NVDSource`, `EUVDSource`, in
  `_CHAIN_ORDER` (positions 1-4 at the time of writing: CVE.org, Vulnrichment, NVD, EUVD).
- **EPSS:** `FirstEPSSSource`.
- **KEV:** `CISAKevSource`.
- **Exploit metadata:** `ExploitDBSource`, `MetasploitSource` (IDs and module names only;
  Hard Rule 4).

---

## 4. Evaluation Dataset

`evals/golden/enrichment_baseline.json` lists 50 hand-picked CVE IDs in five cohorts. The
entries are batch-attested (one `verified_by` / `verified_at` stamp, no per-CVE evidence) and the
cohort labels are **hypotheses**: `cohort_labels_verified` is `false`, and the 2026-10-11 real
run contradicts cohorts B and D (NVD supplied CVSS for all 50). The harness reads only `cve_id`
and `cohort` per item, plus the dataset-level `verification` and `cohort_labels_verified`
fields.

1. **Cohort A: NVD control** — hypothesised to have complete NVD analysis.
2. **Cohort B: NVD gap** — hypothesised to lack NVD analysis while CVE.org / Vulnrichment / EUVD
   carry data.
3. **Cohort C: CISA KEV** — hypothesised KEV-listed CVEs.
4. **Cohort D: High EPSS / no NVD CVSS** — hypothesised high-EPSS CVEs without NVD CVSS.
5. **Cohort E: Weaponized exploit** — hypothesised CVEs with ExploitDB / Metasploit entries.

---

## 5. Execution and Reporting Rules

Per `evals/README.md`:

1. **Never fabricate metrics.** Every number comes from running
   `python evals/enrichment_coverage.py` (see `--help` for `--cache-dir`, `--dataset`,
   `--nvd-file`, `--output-md`, `--output-json`).
2. **Synthetic detection is by content.** A run is synthetic when any loaded mirror file is a
   JSON object with a truthy `_synthetic` key. Synthetic reports open with the banner
   *"SYNTHETIC SMOKE TEST — harness validation on hand-authored fixtures. These are not
   measurements of the platform. The real-mirror run is
   evals/results/enrichment_coverage_real.md."*
3. **Real-mirror provenance.** In non-synthetic mode the report records each mirror file's
   sha256, mtime and `synced_at` (from a `<name>.meta.json` sidecar when present), plus a
   `generated_at` timestamp.
4. **Reproducibility.** Synthetic-mode output contains no wall-clock data and uses POSIX,
   repo-relative paths; `tests/unit/test_enrichment_coverage_eval.py` checks that a fresh run
   matches the committed results.
5. **Offline.** The harness reads local mirror files only (enrichment README rule 5: mirror
   sources locally, never call APIs on the request path).
