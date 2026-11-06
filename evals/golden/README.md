# Golden dataset

Question/answer pairs with verified ground truth. One JSONL file per category.

```
cve_lookups.jsonl
remediation.jsonl
attack_paths.jsonl
prioritization.jsonl
adversarial.jsonl        # correct answer is "I don't have that data"
multi_hop.jsonl
```

Entry format:

```json
{
  "id": "cve-001",
  "question": "What is the severity of CVE-2021-41773 on our DMZ web host?",
  "reference_answer": "...",
  "required_sources": ["cve.org", "first.epss"],
  "lab_configuration": "baseline",
  "verified_by": "name",
  "verified_at": "2026-09-01"
}
```

Every entry must be verifiable against `lab/ground_truth.yaml` or an authoritative source.
Never write a reference answer from memory.

## `enrichment_baseline.json` (enrichment coverage harness input)

Input list for `evals/enrichment_coverage.py` and `evals/ers_validation.py`. Version 3.0.0
(2.0.0 created 2026-10-11; 2.0.1 review corrections 2026-10-12; 3.0.0 stratified selection & evidence records 2026-10-15).

### Selection Rule (Version 3.0.0)

To replace ad-hoc hand-picked famous CVEs with a defensible, reproducible scientific benchmark, the 50 CVEs are sampled deterministically via stratified random sampling from the local mirror universe:
- **Source Universe:** The intersection of valid CVEs in the FIRST EPSS v4 mirror (`data/enrichment_cache/epss_v4.json`) and the CISA KEV catalog (`data/enrichment_cache/cisa_kev.json`).
- **Fixed Random Seed:** `SEED = 20261011` (ensures 100% mechanical reproducibility across environments).
- **Target Size:** $n = 50$ distinct CVE IDs.
- **Generator Script:** `python evals/scripts/generate_eval_cve_list.py`
- **Audit Manifest:** `evals/golden/eval_cve_selection_manifest.json` (records exact mirror SHA-256 digests, timestamps, stratum boundaries, and selections).

### Strata Definitions

| Stratum / Cohort | KEV Member | EPSS Range | Target $n$ | Selected $n$ | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `kev_high_epss` | Yes | $\ge 0.50$ | 15 | 15 | Known exploited + high probability weaponization |
| `kev_low_epss` | Yes | $< 0.50$ | 10 | 10 | Known exploited despite low predictive EPSS |
| `non_kev_high_epss`| No | $\ge 0.70$ | 10 | 10 | High predictive probability outside KEV |
| `non_kev_mid_epss` | No | $[0.10, 0.70)$ | 10 | 10 | Mid-tier emerging threats |
| `non_kev_low_epss` | No | $< 0.005$ | 5 | 5 | Low-probability negative control stratum |

Legacy cohorts B (`nvd_gap`) and D (`high_epss_no_nvd`) were dropped: in empirical runs, NVD published CVSS for all tested CVEs, making those hypothesis labels unrepresentative of mirror data.

### Per-CVE Evidence Records

Batch-attested stamps (`verified_by: Mayank Narang`) have been replaced by structured per-CVE evidence blocks built by `evals/scripts/build_enrichment_baseline.py`:
- `evidence.retrieved_at`: ISO 8601 timestamp of mirror inspection.
- `evidence.nvd`: `checked`, `cvss_present`, `cvss_score`, `cvss_vector`, and direct NVD URL.
- `evidence.cisa_kev`: `in_catalog`, `date_added`, `due_date`, and catalog URL.
- `evidence.epss`: `score` and API URL.
- `evidence.euvd`: `present` and European Vulnerability Database URL.

### Discrepancy Resolutions
- **CVE-2022-22965 (Spring4Shell):** Reviewer flagged that the pre-review dataset omitted KEV listing for Spring4Shell. In the current CISA KEV mirror, `CVE-2022-22965` is verified to be present (`dateAdded: 2022-04-04`). Verified by `tests/unit/test_golden_evidence.py`.
- **`eval_cve_list.txt`**: Matches the exact 50 sorted CVE IDs in `enrichment_baseline.json` and is validated against the manifest in CI.
