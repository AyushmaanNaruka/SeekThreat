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

Input list for `evals/enrichment_coverage.py` and `evals/ers_validation.py`. Version 2.0.1
(2.0.0 created 2026-10-11; 2.0.1 is the 2026-10-12 review correction).

- **50 real-world CVE IDs** in five cohorts. The cohort names are hypotheses about each CVE,
  not checked labels:
  1. `cohort_a_nvd_control`: well-known older vulnerabilities expected to have full NVD analysis.
  2. `cohort_b_nvd_gap`: recent CVEs expected to have had NVD analysis delays.
  3. `cohort_c_cisa_kev`: CVEs expected to be listed in CISA KEV.
  4. `cohort_d_high_epss_no_nvd`: CVEs expected to have high EPSS and little NVD enrichment.
  5. `cohort_e_weaponized_exploit`: CVEs expected to have ExploitDB / Metasploit entries.
- **Selection rule: none documented yet.** The 50 CVEs were hand-picked well-known CVEs, not
  sampled by a stated rule. Any result on this set describes this set, not CVEs in general.
  Writing down a reproducible selection rule (and re-picking by it) is open work.
- **`eval_cve_list.txt`** is the same 50 IDs, one per line. It is the `--cve-file` input to
  `python -m services.enrichment.sync_feeds` for the per-CVE sources (CVE.org, Vulnrichment,
  NVD, EUVD). Keep it in sync with `enrichment_baseline.json`.
- **Verification status: batch-attested, not per-CVE verified.** Every entry carries
  `verified_by: Mayank Narang` / `verified_at: 2026-10-11`, but these are one batch stamp with no
  per-CVE evidence record (what was checked, against which page or API response, with what
  result). The dataset-level `verification` field says so, and `cohort_labels_verified` is
  `false`, which makes the coverage harness report cohort labels as unverified.
- **Labels contradicted by measured data.** In the 2026-10-11 real-mirror run
  (`evals/results/enrichment_coverage_real.json`), NVD supplied CVSS for all 50 CVEs, including
  every CVE in cohorts B (`nvd_gap`) and D (`high_epss_no_nvd`). Those two cohort names do not
  describe these CVEs on that snapshot.
- **Corrections in 2.0.1:** `CVE-2024-3094` and `CVE-2024-26229` listed "CISA KEV" in
  `authoritative_source`, but the KEV mirror in that run reports both as not in KEV. "CISA KEV"
  was removed from both, with a `correction_note`. `CVE-2022-22965` is the reverse case: the KEV
  mirror reports it in KEV but its `authoritative_source` does not list KEV. That entry is
  unchanged, pending a per-CVE check.
- The synthetic placeholders (`CVE-2025-0001`, `CVE-2025-0002`) were replaced with real CVEs
  (`CVE-2024-21893`, `CVE-2024-28995`) in 2.0.0.

To turn this into a verified dataset, each entry needs its own evidence record (source URL or
mirror sha256, retrieval date, observed value), and each cohort needs a membership rule that
can be checked mechanically against the mirrors.
