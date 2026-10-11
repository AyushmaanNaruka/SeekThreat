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

Input list for `evals/enrichment_coverage.py`. Version 2.0.0 (updated 2026-10-11).

- **50 real-world CVEs** across five documented cohorts:
  1. `cohort_a_nvd_control`: Well-known legacy vulnerabilities with full historical NVD analysis.
  2. `cohort_b_nvd_gap`: Real recent zero-days and enterprise perimeter CVEs subjected to NVD publication/analysis delays.
  3. `cohort_c_cisa_kev`: Confirmed active exploitation in the wild listed in the CISA KEV catalog.
  4. `cohort_d_high_epss_no_nvd`: High EPSS probability vulnerabilities with delayed or minimal NVD enrichment.
  5. `cohort_e_weaponized_exploit`: High-profile weaponized vulnerabilities with public exploits in ExploitDB and Metasploit.
- **Empirical Ground Truth:** Every entry is verified (`verified_by: Mayank Narang`, `verified_at: 2026-10-11`) against authoritative upstream catalogs (CISA KEV, CVE.org, and NVD API 2.0).
- All synthetic placeholders (`CVE-2025-0001`, `CVE-2025-0002`) were replaced with genuine real-world vulnerabilities (`CVE-2024-21893` Ivanti SSRF, `CVE-2024-28995` SolarWinds Serv-U).

