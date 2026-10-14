# ERS Ranking Corroboration Report (smoke-level)

> **SYNTHETIC SMOKE TEST — harness validation on hand-authored fixtures. These are not measurements of ERS ranking quality.**

> **Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  
> **Dataset:** `evals/golden/enrichment_baseline.json` (50 CVEs)  
> **Mirror cache:** `tests/fixtures/enrichment` (Mode: Synthetic fixtures)  
> **Tie rule:** score descending, then cve_id ascending  

## 1. Summary

ERS = 0.40 x CVSS + 0.35 x (EPSS x 10) + 0.25 x (10 if KEV). The corroboration target is whether an ExploitDB or Metasploit catalogue entry exists for the CVE. That target is not independent of ERS: EPSS uses exploit-code availability, including ExploitDB and Metasploit, among its features.

- **Base rate (random-ranking precision):** 3 / 50 CVEs (6.0%) have an ExploitDB or Metasploit catalogue entry; 3 / 50 (6.0%) have a Metasploit module.
- **Top 5 precision, balanced ERS:** 60.0% (Metasploit-only 60.0%).
- **Top 5 precision, no-EPSS control:** 60.0% (Metasploit-only 60.0%).
- **Top 5 precision, CVSS-only:** 40.0% (Metasploit-only 40.0%).
- **EPSS marginal gain (balanced - no-EPSS control):** +0.0 pp.
- **Balanced - CVSS-only:** +20.0 pp.
- **Balanced - random baseline:** +54.0 pp.
- **Granularity:** at top 5, one CVE moves precision by 20.0 pp.

## 2. Profile ranking across slices

| Profile | Weights (CVSS / EPSS / KEV) | Slice | Precision | Precision range over tie orders | Metasploit-only precision | Recall | Ties at boundary (outside top k) | Min score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 5 | 60.0% | 60.0% - 60.0% | 60.0% | 100.0% | 1 (0) | 7.22 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 10 | 30.0% | 30.0% - 30.0% | 30.0% | 100.0% | 41 (40) | 2.0 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 15 | 20.0% | 20.0% - 20.0% | 20.0% | 100.0% | 41 (35) | 2.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 5 | 60.0% | 60.0% - 60.0% | 60.0% | 100.0% | 1 (0) | 5.88 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 10 | 30.0% | 30.0% - 30.0% | 30.0% | 100.0% | 41 (40) | 3.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 15 | 20.0% | 20.0% - 20.0% | 20.0% | 100.0% | 41 (35) | 3.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 5 | 40.0% | 40.0% - 40.0% | 40.0% | 66.7% | 1 (0) | 8.6 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 10 | 30.0% | 30.0% - 30.0% | 30.0% | 100.0% | 41 (40) | 5.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 15 | 20.0% | 20.0% - 20.0% | 20.0% | 100.0% | 41 (35) | 5.0 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 5 | 60.0% | 60.0% - 60.0% | 60.0% | 100.0% | 1 (0) | 7.16 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 10 | 30.0% | 30.0% - 30.0% | 30.0% | 100.0% | 41 (40) | 1.25 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 15 | 20.0% | 20.0% - 20.0% | 20.0% | 100.0% | 41 (35) | 1.25 |

## 3. Top-ranked CVEs (balanced ERS)

| Rank | CVE ID | ERS (balanced) | CVSS | EPSS (%) | In KEV | ExploitDB entry | Metasploit module | Cohort |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `CVE-2021-44228` | 9.914 | 10.0 | 97.5% | yes | yes | yes | cohort_a_nvd_control |
| 2 | `CVE-2022-22947` | 9.553 | 9.8 | 89.5% | yes | yes | yes | cohort_c_cisa_kev |
| 3 | `CVE-2024-23897` | 9.154 | 9.8 | 78.1% | yes | — | — | cohort_b_nvd_gap |
| 4 | `CVE-2021-41773` | 8.794 | 7.5 | 94.1% | yes | yes | yes | cohort_a_nvd_control |
| 5 | `CVE-2022-22965` | 7.217 | 9.8 | 94.2% | no | — | — | cohort_d_high_epss_no_nvd |
| 6 | `CVE-2024-28995` | 3.443 | 8.6 | 0.1% | no | — | — | cohort_d_high_epss_no_nvd |
| 7 | `CVE-2020-7699` | 3.419 | 7.3 | 14.2% | no | — | — | cohort_a_nvd_control |
| 8 | `CVE-2024-21893` | 3.283 | 8.2 | 0.1% | no | — | — | cohort_b_nvd_gap |
| 9 | `CVE-2020-15778` | 2.735 | 6.8 | 0.4% | no | — | — | cohort_a_nvd_control |
| 10 | `CVE-2014-0160` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |
| 11 | `CVE-2017-0144` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |
| 12 | `CVE-2017-5638` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |
| 13 | `CVE-2018-13379` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |
| 14 | `CVE-2019-0708` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |
| 15 | `CVE-2019-11510` | 2.003 | 5.0 | 0.1% | no | — | — | cohort_a_nvd_control |

## 4. Limitations & circularity disclosure (D-027, D-038)

1. **Direct inputs.** ExploitDB and Metasploit are not inputs to `calculate_ers()`; the inputs are CVSS, EPSS and KEV.
2. **Not independent of EPSS.** EPSS uses exploit-code availability, including ExploitDB entries and Metasploit modules, among its model features (D-029). Corroborating against either catalogue partly re-measures an ERS input. Metasploit-only precision is a narrower target, not an independent check.
3. **Selection bias.** Cohort E was chosen for exploit presence (0 of 10 have a catalogue entry). Cohort C was chosen on KEV membership, which is an ERS input (1 of 10 in KEV; 4 of 50 overall). The base rate is 6.0%, so precision must be read against it.
4. **Small n.** 50 hand-picked CVEs. At top 5, one CVE moves precision by 20.0 pp. Treat every number here as smoke-level corroboration, not validation.
5. **Ties.** Ranking uses score descending, then cve_id ascending. Where CVEs tie at the k boundary, slice membership is decided by that rule; the precision range column shows how far precision could move under any other tie order.
6. **Additive formula.** ERS never multiplies EPSS by CVSS (D-008; `services/enrichment/README.md` rule 3). Each component is recorded in its own `ScoreComponent`.

---
_Generated by `evals/ers_validation.py`._
