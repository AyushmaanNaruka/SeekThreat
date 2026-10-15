# ERS Ranking Corroboration Report (smoke-level)

> **Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  
> **Dataset:** `evals/golden/enrichment_baseline.json` (50 CVEs)  
> **Mirror cache:** `data/enrichment_cache` (Mode: Real feed mirrors)  
> **Tie rule:** score descending, then cve_id ascending  
> **Generated at:** 2026-10-15T17:10:22.609252+00:00  

## 1. Summary

ERS = 0.40 x CVSS + 0.35 x (EPSS x 10) + 0.25 x (10 if KEV). The corroboration target is whether an ExploitDB or Metasploit catalogue entry exists for the CVE. That target is not independent of ERS: EPSS uses exploit-code availability, including ExploitDB and Metasploit, among its features.

- **Base rate (random-ranking precision):** 17 / 50 CVEs (34.0%) have an ExploitDB or Metasploit catalogue entry; 11 / 50 (22.0%) have a Metasploit module.
- **Top 5 precision, balanced ERS:** 100.0% (Metasploit-only 100.0%).
- **Top 5 precision, no-EPSS control:** 40.0% (Metasploit-only 20.0%).
- **Top 5 precision, CVSS-only:** 40.0% (Metasploit-only 20.0%).
- **EPSS marginal gain (balanced - no-EPSS control):** +60.0 pp.
- **Balanced - CVSS-only:** +60.0 pp.
- **Balanced - random baseline:** +66.0 pp.
- **Granularity:** at top 5, one CVE moves precision by 20.0 pp.

## 2. Profile ranking across slices

| Profile | Weights (CVSS / EPSS / KEV) | Slice | Precision | Precision range over tie orders | Metasploit-only precision | Recall | Ties at boundary (outside top k) | Min score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 5 | 100.0% | 100.0% - 100.0% | 100.0% | 29.4% | 1 (0) | 7.99 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 10 | 60.0% | 60.0% - 60.0% | 60.0% | 35.3% | 1 (0) | 7.41 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 15 | 53.3% | 53.3% - 53.3% | 40.0% | 47.1% | 1 (0) | 6.28 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 5 | 40.0% | 20.0% - 60.0% | 20.0% | 11.8% | 22 (20) | 7.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 10 | 40.0% | 10.0% - 80.0% | 20.0% | 23.5% | 22 (15) | 7.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 15 | 33.3% | 6.7% - 53.3% | 20.0% | 29.4% | 22 (10) | 7.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 5 | 40.0% | 20.0% - 60.0% | 20.0% | 11.8% | 47 (45) | 5.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 10 | 60.0% | 10.0% - 80.0% | 20.0% | 35.3% | 47 (40) | 5.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 15 | 46.7% | 6.7% - 86.7% | 13.3% | 41.2% | 47 (35) | 5.0 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 5 | 100.0% | 100.0% - 100.0% | 100.0% | 29.4% | 1 (0) | 8.74 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 10 | 60.0% | 60.0% - 60.0% | 60.0% | 35.3% | 1 (0) | 7.11 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 15 | 53.3% | 53.3% - 53.3% | 40.0% | 47.1% | 1 (0) | 6.29 |

## 3. Full-ranking metrics (AP and AUC-ROC with 95% bootstrap CIs)

> Positive class: CVE has an ExploitDB or Metasploit catalogue entry.  
> Bootstrap: percentile CIs, n=2,000 resamples, seed=20261011.  
> **Caveat:** the corroboration target is NOT independent of ERS (EPSS uses exploit-code availability among its features — D-029).

| Profile | Weights (CVSS/EPSS/KEV) | AP | AP 95% CI | AUC-ROC | AUC-ROC 95% CI | Positives / n |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | 0.6549 | [0.4419, 0.8347] | 0.7308 | [0.5734, 0.8750] | 17 / 50 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | 0.4193 | [0.2361, 0.6272] | 0.5365 | [0.3671, 0.7077] | 17 / 50 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | 0.4827 | [0.2861, 0.7207] | 0.6150 | [0.4417, 0.7817] | 17 / 50 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | 0.6806 | [0.4662, 0.8490] | 0.7629 | [0.6162, 0.8916] | 17 / 50 |

Random baseline AUC: 0.5000.


## 4. Top-ranked CVEs (balanced ERS)

| Rank | CVE ID | ERS (balanced) | CVSS | EPSS (%) | In KEV | ExploitDB entry | Metasploit module | Cohort |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `CVE-2023-22515` | 9.973 | 10.0 | 99.2% | yes | — | yes | kev_high_epss |
| 2 | `CVE-2021-21985` | 8.000 | 5.0 | 100.0% | yes | — | yes | kev_high_epss |
| 3 | `CVE-2024-34102` | 8.000 | 5.0 | 100.0% | yes | — | yes | kev_high_epss |
| 4 | `CVE-2023-22527` | 7.999 | 5.0 | 100.0% | yes | — | yes | kev_high_epss |
| 5 | `CVE-2024-36401` | 7.993 | 5.0 | 99.8% | yes | — | yes | kev_high_epss |
| 6 | `CVE-2024-57727` | 7.880 | 5.0 | 96.6% | yes | — | — | kev_high_epss |
| 7 | `CVE-2009-0563` | 7.819 | 7.8 | 62.8% | yes | — | — | kev_high_epss |
| 8 | `CVE-2026-71362` | 7.563 | 5.0 | 87.5% | yes | — | — | kev_high_epss |
| 9 | `CVE-2026-81578` | 7.495 | 5.0 | 85.6% | yes | — | yes | kev_high_epss |
| 10 | `CVE-2006-1547` | 7.412 | 7.5 | 54.6% | yes | — | — | kev_high_epss |
| 11 | `CVE-2021-36934` | 6.854 | 5.0 | 67.3% | yes | — | — | kev_high_epss |
| 12 | `CVE-2018-7445` | 6.628 | 5.0 | 60.8% | yes | yes | — | kev_high_epss |
| 13 | `CVE-2024-38812` | 6.410 | 5.0 | 54.6% | yes | — | — | kev_high_epss |
| 14 | `CVE-2020-25079` | 6.390 | 5.0 | 54.0% | yes | — | — | kev_high_epss |
| 15 | `CVE-2013-5223` | 6.279 | 5.0 | 50.8% | yes | yes | — | kev_high_epss |

## 5. Limitations & circularity disclosure (D-027, D-038)

1. **Direct inputs.** ExploitDB and Metasploit are not inputs to `calculate_ers()`; the inputs are CVSS, EPSS and KEV.
2. **Not independent of EPSS.** EPSS uses exploit-code availability, including ExploitDB entries and Metasploit modules, among its model features (D-029). Corroborating against either catalogue partly re-measures an ERS input. Metasploit-only precision is a narrower target, not an independent check.
3. **Selection bias.** Cohort E was chosen for exploit presence (0 of 0 have a catalogue entry). Cohort C was chosen on KEV membership, which is an ERS input (0 of 0 in KEV; 25 of 50 overall). The base rate is 34.0%, so precision must be read against it.
4. **Small n.** 50 hand-picked CVEs. At top 5, one CVE moves precision by 20.0 pp. Treat every number here as smoke-level corroboration, not validation.
5. **Ties.** Ranking uses score descending, then cve_id ascending. Where CVEs tie at the k boundary, slice membership is decided by that rule; the precision range column shows how far precision could move under any other tie order.
6. **Additive formula.** ERS never multiplies EPSS by CVSS (D-008; `services/enrichment/README.md` rule 3). Each component is recorded in its own `ScoreComponent`.

---
_Generated by `evals/ers_validation.py`._
