# ERS Ranking Corroboration Report (smoke-level)

> **SYNTHETIC SMOKE TEST — harness validation on hand-authored fixtures. These are not measurements of ERS ranking quality.**

> **Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  
> **Dataset:** `evals/golden/enrichment_baseline.json` (50 CVEs)  
> **Mirror cache:** `tests/fixtures/enrichment` (Mode: Synthetic fixtures)  
> **Tie rule:** score descending, then cve_id ascending  

## 1. Summary

ERS = 0.40 x CVSS + 0.35 x (EPSS x 10) + 0.25 x (10 if KEV). The corroboration target is whether an ExploitDB or Metasploit catalogue entry exists for the CVE. That target is not independent of ERS: EPSS uses exploit-code availability, including ExploitDB and Metasploit, among its features.

- **Base rate (random-ranking precision):** 0 / 50 CVEs (0.0%) have an ExploitDB or Metasploit catalogue entry; 0 / 50 (0.0%) have a Metasploit module.
- **Top 5 precision, balanced ERS:** 0.0% (Metasploit-only 0.0%).
- **Top 5 precision, no-EPSS control:** 0.0% (Metasploit-only 0.0%).
- **Top 5 precision, CVSS-only:** 0.0% (Metasploit-only 0.0%).
- **EPSS marginal gain (balanced - no-EPSS control):** +0.0 pp.
- **Balanced - CVSS-only:** +0.0 pp.
- **Balanced - random baseline:** +0.0 pp.
- **Granularity:** at top 5, one CVE moves precision by 20.0 pp.

## 2. Profile ranking across slices

| Profile | Weights (CVSS / EPSS / KEV) | Slice | Precision | Precision range over tie orders | Metasploit-only precision | Recall | Ties at boundary (outside top k) | Min score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 5 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (45) | 2.0 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 10 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (40) | 2.0 |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | top 15 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (35) | 2.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 5 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (45) | 3.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 10 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (40) | 3.0 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | top 15 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (35) | 3.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 5 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (45) | 5.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 10 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (40) | 5.0 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | top 15 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (35) | 5.0 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 5 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (45) | 1.25 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 10 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (40) | 1.25 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | top 15 | 0.0% | 0.0% - 0.0% | 0.0% | 0.0% | 50 (35) | 1.25 |

## 3. Full-ranking metrics (AP and AUC-ROC with 95% bootstrap CIs)

> Positive class: CVE has an ExploitDB or Metasploit catalogue entry.  
> Bootstrap: percentile CIs, n=2,000 resamples, seed=20261011.  
> **Caveat:** the corroboration target is NOT independent of ERS (EPSS uses exploit-code availability among its features — D-029).

| Profile | Weights (CVSS/EPSS/KEV) | AP | AP 95% CI | AUC-ROC | AUC-ROC 95% CI | Positives / n |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Balanced (production default) | 0.40 / 0.35 / 0.25 | 0.0000 | [0.0000, 0.0000] | 0.5000 | [0.5000, 0.5000] | 0 / 50 |
| No-EPSS control (CVSS+KEV) | 0.60 / 0.00 / 0.40 | 0.0000 | [0.0000, 0.0000] | 0.5000 | [0.5000, 0.5000] | 0 / 50 |
| CVSS-only baseline | 1.00 / 0.00 / 0.00 | 0.0000 | [0.0000, 0.0000] | 0.5000 | [0.5000, 0.5000] | 0 / 50 |
| Exploitation heavy | 0.25 / 0.50 / 0.25 | 0.0000 | [0.0000, 0.0000] | 0.5000 | [0.5000, 0.5000] | 0 / 50 |

Random baseline AUC: 0.5000.


## 4. Top-ranked CVEs (balanced ERS)

| Rank | CVE ID | ERS (balanced) | CVSS | EPSS (%) | In KEV | ExploitDB entry | Metasploit module | Cohort |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `CVE-2001-0154` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 2 | `CVE-2006-1547` | 2.003 | 5.0 | 0.1% | no | — | — | kev_high_epss |
| 3 | `CVE-2008-1051` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 4 | `CVE-2009-0305` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 5 | `CVE-2009-0563` | 2.003 | 5.0 | 0.1% | no | — | — | kev_high_epss |
| 6 | `CVE-2009-3613` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 7 | `CVE-2009-4223` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 8 | `CVE-2010-3653` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_high_epss |
| 9 | `CVE-2013-5223` | 2.003 | 5.0 | 0.1% | no | — | — | kev_high_epss |
| 10 | `CVE-2014-9034` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_high_epss |
| 11 | `CVE-2018-0155` | 2.003 | 5.0 | 0.1% | no | — | — | kev_low_epss |
| 12 | `CVE-2018-0795` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 13 | `CVE-2018-14718` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_mid_epss |
| 14 | `CVE-2018-15203` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_low_epss |
| 15 | `CVE-2018-16509` | 2.003 | 5.0 | 0.1% | no | — | — | non_kev_high_epss |

## 5. Limitations & circularity disclosure (D-027, D-038)

1. **Direct inputs.** ExploitDB and Metasploit are not inputs to `calculate_ers()`; the inputs are CVSS, EPSS and KEV.
2. **Not independent of EPSS.** EPSS uses exploit-code availability, including ExploitDB entries and Metasploit modules, among its model features (D-029). Corroborating against either catalogue partly re-measures an ERS input. Metasploit-only precision is a narrower target, not an independent check.
3. **Selection bias.** Cohort E was chosen for exploit presence (0 of 0 have a catalogue entry). Cohort C was chosen on KEV membership, which is an ERS input (0 of 0 in KEV; 0 of 50 overall). The base rate is 0.0%, so precision must be read against it.
4. **Small n.** 50 hand-picked CVEs. At top 5, one CVE moves precision by 20.0 pp. Treat every number here as smoke-level corroboration, not validation.
5. **Ties.** Ranking uses score descending, then cve_id ascending. Where CVEs tie at the k boundary, slice membership is decided by that rule; the precision range column shows how far precision could move under any other tie order.
6. **Additive formula.** ERS never multiplies EPSS by CVSS (D-008; `services/enrichment/README.md` rule 3). Each component is recorded in its own `ScoreComponent`.

---
_Generated by `evals/ers_validation.py`._
