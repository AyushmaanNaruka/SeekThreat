# ERS Empirical Validation & Exploit Corroboration Report

> **Review status (2026-10-12): pre-review harness output, smoke-level only. Must be regenerated.**
> These numbers were produced on 2026-10-11 by the version of `evals/ers_validation.py` that existed
> before the PR #19 review. That version broke score ties by dataset input order and did not report
> the random baseline, Metasploit-only precision or boundary ties. The harness method has since
> changed (see "Reviewer notes" at the end). The numbers below are left exactly as generated;
> regenerating them on real mirrors with the revised harness is Mayank's next task. Label
> corrections in this file change wording only.

> **Evaluation Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  
> **Evaluation Dataset:** `evals/golden/enrichment_baseline.json` (50 CVEs)  
> **Mirror Cache:** `data/enrichment_cache` (Mode: Real Feed Mirrors)  

## 1. Executive Summary & Corroboration Metrics

Exposure Risk Score (ERS) combines technical severity (CVSS: 40%), exploitation probability (FIRST EPSS: 35%), and confirmed active exploitation (CISA KEV: 25%) additively.

- **Dataset Exploit Prevalence:** **36 / 50 CVEs** (72.0%) have a catalogue entry in ExploitDB or Rapid7 Metasploit (catalogue entry exists; not verified as working or weaponized).
- **Top Decile Precision (Balanced ERS):** **100.0%** of top-ranked CVEs have an ExploitDB or Metasploit catalogue entry.
- **Control Comparison (No-EPSS Control):** **100.0%** precision when EPSS is zeroed out.
- **CVSS-Only Baseline Precision:** **80.0%** precision under pure CVSS base score ranking.
- **EPSS Marginal Signal Gain:** **+0.0 pp** over CVSS+KEV control.
- **Full ERS vs CVSS Gain:** **+20.0 pp** over legacy CVSS prioritization.

## 2. Profile Ranking Performance (Precision & Recall Across Slices)

| Weight Profile | Weights (CVSS / EPSS / KEV) | Top Slice | Precision (%) | Recall (%) | Min ERS Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Balanced (Production Default)** | 0.40 / 0.35 / 0.25 | Top 5 (5 CVEs) | 100.0% | 13.9% | 9.98 |
| **Balanced (Production Default)** | 0.40 / 0.35 / 0.25 | Top 10 (10 CVEs) | 100.0% | 27.8% | 9.92 |
| **Balanced (Production Default)** | 0.40 / 0.35 / 0.25 | Top 15 (15 CVEs) | 100.0% | 41.7% | 9.92 |
| **No-EPSS Control (Severity+KEV)** | 0.60 / 0.00 / 0.40 | Top 5 (5 CVEs) | 100.0% | 13.9% | 10.0 |
| **No-EPSS Control (Severity+KEV)** | 0.60 / 0.00 / 0.40 | Top 10 (10 CVEs) | 100.0% | 27.8% | 9.88 |
| **No-EPSS Control (Severity+KEV)** | 0.60 / 0.00 / 0.40 | Top 15 (15 CVEs) | 93.3% | 38.9% | 9.88 |
| **CVSS-Only Baseline** | 1.00 / 0.00 / 0.00 | Top 5 (5 CVEs) | 80.0% | 11.1% | 10.0 |
| **CVSS-Only Baseline** | 1.00 / 0.00 / 0.00 | Top 10 (10 CVEs) | 90.0% | 25.0% | 9.8 |
| **CVSS-Only Baseline** | 1.00 / 0.00 / 0.00 | Top 15 (15 CVEs) | 80.0% | 33.3% | 9.8 |
| **Exploitation Heavy** | 0.25 / 0.50 / 0.25 | Top 5 (5 CVEs) | 100.0% | 13.9% | 9.98 |
| **Exploitation Heavy** | 0.25 / 0.50 / 0.25 | Top 10 (10 CVEs) | 100.0% | 27.8% | 9.95 |
| **Exploitation Heavy** | 0.25 / 0.50 / 0.25 | Top 15 (15 CVEs) | 100.0% | 41.7% | 9.95 |

## 3. Top-Ranked Vulnerabilities Corroboration Table

| Rank | CVE ID | ERS (Balanced) | CVSS | EPSS (%) | In KEV | Public Exploit | Metasploit | Cohort |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `CVE-2021-44228` | **10.00** | 10.0 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_a_nvd_control |
| 2 | `CVE-2024-3400` | **10.00** | 10.0 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_b_nvd_gap |
| 3 | `CVE-2023-22518` | **10.00** | 10.0 | 100.0% | ✅ Yes | — | ✅ MSF | cohort_c_cisa_kev |
| 4 | `CVE-2024-1709` | **10.00** | 10.0 | 100.0% | ✅ Yes | — | ✅ MSF | cohort_b_nvd_gap |
| 5 | `CVE-2023-20198` | **9.98** | 10.0 | 99.6% | ✅ Yes | — | ✅ MSF | cohort_c_cisa_kev |
| 6 | `CVE-2023-22515` | **9.97** | 10.0 | 99.2% | ✅ Yes | — | ✅ MSF | cohort_c_cisa_kev |
| 7 | `CVE-2019-11510` | **9.96** | 9.9 | 100.0% | ✅ Yes | ✅ EDB | — | cohort_a_nvd_control |
| 8 | `CVE-2022-22947` | **9.94** | 10.0 | 98.3% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_c_cisa_kev |
| 9 | `CVE-2019-0708` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_a_nvd_control |
| 10 | `CVE-2017-5638` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_a_nvd_control |
| 11 | `CVE-2024-23897` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | — | cohort_b_nvd_gap |
| 12 | `CVE-2024-4577` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_b_nvd_gap |
| 13 | `CVE-2022-26134` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_e_weaponized_exploit |
| 14 | `CVE-2023-27350` | **9.92** | 9.8 | 100.0% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_e_weaponized_exploit |
| 15 | `CVE-2024-27198` | **9.92** | 9.8 | 99.9% | ✅ Yes | ✅ EDB | ✅ MSF | cohort_b_nvd_gap |

## 4. Methodological Defense & Circularity Disclosure (D-038)

### A. Partial Circularity Analysis
In academic viva defense, evaluators may question whether validating ERS against ExploitDB / Metasploit is circular:
1. **Direct Input Independence:** ExploitDB and Metasploit are **not** direct inputs to the ERS formula. ERS inputs are strictly CVSS Base Score, FIRST EPSS v4 probability, and CISA KEV membership.
2. **Indirect Training Overlap (EPSS v4):** The FIRST EPSS machine learning model utilizes public exploit code availability (including ExploitDB records and GitHub PoCs) as features in its training pipeline. Therefore, corroborating ERS against ExploitDB involves partial feature overlap.
3. **Circularity Mitigation:**
   - ~~Independent Metasploit Corroboration~~ **(withdrawn in review):** Metasploit is not independent of EPSS; EPSS uses Metasploit modules among its features (D-029). A Metasploit catalogue entry does not make this check independent.
   - **Comparative Control Isolation:** By comparing Balanced ERS against the `no_epss_control` (EPSS zeroed out), we compare against EPSS zeroed out. On this run the top-5 gain was +0.0 pp (see Reviewer notes); it does not isolate a "precise" predictive value.
   - **Additive Non-Multiplicative Architecture:** ERS strictly avoids multiplying EPSS × CVSS (D-008; `services/enrichment/README.md` rule 3 — corrected from "Project Hard Rule 1", which is about graph edges). Each factor's provenance and contribution are recorded transparently in self-explaining `ScoreComponent` objects.

---

## Reviewer notes / interpretation (added 2026-10-12, PR #19 review)

Not generated by the harness. Every number in this section was computed by code from the
per-CVE scores and flags committed in `evals/results/ers_validation_results.json` (the `items`
array), using the revised `rank_items` / `evaluate_ranking` functions in
`evals/ers_validation.py`. It is a recomputation over the committed scores, not a rerun on mirrors.

1. **Status: small, biased, smoke-level corroboration. Not validation.**
   - n = 50 hand-picked CVEs, no documented selection rule (`evals/golden/README.md`).
   - Base rate: 36 / 50 (72.0%) have an ExploitDB or Metasploit catalogue entry, and 29 / 50
     (58.0%) have a Metasploit module. A random ranking has expected precision equal to the base
     rate, so 100% at top 5 has to be read against 72%, not against 0%.
   - Cohort E was selected for exploit presence (10 / 10 have a catalogue entry). Cohort C was
     selected on KEV membership (10 / 10 in KEV), and KEV is a 25% ERS input. 40 / 50 CVEs are
     in KEV overall.
   - Metasploit is not an independent target. EPSS uses exploit-code availability, including
     Metasploit modules and ExploitDB entries, among its features (D-029, D-038).
2. **EPSS added nothing measurable here.** `epss_marginal_precision_gain_pp` is **0.0** (balanced
   and no-EPSS control are both 100.0% at top 5). The top-15 difference (100.0% vs 93.3%) is
   one CVE (`CVE-2024-21413` in the control's top 15). Under the revised tie diagnostics the
   control's top-15 precision ranges over 93.3% - 100.0% depending on tie order (10 CVEs tie at
   the boundary score, 3 of them outside the slice). So this does not show that EPSS adds
   discriminating power.
3. **Top-k numbers hinge on one CVE, and ties were broken by input order.** At top 5, one CVE is
   20 pp. The pre-review harness used Python's stable sort, so tied scores kept dataset input
   order. The "+20.0 pp ERS vs CVSS" result comes from `CVE-2024-3094` (CVSS 10.0, no catalogue
   entry) entering the CVSS-only top 5 as one of 8 CVEs tied at 10.0. Recomputed with the new
   deterministic rule (score descending, then `cve_id` ascending), CVSS-only top-5 precision is
   100.0% (range over tie orders 80.0% - 100.0%), so the ERS-vs-CVSS top-5 gain is 0.0 pp under
   that rule. CVSS-only top 15 is 93.3% under the new rule (range 73.3% - 93.3%) against the
   80.0% shown above.
4. **Metasploit-only precision** (recomputed): top 5 is 100.0% for every profile. Top 10 is
   90.0% for balanced, no-EPSS and exploitation-heavy, and 80.0% for CVSS-only. Base rate 58.0%.
5. **Wording.** "Verified weaponized exploit" means only that a catalogue entry exists in the
   ExploitDB or Metasploit mirror. Nothing was executed or checked for working status (Hard Rule 4).
6. **Rerun required.** Regenerate with
   `python evals/ers_validation.py --cache-dir data/enrichment_cache --output-json evals/results/ers_validation_results.json --output-md evals/results/ers_validation_results.md`
   on a dated mirror snapshot, and replace this file.

---
_Generated by `evals/ers_validation.py`._
