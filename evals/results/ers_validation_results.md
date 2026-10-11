# ERS Empirical Validation & Exploit Corroboration Report

> **Evaluation Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  
> **Evaluation Dataset:** `evals/golden/enrichment_baseline.json` (50 CVEs)  
> **Mirror Cache:** `data/enrichment_cache` (Mode: Real Feed Mirrors)  

## 1. Executive Summary & Corroboration Metrics

Exposure Risk Score (ERS) combines technical severity (CVSS: 40%), exploitation probability (FIRST EPSS: 35%), and confirmed active exploitation (CISA KEV: 25%) additively.

- **Dataset Exploit Prevalence:** **36 / 50 CVEs** (72.0%) possess verified weaponized exploits in ExploitDB or Rapid7 Metasploit.
- **Top Decile Precision (Balanced ERS):** **100.0%** of top-ranked CVEs have verified public exploits.
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
   - **Independent Metasploit Corroboration:** Metasploit module presence indicates weaponized, high-reliability exploit tooling that requires manual engineering beyond raw PoC scripts.
   - **Comparative Control Isolation:** By comparing Balanced ERS against the `no_epss_control` (EPSS zeroed out), we empirically isolate the precise predictive value added by EPSS versus technical severity alone.
   - **Additive Non-Multiplicative Architecture:** ERS strictly avoids multiplying EPSS × CVSS (Project Hard Rule 1 & D-008). Each factor's provenance and contribution are recorded transparently in self-explaining `ScoreComponent` objects.

---
_Generated by `evals/ers_validation.py`._
