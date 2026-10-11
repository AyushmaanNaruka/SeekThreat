# Task 3 Implementation: Real Layer 2 Evaluation & Baseline Measurement

> **Document:** `docs/mayank_implementation/task3_level2_work.md`  
> **Topic:** Task 3 of `docs/mayank_implementation/mayank_task_level2.md` (PR 4: `eval/real-layer2-coverage`)  
> **Author:** Mayank Narang  
> **Status:** ✅ Complete — Layer 2 Milestone Formally Delivered (612 unit/integration tests passed, 19 frontend tests passed, all quality gates clean)  

---

## 1. Executive Summary

In the SeekThreat project roadmap, Layer 2 ("Enrichment — feeds, secondary sources, fallback, ERS, UI") has a strict October milestone delivery criterion defined in `docs/00-scope.md`:
> **"Done when: Coverage measured against an NVD-only baseline."**

Prior to Task 3, `evals/enrichment_coverage.py` had only been run as a smoke test against synthetic fixtures in `tests/fixtures/enrichment/` (producing `evals/results/enrichment_coverage_results.json` explicitly labelled with the `SYNTHETIC SMOKE TEST` banner). As mandated by `evals/README.md` ("No number in this project has been measured yet. Never generate placeholder metrics that look like results"), that synthetic smoke test was not a platform measurement.

**Task 3 delivers SeekThreat's first genuine empirical measurement using real feed mirrors and a verified golden CVE dataset:**
1. **Real Golden Dataset (`evals/golden/enrichment_baseline.json` v2.0.0):** Established 50 real-world CVEs across 5 documented cohorts. Replaced all synthetic placeholders (`CVE-2025-0001`, `CVE-2025-0002`) with genuine vulnerabilities (`CVE-2024-21893`, `CVE-2024-28995`). Each entry was individually verified against live upstream catalogs by Mayank Narang on 2026-10-11.
2. **Full Live Upstream Mirror Synchronization:** Synchronized all 8 intelligence mirrors into `data/enrichment_cache` (including FIRST EPSS ~385k rows, CISA KEV 1,739 rows, ExploitDB 25k rows, Metasploit 2.5k modules, and per-CVE records for NVD API 2.0, CVE.org, Vulnrichment, and EUVD).
3. **Empirical Offline Coverage Evaluation:** Executed `evals/enrichment_coverage.py` in non-synthetic mode against `data/enrichment_cache`.
4. **Headline Result:** Multi-source fusion achieved **98.0% (196/200)** headline coverage vs **73.0% (146/200)** for the NVD-only baseline, delivering an empirical **+25.0 percentage point gain**.
5. **Committed Results:** Produced and committed [`evals/results/enrichment_coverage_real.json`](file:///e:/SeekThreat/SeekThreat/evals/results/enrichment_coverage_real.json) and [`evals/results/enrichment_coverage_real.md`](file:///e:/SeekThreat/SeekThreat/evals/results/enrichment_coverage_real.md), capturing exact mirror SHA256 hashes, generation timestamps, and per-cohort breakdowns.

---

## 2. Golden Evaluation Dataset Construction (`enrichment_baseline.json` v2.0.0)

In accordance with `evals/golden/README.md` ("never from memory — always from verified ground truth"), the golden dataset was upgraded to **v2.0.0** (`_synthetic: false`).

### A. Stratified Cohort Design (50 Real CVEs)

| Cohort | Focus & Scope | Count | Representative CVEs |
| :--- | :--- | :--- | :--- |
| **Cohort A: NVD Control** | Established enterprise vulnerabilities well-covered by NVD | 10 | `CVE-2021-44228` (Log4Shell), `CVE-2021-41773` (Apache Path Traversal), `CVE-2017-0144` (EternalBlue), `CVE-2014-0160` (Heartbleed) |
| **Cohort B: NVD Gap** | Recent zero-days, edge device & VPN exploits with historical NVD publication delays | 10 | `CVE-2024-3400` (PAN-OS GlobalProtect), `CVE-2024-21893` (Ivanti Connect Secure), `CVE-2024-21762` (Fortinet SSL-VPN), `CVE-2024-3094` (XZ Utils Backdoor) |
| **Cohort C: CISA KEV** | Actively exploited vulnerabilities listed in CISA KEV catalog | 10 | `CVE-2023-34362` (MOVEit Transfer), `CVE-2023-22515` (Confluence Broken Access Control), `CVE-2023-20198` (Cisco IOS XE), `CVE-2024-21887` (Ivanti Injection) |
| **Cohort D: High EPSS** | Critical infrastructure vulnerabilities with high EPSS probability | 10 | `CVE-2022-22965` (Spring4Shell), `CVE-2024-28995` (SolarWinds Serv-U), `CVE-2024-30078` (Windows Wi-Fi RCE), `CVE-2024-38063` (Windows IPv6 RCE) |
| **Cohort E: Weaponized Exploit** | High-severity vulnerabilities with public exploits in ExploitDB and Metasploit | 10 | `CVE-2020-1472` (Zerologon), `CVE-2021-34527` (PrintNightmare), `CVE-2021-26855` (ProxyLogon), `CVE-2021-34473` (ProxyShell), `CVE-2023-0669` (GoAnywhere) |

### B. Replacement of Synthetic Artifacts
- **Previous Artifacts:** Items #12 and #32 were previously synthetic placeholders (`CVE-2025-0001` and `CVE-2025-0002`).
- **Real-World Replacements:**
  - `CVE-2025-0001` was replaced by **`CVE-2024-21893`** (Ivanti Connect Secure SSRF, CVSS 8.2, in CISA KEV).
  - `CVE-2025-0002` was replaced by **`CVE-2024-28995`** (SolarWinds Serv-U Directory Traversal, CVSS 8.6, EPSS 0.972, in CISA KEV).
- **Verification Metadata:** Every entry records `authoritative_source`, `verified_by: "Mayank Narang"`, and `verified_at: "2026-10-11"`.

---

## 3. Live Upstream Mirror Synchronization Audit

All 8 intelligence mirrors were synchronized from authoritative upstream APIs using `services.enrichment.sync_feeds` into `data/enrichment_cache/`. Every mirror generated a cryptographically verifiable `.meta.json` sidecar.

| Source Mirror | Upstream API / Source | Target Cache File | Records | File Size | SHA256 Hash | Synced Timestamp |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NIST NVD API 2.0** | `services.nvd.nist.gov/rest/json/cves/2.0` | `nvd.json` | 50 | 258 KB | `218f7d649a7c0124dfb970377627bcd10b9e77cf0157dc78fc0e89fde3a854f8` | `2026-10-11T15:00:45Z` |
| **CVE Services 5.x** | `cveawg.mitre.org/api/cve/` | `cve_org.json` | 50 | 429 KB | `6b7c05da5a3ac93182396fe7212430cac3b7996f176a849595c5f86bcc4be36c` | `2026-10-11T14:49:12Z` |
| **CISA Vulnrichment**| `raw.githubusercontent.com/cisagov/vulnrichment` | `vulnrichment.json` | 49 | 423 KB | `e571697ee56c46526d2d587da69e8cda644ba8a43574d883c7cb4baff026573a` | `2026-10-11T14:49:46Z` |
| **ENISA EUVD** | `euvdservices.enisa.europa.eu/api/search` | `euvd.json` | 50 | 200 KB | `d5513cf21a4c6233a33b93ef1710917f3b2e6bb05dec0b735a37cb57354f805b` | `2026-10-11T14:54:20Z` |
| **FIRST EPSS v4** | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | `epss_v4.json` | 385,738 | 23.3 MB | `1a638ce526fd216296a0615e11b9a14d526016d879aa30e1181cfcb19ba2ff4d` | `2026-10-11T14:48:38Z` |
| **CISA KEV Catalog**| `www.cisa.gov/.../known_exploited_vulnerabilities.json` | `cisa_kev.json` | 1,739 | 1.39 MB | `6ca5d289d4932aea583705c80bf25cca2cc3d9e7eba802bec79603f04b159611` | `2026-10-11T14:47:46Z` |
| **OffSec ExploitDB** | `gitlab.com/exploit-database/exploitdb/.../files_exploits.csv` | `exploitdb.json` | 25,090 | 2.49 MB | `0fe059914b4ea2e6f4b61ad8badfd71658272df99fce272797ecb0a96c84104c` | `2026-10-11T14:47:59Z` |
| **Rapid7 Metasploit**| `raw.githubusercontent.com/.../modules_metadata_base.json` | `metasploit.json` | 2,554 | 357 KB | `163139cc0cce2a06b4711871b72bab18f62be012879872014bc019e3bedb3c54` | `2026-10-11T14:48:22Z` |

> **Note on NVD 2.0 Sync:** Executed with unauthenticated delay `NVD_DELAY_NO_KEY_SECONDS = 6.0s` across all 50 CVEs without triggering any rate-limit 403/429 failures.

---

## 4. Empirical Evaluation Results

Execution of `evals/enrichment_coverage.py`:
```powershell
python evals/enrichment_coverage.py `
  --cache-dir data/enrichment_cache `
  --dataset evals/golden/enrichment_baseline.json `
  --output-json evals/results/enrichment_coverage_real.json `
  --output-md evals/results/enrichment_coverage_real.md
```

### A. Headline Coverage Comparison

Headline coverage counts the four core intelligence fields: `cvss_score`, `cwe_ids`, `summary`, and `epss_score`.

| Metric | NVD-Only Baseline | SeekThreat Multi-Source Fusion | Empirical Delta |
| :--- | :--- | :--- | :--- |
| **Overall Headline Coverage** | **73.0%** (146 / 200 fields) | **98.0%** (196 / 200 fields) | **+25.0 percentage points** |

### B. Per-Field Breakdown

| Field | Baseline (NVD-Only) | Multi-Source Fusion | Improvement | Key Observation |
| :--- | :--- | :--- | :--- | :--- |
| **`cvss_score`** | 100.0% (50/50) | 100.0% (50/50) | +0.0 pp | NVD eventually published scores for all 50 historic/recent CVEs; multi-source provides multi-provider redundancy. |
| **`cwe_ids`** | 92.0% (46/50) | 92.0% (46/50) | +0.0 pp | 4 CVEs have no specific CWE assigned upstream across any feed. |
| **`summary`** | 100.0% (50/50) | 100.0% (50/50) | +0.0 pp | Complete descriptions available from NVD and CVE Services. |
| **`epss_score`** | **0.0%** (0/50) | **100.0%** (50/50) | **+100.0 pp** | NVD does not serve EPSS. Multi-source integration provides complete 30-day exploitation probability coverage. |

### C. Secondary Signal Fields (Not in Headline)

Signal fields evaluate whether mirrors provide definite answers (`True` / `False`) rather than unknown (`None`), along with the positive hit rate:

| Signal Field | Baseline (NVD-Only) | Multi-Source Fusion | Positive Hit Count |
| :--- | :--- | :--- | :--- |
| **`in_kev`** | *Not loaded* (unknown) | **Loaded** (100% definite answers) | **80.0%** (40 / 50 CVEs confirmed in CISA KEV) |
| **`exploit_availability`** | *Not loaded* (unknown) | **Loaded** (100% definite answers) | **72.0%** (36 / 50 CVEs with weaponized exploits) |

### D. Cohort Analysis (Headline Coverage)

| Cohort | Evaluated CVEs | NVD-Only Baseline | Multi-Source Fusion | Delta |
| :--- | :--- | :--- | :--- | :--- |
| **Cohort A: NVD Control** | 10 | 72.5% | 97.5% | +25.0 pp |
| **Cohort B: NVD Gap** | 10 | 75.0% | 100.0% | +25.0 pp |
| **Cohort C: CISA KEV** | 10 | 75.0% | 100.0% | +25.0 pp |
| **Cohort D: High EPSS** | 10 | 75.0% | 100.0% | +25.0 pp |
| **Cohort E: Weaponized Exploit** | 10 | 67.5% | 92.5% | +25.0 pp |

---

## 5. Viva Defensibility & Analytical Insights

In the final defense, evaluators will scrutinize why multi-source fusion matters if NVD eventually achieves 100% CVSS coverage for historic CVEs:

1. **The Definitional EPSS Advantage (+100.0 pp):**
   NIST NVD does not compute or distribute EPSS scores. Without Layer 2's direct FIRST EPSS integration, a SOC analyst or vulnerability management team is blind to the 30-day probability of active exploitation in the wild.
2. **Actionable Threat Intelligence vs Severity Descriptions:**
   CVSS measures theoretical severity (e.g. CVSS 9.8). However, without CISA KEV and ExploitDB/Metasploit corroboration, an organization cannot differentiate between a theoretical CVSS 9.8 vulnerability with 0% real-world exploit probability and an actively weaponized CVSS 7.5 vulnerability used in ransomware campaigns. Multi-source fusion fills this operational intelligence gap.
3. **Resilience Against Upstream Outages and Publication Lags:**
   During real-world zero-day disclosures (such as Ivanti `CVE-2024-21893` or PAN-OS `CVE-2024-3400`), CISA Vulnrichment and CVE Services publish actionable CVSS and SSVC vectors days or weeks before NVD finalizes its analysis. The multi-source fallback chain (`CVE.org -> Vulnrichment -> NVD -> EUVD -> Derived`) guarantees zero analysis downtime.

---

## 6. Verification Checklist & Quality Gates

All automated verification commands passed cleanly:

- [x] **Backend Unit & Integration Tests:** `pytest tests -q` — **612 passed, 5 skipped** (100% green).
- [x] **Coverage Eval Unit Tests:** `pytest tests/unit/test_enrichment_coverage_eval.py` — **17 passed**.
- [x] **Frontend Unit Tests:** `npm --prefix apps/web test` — **19 passed, 0 failed**.
- [x] **Linter & Code Style:** `ruff check` — Clean (no warnings or errors).
- [x] **Code Formatter:** `ruff format --check` — Clean (169 files formatted).
- [x] **Static Type Checking:** `mypy packages services apps` — Clean (51 source files checked, 0 errors).
- [x] **Committed Real Artifacts:** `evals/results/enrichment_coverage_real.json` and `evals/results/enrichment_coverage_real.md` generated directly from executed code.
- [x] **Layer 2 Milestone Done-When Criterion:** Formally verified and delivered.
