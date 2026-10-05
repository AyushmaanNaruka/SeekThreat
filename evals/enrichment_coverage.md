# Enrichment Coverage Evaluation Metric Specification

## 1. Overview and Objective

In April 2026, the National Vulnerability Database (NVD) scaled back its enrichment operations,
leaving a substantial proportion of newly published CVEs in an "Awaiting Analysis" or "Not Scheduled"
state without CVSS severity scores, CWE taxonomy classifications, or standardized descriptions.
Furthermore, an NVD-only scanning strategy provides no signal for:
- Exploitation probability (FIRST EPSS)
- Active in-the-wild exploitation (CISA KEV)
- Public exploit weaponization (ExploitDB, Metasploit)

The **SeekThreat Multi-Source Fusion Engine** addresses this intelligence gap by querying canonical
and secondary feeds with strict per-field provenance and deterministic fallback chains:
`CVE.org -> CISA Vulnrichment -> NVD 2.0 -> ENISA EUVD -> Derived`.

This specification formalizes the **Enrichment Coverage Metric**, which quantifies the measurable
gain in vulnerability intelligence provided by SeekThreat's multi-source fusion over an NVD-only baseline.

---

## 2. Core Metric Definitions

### 2.1 Evaluated Fields

Enrichment coverage is evaluated across six (6) distinct intelligence dimensions:

| Field Identifier | Intelligence Dimension | Meaning of "Filled" (Non-Placeholder) | Placeholder / Empty Definition |
|---|---|---|---|
| `cvss_score` | Vulnerability Severity | Attributed numeric CVSS score from an authoritative feed (`CVE_ORG`, `VULNRICHMENT`, `NVD`, `EUVD`). | `Source.DERIVED`, `Confidence.LOW`, placeholder score == 5.0. |
| `cwe_ids` | Weakness Taxonomy | List of specific CWE identifiers (e.g. `["CWE-79"]`, `["CWE-502"]`). | `Source.DERIVED`, `Confidence.LOW`, `["CWE-Other"]` (fallback) or empty list. |
| `summary` | Vulnerability Description | Authoritative natural-language description from an authoritative feed. | Absent, empty string, or derived generic placeholder. |
| `epss_score` | Exploitation Probability | Numeric probability from FIRST EPSS v4 (`Source.EPSS`, `Confidence.HIGH`). | `Source.DERIVED`, `Confidence.LOW`, score == 0.001 (default placeholder). |
| `in_kev` | Active Exploitation Status | Definite boolean (`True` or `False`) with `Source.KEV`, `Confidence.HIGH`. | `None`, `Source.DERIVED`, `Confidence.LOW` ("KEV status unknown"). |
| `exploit_availability` | Weaponization & Exploit Presence | Definite boolean (`True` or `False`) with `Source.EXPLOITDB` or `Source.METASPLOIT`. | `None`, `Source.DERIVED`, `Confidence.LOW` (mirror not loaded / status unknown). |

### 2.2 Finding-Level Field Assessment

For a finding i and field j in {1, ..., 6} under engine configuration M:

- `filled(i, j, M) = 1` if field j has an authoritative, non-placeholder value.
- `filled(i, j, M) = 0` if field j is missing, None, or a DERIVED/LOW placeholder.

### 2.3 Per-Field Coverage

For a dataset of N findings, the coverage of field j under configuration M is:

`Coverage_j(M) = (sum_{i=1}^{N} filled(i, j, M) / N) * 100%`

### 2.4 Overall Enrichment Coverage

Total evaluated field instances across N findings is 6 * N. Overall coverage is the proportion
of all field instances containing non-placeholder intelligence:

`Coverage(M) = (sum_{i=1}^{N} sum_{j=1}^{6} filled(i, j, M) / (6 * N)) * 100%`

### 2.5 Coverage Improvement

The coverage improvement of SeekThreat Multi-Source (M_multi) over the NVD-Only Baseline (M_nvd) is:

`Delta_Coverage = Coverage(M_multi) - Coverage(M_nvd)`

Expressed in percentage points.

---

## 3. Evaluation Configurations

### 3.1 NVD-Only Baseline Configuration (M_nvd)
- **Active Source:** `NVDSource` only.
- **Secondary / Fallback Sources:** None.
- **EPSS Feed:** None (unloaded -> returns `Source.DERIVED` placeholder).
- **KEV Catalog:** None (unloaded -> returns `in_kev=None`, `Source.DERIVED`).
- **Exploit Feeds:** None (unloaded -> returns `has_public_exploit=None`, `has_metasploit_module=None`).

### 3.2 Multi-Source Fusion Configuration (M_multi)
- **Primary Source:** `CVEOrgSource` (CVE Services 5.1).
- **Secondary Sources:** `VulnrichmentSource` (CISA, rank 2), `NVDSource` (NVD 2.0, rank 3), `EUVDSource` (ENISA, rank 4).
- **EPSS Feed:** `FirstEPSSSource` (FIRST EPSS v4 probability & percentile).
- **KEV Catalog:** `CISAKevSource` (CISA Known Exploited Vulnerabilities catalog).
- **Exploit Intelligence:** `ExploitDBSource` & `MetasploitSource` (exploit existence and module identifiers; never exploit code).

---

## 4. Evaluation Dataset Cohorts

The evaluation dataset (`evals/golden/enrichment_baseline.json`) contains a minimum of 50 CVE IDs
divided into five distinct analytical cohorts:

1. **Cohort A: Full NVD Control Group** ? Historic, widely documented CVEs where NVD provided complete CVSS, CWE, and description.
2. **Cohort B: NVD Gap CVEs** ? CVEs where NVD moved to "Not Scheduled" or "Awaiting Analysis", but CVE.org / Vulnrichment / EUVD provide full severity and taxonomy data.
3. **Cohort C: CISA KEV Exploited CVEs** ? Vulnerabilities with confirmed active exploitation in the wild listed in CISA KEV.
4. **Cohort D: High EPSS / No NVD CVSS** ? Vulnerabilities with elevated exploitation probability where traditional CVSS scanners lack severity metrics.
5. **Cohort E: Weaponized Exploit Entries** ? CVEs with public exploits in ExploitDB or automated modules in Metasploit.

---

## 5. Execution and Reporting Rules

Per `evals/README.md`:
1. **Never fabricate metrics.** Numbers must be computed by executing `evals/enrichment_coverage.py`.
2. **Provenance of evaluation data.** If run against synthetic offline fixtures, reports must explicitly declare:
   *"Measured against synthetic fixture files (`tests/fixtures/enrichment/`)."*
   When run against real mirrors, reports must state the mirror date and hash.
3. **No network calls on request path.** Evaluation harness operates 100% offline using local cache directories.
