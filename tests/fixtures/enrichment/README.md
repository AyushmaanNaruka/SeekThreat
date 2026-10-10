# Enrichment test fixtures — SYNTHETIC

The files in this directory (except `upstream/`, described at the end) are **synthetic test
fixtures**. They are shaped like the real
upstream feed formats so the source loaders can be exercised offline, but they are **not**
copies of real feeds and their values are **not real measurements**.

| File | Shaped like |
|---|---|
| `cve_org_sample.json` | CVE Services 5.1 `CVE_RECORD` objects, keyed by CVE ID |
| `cisa_kev_sample.json` | CISA Known Exploited Vulnerabilities catalog JSON |
| `epss_v4_sample.json` | FIRST EPSS API v4 response (`data` array) |
| `vulnrichment_sample.json` | CISA Vulnrichment enriched records (SSVC, CVSS, CWE) |
| `euvd_sample.json` | ENISA European Vulnerability Database records |
| `exploitdb_sample.json` | ExploitDB metadata (exploit IDs only, never exploit code) |
| `metasploit_sample.json` | Metasploit module metadata (module names only, never exploit code) |

- CVSS scores, EPSS probabilities/percentiles, KEV dates, catalog versions and ransomware flags
  are illustrative values chosen to drive test cases (high/moderate/low EPSS tiers, a non-KEV
  CVE, a KEV entry with `knownRansomwareCampaignUse: "Unknown"`, and so on). Do not cite them
  as current data for any CVE. They may be used for harness smoke tests only; results
  computed on them are not measurements and must be labelled synthetic.
- Each file carries a top-level `"_synthetic": true` and `"_comment"` key. The loaders in
  `services/enrichment/sources/` ignore unknown top-level keys, so the markers do not affect
  parsing.
- For real data, populate a mirror directory with the file names in
  `services.enrichment.sources.sync.MIRROR_FILENAMES` and pass it as `cache_dir`.

## `upstream/` — REAL captured responses (labelled)

Unlike the files above, `upstream/` holds **real** upstream responses, captured on
**2026-10-11** and trimmed to a few records so the parsers and `FeedSyncer` are tested
against the shapes the feeds actually publish. Trimming removed fields and records only; no
value was edited. They are dated snapshots, not current data, and are not measurements.

| File | Captured from | Trimmed to |
|---|---|---|
| `cisa_kev_catalog_sample.json` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | catalog header + first 2 entries |
| `epss_scores_sample.csv` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (302 to `epss_scores-2026-10-10.csv.gz`), decompressed | comment line, header, 3 rows |
| `cve_org_record_CVE-2021-44228.json` | `https://cveawg.mitre.org/api/cve/CVE-2021-44228` | `cveMetadata` + CNA `providerMetadata`/`title`/`descriptions`/`metrics`/`problemTypes` |
| `vulnrichment_record_CVE-2024-3400.json` | `https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/3xxx/CVE-2024-3400.json` | `cveMetadata`, CNA `title`/`metrics`/`problemTypes`, CISA-ADP container |
| `euvd_search_CVE-2024-3400.json` | `https://euvdservices.enisa.europa.eu/api/search?text=CVE-2024-3400&size=10` | the one item; product/vendor lists cut to 1 |
| `nvd_response_CVE-2021-44228.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228` | wrapper + `id`, dates, `vulnStatus`, `metrics`, `weaknesses`, English description |
| `metasploit_modules_metadata_sample.json` | `https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json` | 4 modules (2 exploit, 1 auxiliary, 1 payload); `name`/`fullname`/`type`/`references`/`mod_time` only (no descriptions, no code); Rapid7, BSD-3-Clause |
| `exploitdb_files_exploits_sample.csv` | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | first 2 rows, `id` and `codes` columns only (ExploitDB is GPL-2.0-or-later: we keep identifier facts, no descriptions, files or code) |
