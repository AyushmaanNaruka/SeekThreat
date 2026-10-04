# Enrichment test fixtures — SYNTHETIC

The files in this directory are **synthetic test fixtures**. They are shaped like the real
upstream feed formats so the source loaders can be exercised offline, but they are **not**
copies of real feeds and their values are **not real measurements**.

| File | Shaped like |
|---|---|
| `cve_org_sample.json` | CVE Services 5.1 `CVE_RECORD` objects, keyed by CVE ID |
| `cisa_kev_sample.json` | CISA Known Exploited Vulnerabilities catalog JSON |
| `epss_v4_sample.json` | FIRST EPSS API v4 response (`data` array) |

- CVSS scores, EPSS probabilities/percentiles, KEV dates, catalog versions and ransomware flags
  are illustrative values chosen to drive test cases (high/moderate/low EPSS tiers, a non-KEV
  CVE, a KEV entry with `knownRansomwareCampaignUse: "Unknown"`, and so on). Do not cite them
  as current data for any CVE, and do not use them in evaluations or reports.
- Each file carries a top-level `"_synthetic": true` and `"_comment"` key. The loaders in
  `services/enrichment/sources/` ignore unknown top-level keys, so the markers do not affect
  parsing.
- For real data, populate a mirror directory with the file names in
  `services.enrichment.sources.sync.MIRROR_FILENAMES` and pass it as `cache_dir`.
