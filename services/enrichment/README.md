# services/enrichment

**Our core work. Do not outsource this.**

Multi-source fusion with provenance. Every field carries where it came from and how confident
we are, with fallback chains when the primary source has nothing.

## Why it matters

In April 2026 the NVD stopped enriching most CVEs — only KEV entries, federal software, and
EO 14028 critical software get full enrichment, roughly 15–20% of volume. Around 29,000 older
CVEs moved to "Not Scheduled."

Any tool that asks the NVD for a CVSS score and displays it now returns empty for most
findings. This layer is the answer, and it is one of our two research contributions.

## Sources, in priority order

| Source | Gives us |
|---|---|
| CVE.org | Canonical record, CNA-supplied CVSS/CWE — now primary |
| CISA Vulnrichment | SSVC decision points, CWE, CVSS on higher-risk CVEs |
| CISA KEV | Confirmed active exploitation — first-tier signal |
| FIRST EPSS v4 | Exploitation probability; scores CVEs with no CVSS |
| NVD 2.0 | CVSS/CPE where still enriched — one input, not the input |
| ENISA EUVD | European fallback (beta, incomplete) |
| OSV.dev | Package/ecosystem vulns NVD misses |
| GitHub Advisories | Open-source package coverage |
| ExploitDB | Public exploit existence |
| Metasploit | Exploit maturity signal |

## Rules

1. **Every field gets a `Provenance`.** No unattributed data.
2. **Fallback chain:** CVE.org -> Vulnrichment -> NVD -> EUVD -> derived, per field (CVSS,
   CWE, description). This is `_CHAIN_ORDER` in `fusion.py`. Label derived values: when no
   source in the chain has a value, CVSS/EPSS fall back to `PLACEHOLDER_*` constants
   attributed `derived`/`low` and noted "Not a measurement".
3. **Never multiply EPSS by CVSS.** It does not compute probability x severity. FIRST is
   explicit about this.
4. **ERS must explain itself.** Every score renders its component breakdown.
5. Mirror sources locally. Don't hit APIs on the request path.
6. **Absence is not a confident negative.** An unloaded mirror yields `None`
   (`derived`/`low`, "unknown"). A CVE absent from a loaded KEV catalog is `False` (`high`);
   absent from a loaded ExploitDB/Metasploit mirror it is `False` at `medium` only, because
   a public exploit can exist that neither indexes.

## Feed mirrors

`sources/sync.py` (`FeedSyncer`) is the only code allowed to reach the network. It runs as
the Celery task `seekthreat.sync_feeds.run` (daily 02:00 UTC via the `beat` compose
service) or as `python -m services.enrichment.sync_feeds`. Both write to
`ENRICHMENT_CACHE_DIR` (default `data/enrichment_cache`), the same directory the API and
worker read.

| Source | Mode | Upstream |
|---|---|---|
| CISA KEV | full mirror | `known_exploited_vulnerabilities.json` |
| FIRST EPSS | full mirror | daily bulk CSV `epss_scores-current.csv.gz`; `score_date` is the record date |
| ExploitDB | full mirror | `files_exploits.csv`, `id`/`codes` columns only |
| Metasploit | full mirror | `modules_metadata_base.json`, `type == "exploit"` modules, `fullname` only |
| CVE.org | targeted per CVE | `cveawg.mitre.org/api/cve/{id}` |
| Vulnrichment | targeted per CVE | `cisagov/vulnrichment/{year}/{n//1000}xxx/{id}.json` |
| ENISA EUVD | targeted per CVE | `euvdservices.enisa.europa.eu/api/search?text={id}`, exact alias match |
| NVD 2.0 | targeted per CVE | `services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`, 5 req/30 s without key |

Targeted sources fetch only the CVE IDs found in `enriched_findings` (plus any passed in)
and merge them into the mirror keyed by CVE ID. Every write is atomic, refuses to replace a
mirror with an empty result or one under 50% of its previous record count, and leaves a
`<name>.meta.json` sidecar (`synced_at`, `source_url`, `record_count`, `sha256` of the file
written). Readers use `synced_at` as `retrieved_at` for records with no date of their own.
