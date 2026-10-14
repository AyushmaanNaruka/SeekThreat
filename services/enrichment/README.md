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

## Upstream Licences, Terms of Use & Disclaimers

All intelligence feeds ingested into SeekThreat are subject to their respective upstream licenses, terms of use, and attribution conditions (fully tracked in `THIRD_PARTY.md`):

1. **National Vulnerability Database (NVD API 2.0):**
   *Data produced by the National Institute of Standards and Technology (NIST).*
   > *Requested notice* ([NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use)): **"This product uses the NVD API but is not endorsed or certified by the NVD."** SeekThreat must not imply NVD endorsement.
   *Rate limits:* 5 requests per rolling 30 seconds without an API key; 50 requests per rolling 30 seconds with an API key. Automatic rate-limiting back-off with exponential retry is enforced by `FeedSyncer`.

2. **FIRST Exploit Prediction Scoring System (EPSS v4):**
   *EPSS is a community-driven initiative governed by the Forum of Incident Response and Security Teams (FIRST) EPSS Special Interest Group (SIG).*
   Attribution is given to the FIRST EPSS SIG and Empirical Security (FIRST requests attribution; see [EPSS data](https://www.first.org/epss/data_stats) and the [EPSS FAQ](https://www.first.org/epss/faq)). Academic citation: Jacobs et al., "Exploit Prediction Scoring System (EPSS)", *Digital Threats: Research and Practice* 2(3), 2021.

3. **European Vulnerability Database (ENISA EUVD):**
   *Managed by the European Union Agency for Cybersecurity (ENISA).*
   [ENISA Legal Notice](https://www.enisa.europa.eu/about-enisa/legal-notice): reuse permitted with source acknowledgement; an EUVD-specific licence is unconfirmed (*TO VERIFY* in `THIRD_PARTY.md`). An earlier "CC BY 4.0 per Decision 2011/833/EU" claim was not supported by the notice and was withdrawn. Data reused with attribution to ENISA.

4. **CVE Program (CVE.org):**
   *Managed by The MITRE Corporation.*
   Used in accordance with the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

5. **CISA Known Exploited Vulnerabilities (KEV) & Vulnrichment:**
   *Cybersecurity and Infrastructure Security Agency (CISA).*
   Released into the public domain under Creative Commons Zero 1.0 (CC0 1.0). Ingestion implies no official endorsement by DHS or CISA.

6. **ExploitDB & Rapid7 Metasploit:**
   Used strictly as **data facts** (CVE IDs, EDB-IDs, and Metasploit module names). No exploit code, scripts, or weaponized payloads are ingested or copied, adhering strictly to Project Hard Rule 4.

