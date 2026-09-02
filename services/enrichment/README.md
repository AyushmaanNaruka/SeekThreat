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
2. **Fallback chain:** CVE.org -> Vulnrichment -> EUVD -> derived. Label derived values.
3. **Never multiply EPSS by CVSS.** It does not compute probability x severity. FIRST is
   explicit about this.
4. **ERS must explain itself.** Every score renders its component breakdown.
5. Mirror sources locally. Don't hit APIs on the request path.
