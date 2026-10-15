# Third-party register

Every external project we use. Maintained from day one, and included as an appendix in the
final report.

**A table listing exactly what we built on reads as rigour. A gap discovered later reads as
something much worse.** Be loud about this.

## When to add a row

Add an entry when you:
- copy any code into `vendor/`
- run an external project as a service we depend on
- ingest a dataset produced by an external project
- add a library that is central to a core subsystem

Routine, well-known libraries (FastAPI, React, pytest) do not need rows — they are in the
dependency manifests.

**CI fails the build if `vendor/` changes without a matching change here.**

## Modes

| Mode | Meaning | Licence risk |
|---|---|---|
| **Service** | We run their container and call their API | None |
| **Study** | We read their design and wrote our own | None |
| **Vendored** | Their code lives in `vendor/` | Their licence applies to us |
| **Data** | We ingest data they produce, not their code | Check data licence |

---

## Register

| Project | Licence | Mode | What we use | Verified by | Date |
|---|---|---|---|---|---|
| BRON (MIT ALFA group) | MIT | Data | CVE→CWE→CAPEC→ATT&CK graph substrate (github.com/ALFA-group/BRON) | Mayank Narang | 2026-10-11 |
| DefectDojo | BSD-3-Clause | Study / Vendored | Scanner output parser patterns (django-DefectDojo) | Mayank Narang | 2026-10-11 |
| Nmap | NPSL | Service | Invoked as subprocess, XML output parsed. Source never vendored | | |
| NetworkX | BSD-3-Clause | Service | In-memory attack graph substrate (D-003) | Ayushmaan | 2026-09-05 |
| PyYAML | MIT | Service | Rules-as-data loading for the path engine (D-004) | Ayushmaan | 2026-09-05 |
| Nuclei | MIT (ProjectDiscovery) | Service | Invoked as subprocess, JSONL output parsed. Source never vendored | Ayushmaan | 2026-09-20 |
| Nuclei Templates | MIT (ProjectDiscovery) | Vendored | Official vulnerability template archive pinned in container image | Mayank | 2026-09-25 |
| Nikto | GPL-2.0 (sullo/nikto) | Service | Invoked as subprocess, JSON report parsed. Source never vendored or copied (D-043) | Claude agent — human to confirm | 2026-10-12 |
| ssh-audit | MIT (jtesta/ssh-audit LICENSE) | Service | Invoked as subprocess, `-j` JSON output parsed. Source never vendored (D-043) | Claude agent read LICENSE — human to confirm | 2026-10-12 |
| Greenbone / OpenVAS | GPL | Service | Run as container, GMP API via python-gvm | | |
| Foundation-Sec-8B-Reasoning | Open weights | Service | Local model serving | | |
| CISA Vulnrichment | CC0-1.0 (Public Domain, cisagov/vulnrichment LICENSE) | Data | Per-CVE files fetched for CVEs we have seen: SSVC decision points, CWE, CVSS fallback | Mayank Narang | 2026-10-11 |
| CISA KEV catalog | CC0-1.0 (Public Domain, cisagov/kev-data LICENSE; no CISA/DHS seal use or implied endorsement) | Data | Full catalog JSON mirrored daily; confirmed-exploitation flag, date added, ransomware use | Mayank Narang | 2026-10-11 |
| FIRST EPSS | Free use; attribution requested (FIRST EPSS FAQ). Cite Jacobs et al. 2021 — see note [E] | Data | Daily bulk CSV (`epss_scores-current.csv.gz`). Attribution to FIRST EPSS SIG / Empirical Security in documentation and UI | Mayank Narang (no terms page cited; see note [E]) | 2026-10-11 |
| CVE.org (CVE Services) | CVE Program Terms of Use — https://www.cve.org/Legal/TermsOfUse (see note [C]) | Data | Per-CVE CVE_RECORD from `cveawg.mitre.org/api/cve/{id}`; perpetual royalty-free non-exclusive licence to reproduce and create derivative works; MITRE copyright/disclaimer retained | Mayank Narang | 2026-10-15 |
| NVD API 2.0 | Public Domain (US Government work / NIST); NVD Terms of Use — https://nvd.nist.gov/developers/terms-of-use (see note [N]) | Data | Per-CVE records from `services.nvd.nist.gov/rest/json/cves/2.0?cveId=`; 5 req/30 s without key, 50 req/30 s with key; requested notice displayed in UI and docs: "This product uses the NVD API but is not endorsed or certified by the NVD"; must not imply NVD endorsement | Mayank Narang | 2026-10-15 |
| ENISA EUVD | ENISA Legal Notice: reuse permitted with source acknowledgement; EUVD-specific licence unconfirmed — *TO VERIFY* (see note [U]) | Data | Per-CVE lookup via `euvdservices.enisa.europa.eu/api/search?text={id}`; base score/vector/version, description; credit to European Union Agency for Cybersecurity (ENISA) | Mayank Narang (general notice confirmed; data licence TO VERIFY) | 2026-10-15 |
| ExploitDB (OffSec) | GPL-2.0-or-later (repository); Data only | Data | Data only: derived CVE→EDB-ID facts from `files_exploits.csv` `id`/`codes` columns; no files or code copied (Hard Rule 4) | Mayank Narang | 2026-10-11 |
| Rapid7 Metasploit Framework | BSD-3-Clause (Rapid7) | Data | `modules_metadata_base.json`: CVE → exploit module `fullname` only, `type == "exploit"`; no module code (Hard Rule 4) | Mayank Narang | 2026-10-11 |

### Data-feed licence sources (updated 2026-10-15, Track D verification)

The data-feed rows above record the terms pages verified against official sources.

| Note | Feed | Source URL | Accessed | Status | Notes |
|---|---|---|---|---|---|
| [U] | ENISA EUVD | https://www.enisa.europa.eu/about-enisa/legal-notice ; https://euvd.enisa.europa.eu | 2026-10-15 | Confirmed (general notice only; status *TO VERIFY*) | The general ENISA Legal Notice authorises reproduction of ENISA material provided the source is acknowledged, unless stated otherwise. No separate open data licence (CC BY 4.0 or Decision 2011/833/EU) is posted on the EUVD portal. Endpoint verification (Task D-4): `GET /api/vulnerability?id={id}` returns HTTP 403 Forbidden; the public search endpoint `GET /api/search?text={id}` returns HTTP 200 with an `items` array. Code in `services/enrichment/sources/sync.py` uses `/api/search` with exact alias matching. Status stays *TO VERIFY* for a dedicated data licence. |
| [N] | NVD API 2.0 | https://nvd.nist.gov/developers/terms-of-use | 2026-10-15 | Confirmed (verified via browser rendering) | Public service created by NIST (U.S. Government work / public domain). No commercial restrictions. Permitted to search, display, analyze, retrieve, view NVD data. Attribution and endorsement disclaimer: must display `"This product uses the NVD API but is not endorsed or certified by the NVD."` Must not imply NVD endorsement. If content is modified, source may not be attributed as NVD. Public rate limits apply without a key (~5 req/30 s); registered API key raises limit (~50 req/30 s); keys must not be shared. |
| [C] | CVE.org | https://www.cve.org/Legal/TermsOfUse | 2026-10-15 | Confirmed (verified via browser rendering) | MITRE grants a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Authorized provided MITRE's copyright designation and license are reproduced in any copy. All documents provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. |
| [E] | FIRST EPSS | https://www.first.org/epss/data_stats ; https://www.first.org/epss/faq | 2026-10-12 | FAQ confirmed; data_stats returned HTTP 404 | The FAQ says EPSS data is free to use and that attribution is requested when it is used in publications or products. Academic citation: Jacobs, J., Romanosky, S., Edwards, B., Adjerid, I., Roytman, M., "Exploit Prediction Scoring System (EPSS)", *Digital Threats: Research and Practice* 2(3), 2021. |
| — | CISA KEV, CISA Vulnrichment | https://github.com/cisagov/kev-data ; https://github.com/cisagov/vulnrichment (LICENSE files) | — | Not re-checked in review | CC0-1.0 per the original check. |
| — | ExploitDB, Metasploit | https://gitlab.com/exploit-database/exploitdb ; https://github.com/rapid7/metasploit-framework (LICENSE files) | — | Not re-checked in review | Data facts only (IDs, module names), so the code licence does not reach us. Recorded for completeness. |

---

## Studied but deliberately not copied

Recording this protects us. These are all AGPL, GPL, or source-available — copying from any of
them would change our project's licence.

| Project | Licence | What we learned | Why not copied |
|---|---|---|---|
| PatrOwl | AGPL-3.0 | Manager + engine microservice architecture, Celery task model | AGPL would force source disclosure for any network user |
| Vulnerability-Lookup | AGPL-3.0 | Multi-source feeder client design; their ATT&CK classifier is our baseline | AGPL, and it is our differentiator — see D-001 |
| cve-search | AGPL-3.0 | Local CVE mirror architecture | AGPL |
| Faraday | GPL-3.0 | Finding normalization and dedup approach | GPL |
| reNgine | GPL-3.0 | Configurable scan "engine" concept | GPL |
| OpenCVE | BSL 1.1 | Multi-source aggregation and filtering model | Source-available, not open source |
| Sn1per CE | Source-available | Breadth of tool orchestration | Restrictive licence; exploit modes out of scope |
| MulVAL | GPL-2.0-or-later | Datalog attack graph semantics, interaction rule design | Heavy XSB/Prolog dependency; GPL-2.0-or-later copyleft would compromise licence boundary (Hard Rule 3); we reimplement interaction rules natively in Python/NetworkX |
