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
| Greenbone / OpenVAS | GPL | Service | Run as container, GMP API via python-gvm | | |
| Foundation-Sec-8B-Reasoning | Open weights | Service | Local model serving | | |
| CISA Vulnrichment | CC0-1.0 (Public Domain, cisagov/vulnrichment LICENSE) | Data | Per-CVE files fetched for CVEs we have seen: SSVC decision points, CWE, CVSS fallback | Mayank Narang | 2026-10-11 |
| CISA KEV catalog | CC0-1.0 (Public Domain, cisagov/kev-data LICENSE; no CISA/DHS seal use or implied endorsement) | Data | Full catalog JSON mirrored daily; confirmed-exploitation flag, date added, ransomware use | Mayank Narang | 2026-10-11 |
| FIRST EPSS | Free use; attribution requested (FIRST EPSS FAQ). Cite Jacobs et al. 2021 — see note [E] | Data | Daily bulk CSV (`epss_scores-current.csv.gz`). Attribution to FIRST EPSS SIG / Empirical Security in documentation and UI | Mayank Narang (no terms page cited; see note [E]) | 2026-10-11 |
| CVE.org (CVE Services) | CVE Program Terms of Use — https://www.cve.org/Legal/TermsOfUse (see note [C]) | Data | Per-CVE CVE_RECORD from `cveawg.mitre.org/api/cve/{id}`; perpetual royalty-free non-exclusive licence to reproduce and create derivative works; MITRE copyright/disclaimer retained | Mayank Narang (no terms page cited; see note [C]) | 2026-10-11 |
| NVD API 2.0 | Public Domain (US Government work / NIST); NVD Terms of Use — https://nvd.nist.gov/developers/terms-of-use (see note [N]) | Data | Per-CVE records from `services.nvd.nist.gov/rest/json/cves/2.0?cveId=`; 5 req/30 s without key, 50 req/30 s with key; requested notice displayed in UI and docs: "This product uses the NVD API but is not endorsed or certified by the NVD"; must not imply NVD endorsement | Mayank Narang (no terms page cited; see note [N]) | 2026-10-11 |
| ENISA EUVD | ENISA Legal Notice: reuse permitted with source acknowledgement; EUVD-specific licence unconfirmed — *TO VERIFY* (see note [U]) | Data | Per-CVE lookup via `euvdservices.enisa.europa.eu/api/search?text={id}`; base score/vector/version, description; credit to European Union Agency for Cybersecurity (ENISA) | *TO VERIFY* (earlier "CC BY 4.0" claim unsupported; see note [U]) | 2026-10-12 |
| ExploitDB (OffSec) | GPL-2.0-or-later (repository); Data only | Data | Data only: derived CVE→EDB-ID facts from `files_exploits.csv` `id`/`codes` columns; no files or code copied (Hard Rule 4) | Mayank Narang | 2026-10-11 |
| Rapid7 Metasploit Framework | BSD-3-Clause (Rapid7) | Data | `modules_metadata_base.json`: CVE → exploit module `fullname` only, `type == "exploit"`; no module code (Hard Rule 4) | Mayank Narang | 2026-10-11 |

### Data-feed licence sources (added in PR #19 review, 2026-10-12)

The data-feed rows above marked "Verified by Mayank Narang, 2026-10-11" did not cite the terms pages they were checked against. This table records the source for each claim and what was confirmed when. "Confirmed" means the reviewer read the page on that date. "Not retrieved" means the page could not be read by an automated fetch (it renders client-side, or it returned an error), so the claim still rests on the original unrecorded check.

| Note | Feed | Source URL | Accessed | Status | Notes |
|---|---|---|---|---|---|
| [U] | ENISA EUVD | https://www.enisa.europa.eu/about-enisa/legal-notice | 2026-10-12 | Confirmed (general notice only) | The legal notice authorises reproduction of ENISA material provided the source is acknowledged, unless stated otherwise. It names no specific open licence and does not mention CC BY 4.0 or Decision 2011/833/EU. Whether this notice governs EUVD API data, or EUVD has its own terms, is unconfirmed. Status stays *TO VERIFY*. |
| [N] | NVD API 2.0 | https://nvd.nist.gov/developers/terms-of-use | 2026-10-12 | Not retrieved (client-rendered page) | The "uses the NVD API but is not endorsed or certified by the NVD" text is a **requested** notice, not a licence condition. Products must not imply NVD endorsement. Re-read the page and record the exact wording. |
| [C] | CVE.org | https://www.cve.org/Legal/TermsOfUse | 2026-10-12 | Not retrieved (client-rendered page) | The licence-grant wording in the row above is from the original check and has not been re-confirmed. |
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
