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
| BRON (MIT ALFA group) | *TO VERIFY* | Data | CVE→CWE→CAPEC→ATT&CK graph substrate | | |
| DefectDojo | *TO VERIFY — believed BSD-3* | Study / Vendored | Scanner output parser patterns | | |
| Nmap | NPSL | Service | Invoked as subprocess, XML output parsed. Source never vendored | | |
| NetworkX | BSD-3-Clause | Service | In-memory attack graph substrate (D-003) | Ayushmaan | 2026-09-05 |
| PyYAML | MIT | Service | Rules-as-data loading for the path engine (D-004) | Ayushmaan | 2026-09-05 |
| Nuclei | MIT (ProjectDiscovery) | Service | Invoked as subprocess, JSONL output parsed. Source never vendored | Ayushmaan | 2026-09-20 |
| Nuclei Templates | MIT (ProjectDiscovery) | Vendored | Official vulnerability template archive pinned in container image | Mayank | 2026-09-25 |
| Greenbone / OpenVAS | GPL | Service | Run as container, GMP API via python-gvm | | |
| Foundation-Sec-8B-Reasoning | Open weights | Service | Local model serving | | |
| CISA Vulnrichment | CC0-1.0 (cisagov/vulnrichment LICENSE) | Data | Per-CVE files fetched for CVEs we have seen: SSVC decision points, CWE, CVSS fallback | Claude agent via GitHub licence API — human to confirm | 2026-10-11 |
| CISA KEV catalog | CC0-1.0 (cisagov/kev-data LICENSE; no use of CISA logo / DHS seal or implied endorsement) | Data | Full catalog JSON mirrored daily; confirmed-exploitation flag, date added, ransomware use | Claude agent read LICENSE — human to confirm | 2026-10-11 |
| FIRST EPSS | No licence stated; FIRST EPSS FAQ: "Attribution is requested when EPSS data is used in publications or products." | Data | Daily bulk CSV (`epss.empiricalsecurity.com/epss_scores-current.csv.gz`, per first.org/epss/data). Attribute FIRST EPSS SIG / Empirical Security in the report and UI | Claude agent read first.org FAQ + data page — human to confirm | 2026-10-11 |
| CVE.org (CVE Services) | CVE Program Terms of Use — *TO VERIFY* (cve.org/Legal/TermsOfUse is a JS page; not read this session) | Data | Per-CVE CVE_RECORD from `cveawg.mitre.org/api/cve/{id}` for CVEs we have seen | | |
| NVD API 2.0 | US Government work — *TO VERIFY* NVD terms of use and required "not endorsed by the NVD" notice (developer pages not retrievable this session) | Data | Per-CVE records from `services.nvd.nist.gov/rest/json/cves/2.0?cveId=`; 5 req/30 s without API key (per NVD docs, not re-verified) | | |
| ENISA EUVD | *TO VERIFY* (EUVD terms of use not found; earlier "Open Data / EUPL" entry was unverified) | Data | Per-CVE lookup via `euvdservices.enisa.europa.eu/api/search?text={id}`; base score/vector/version, description | | |
| ExploitDB (OffSec) | GPL-2.0-or-later (repository, GitLab licence API) | Data | Data only: derived CVE→EDB-ID facts from `files_exploits.csv` `id`/`codes` columns; no files or code copied (Hard Rule 4) | Claude agent via GitLab licence API — human to confirm | 2026-10-11 |
| Rapid7 Metasploit Framework | BSD-3-Clause (LICENSE, Rapid7) | Data | `modules_metadata_base.json`: CVE → exploit module `fullname` only, `type == "exploit"`; no module code (Hard Rule 4) | Claude agent read LICENSE — human to confirm | 2026-10-11 |

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
| MulVAL | *TO VERIFY* | Datalog attack graph semantics, interaction rule design | Heavy XSB/Prolog dependency; we reimplement the semantics |
