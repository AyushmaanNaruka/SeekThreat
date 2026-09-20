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
| Greenbone / OpenVAS | GPL | Service | Run as container, GMP API via python-gvm | | |
| Foundation-Sec-8B-Reasoning | Open weights | Service | Local model serving | | |

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
