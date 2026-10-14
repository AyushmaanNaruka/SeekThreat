# packages/schema

Shared data models. Everything depends on this — change carefully and communicate it.

## Invariants

These are enforced by the models themselves, not by convention.

1. **Every enriched field carries `Provenance`.** `Attributed[T]` pairs a value with
   its provenance, so an unattributed value cannot be constructed.
2. **Every score explains itself.** `ExposureRiskScore` validates that its value is
   the weighted sum of its components, and every component needs an explanation.
   Components combine additively — never multiply EPSS by CVSS.
3. **Every `PathEdge` carries `rule_name` and non-empty `evidence`.** An edge without
   provenance is rejected at construction.
4. **Observations are immutable.** `Observation` and `RawArtifact` are frozen. Everything
   downstream is a derived view.
5. **All datetimes are timezone-aware.** Naive datetimes are rejected.
6. **Findings strictly trace to observations.** A `Finding` must reference at least one
   observation (`observation_ids`), and its `cve_ids` must be formatted as uppercase
   canonical CVE identifiers (`CVE-YYYY-NNNN+`, ASCII digits), deduplicated, rejecting
   non-CVE identifiers.

Breaking any of these breaks the project's core claim.

`asset_id` format is a contract, not (yet) an invariant: see "`asset_id` Standard
Identifier Format" below.

## Layout

Models are split by concern under `models/`: `provenance`, `engagement`, `observation`,
`asset`, `finding`, `scoring`, `graph`, `citation`. Import from `packages.schema` directly.

---

## Finding Ingestion Contract (Track 1 Normalization -> Layer 2 Enrichment)

Track 1 (`services/normalize`) converts raw scanner `Observation` records into de-duplicated `Finding` records. Layer 2 (`services/enrichment`) consumes these findings for intelligence fusion, metric extraction, and Exposure Risk Scoring (ERS).

### 1. `asset_id` Standard Identifier Format — contract (not yet enforced)

**Status: contract, not yet enforced; enforced when Track 1 lands.** `Finding.asset_id`
is a plain `str` today and no validator checks its shape. A strict validator now would
reject the synthetic fixtures and constrain a normalizer that has not been written.
When Track 1 (`services/normalize`) lands, it produces `asset_id`s in exactly this form
and the validator is added with it. Until then, treat the format below as what
producers must emit, not as something consumers can rely on having been checked.

To enable cross-scanner correlation (e.g. Nmap port facts + Nuclei vulnerability
candidates), `asset_id` is `host:` + the host part of the nmap `HOST_UP` observation
subject (`services/scanners/nmap_xml.py`), chosen by IPv4 > IPv6 > MAC > FQDN:
- **IPv4:** `host:<dotted-quad>` as Python's `ipaddress` prints it (e.g. `host:172.20.1.10`).
- **IPv6:** `host:<compressed>`, **unbracketed**, lowercase hex, as
  `ipaddress.IPv6Address(...).compressed` prints it (e.g. `host:2001:db8::10`). This is
  the nmap `HOST_UP` subject. Brackets appear only in *port* subjects
  (`[2001:db8::10]:443/tcp`), where they separate the address from the port; they are
  not part of the `asset_id`.
- **MAC fallback:** `host:mac:<mac>`, **lowercase**, colon-separated (e.g.
  `host:mac:aa:bb:cc:dd:ee:ff`), matching the nmap `mac:<mac>` subject.
- **Hostname:** `host:<fqdn>`, **lowercase**, trailing dot removed (e.g.
  `host:dvwa.lab.local`).
- **Synthetic test fixtures:** prefixes `asset-*` or `ast-*` remain allowed for isolated
  unit tests.

### 2. `cve_ids` Formatting & Normalization
- **Canonical Syntax:** Strictly validated with `CVE_ID_PATTERN.fullmatch` against `CVE-[0-9]{4}-[0-9]{4,7}` (`re.ASCII`; other Unicode digits are rejected).
- **Automatic Uppercasing:** Lowercase scanner outputs (e.g. `cve-2021-44228`) are automatically normalized to uppercase `CVE-2021-44228`.
- **Deduplication:** Multiple scanner matches on the same CVE are deduplicated while preserving discovery order.
- **Handling of Non-CVE IDs:** Non-CVE identifiers (e.g., `GHSA-xxxx`, `CWE-502`, template IDs) must **never** be placed into `cve_ids`. They belong in `Observation.attributes` or finding descriptive metadata.

### 3. `observation_ids` Provenance Requirement
- Every `Finding` must link to at least one valid, stored `observation_id` belonging to the same `engagement_id`.
- Enforced at model construction by Pydantic (`Finding._must_trace_to_observations`) and at the API router boundary by `_verify_findings_provenance()` in `apps/api/routers/findings.py`. Untraceable findings are rejected with HTTP 422.

