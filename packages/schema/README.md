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
   canonical CVE identifiers (`CVE-YYYY-NNNN+`), deduplicated, rejecting non-CVE identifiers.
7. **Asset identifiers are standardized.** Scanner-derived asset identifiers use canonical
   prefix notation (`host:<ip>`, `host:<fqdn>`, or `host:mac:<mac>`).

Breaking any of these breaks the project's core claim.

## Layout

Models are split by concern under `models/`: `provenance`, `engagement`, `observation`,
`asset`, `finding`, `scoring`, `graph`, `citation`. Import from `packages.schema` directly.

---

## Finding Ingestion Contract (Track 1 Normalization -> Layer 2 Enrichment)

Track 1 (`services/normalize`) converts raw scanner `Observation` records into de-duplicated `Finding` records. Layer 2 (`services/enrichment`) consumes these findings for intelligence fusion, metric extraction, and Exposure Risk Scoring (ERS).

### 1. `asset_id` Standard Identifier Format
To enable cross-scanner correlation (e.g. Nmap port facts + Nuclei vulnerability candidates), `asset_id` strings follow deterministic canonical formatting:
- **IP Assets:** `host:<canonical_ip>` (e.g., `host:172.20.1.10`, `host:[2001:db8::10]`).
- **Hostname Assets:** `host:<canonical_fqdn>` (lowercased, trailing dot removed, e.g., `host:dvwa.lab.local`).
- **MAC Fallback:** `host:mac:<lowercase_mac>` (e.g., `host:mac:aa:bb:cc:dd:ee:ff`).
- **Synthetic Test Fixtures:** Prefixes `asset-*` or `ast-*` remain supported for isolated unit tests.

### 2. `cve_ids` Formatting & Normalization
- **Canonical Syntax:** Strictly regex-validated against `^CVE-\d{4}-\d{4,7}$`.
- **Automatic Uppercasing:** Lowercase scanner outputs (e.g. `cve-2021-44228`) are automatically normalized to uppercase `CVE-2021-44228`.
- **Deduplication:** Multiple scanner matches on the same CVE are deduplicated while preserving discovery order.
- **Handling of Non-CVE IDs:** Non-CVE identifiers (e.g., `GHSA-xxxx`, `CWE-502`, template IDs) must **never** be placed into `cve_ids`. They belong in `Observation.attributes` or finding descriptive metadata.

### 3. `observation_ids` Provenance Requirement
- Every `Finding` must link to at least one valid, stored `observation_id` belonging to the same `engagement_id`.
- Enforced at model construction by Pydantic (`Finding._must_trace_to_observations`) and at the API router boundary by `_verify_findings_provenance()` in `apps/api/routers/findings.py`. Untraceable findings are rejected with HTTP 422.

