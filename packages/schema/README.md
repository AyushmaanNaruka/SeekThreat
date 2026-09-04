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

Breaking any of these breaks the project's core claim.

## Layout

Models are split by concern under `models/`: `provenance`, `engagement`, `observation`,
`asset`, `finding`, `scoring`, `graph`, `citation`. Import from `packages.schema` directly.
