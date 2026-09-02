# packages/schema

Shared data models. Everything depends on this — change carefully and communicate it.

## Invariants

1. **Every enriched field carries `Provenance`** — source and confidence. No unattributed data.
2. **Every score explains itself.** `ExposureRiskScore.explain()` is not optional.
3. **Every `PathEdge` carries `rule_name` and `evidence`.** This is what makes attack paths
   defensible.

Breaking any of these breaks the project's core claim.
