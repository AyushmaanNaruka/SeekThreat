# Scope

> **Placeholder.** Paste the full scope and research document here, or drop it in as
> `docs/00-scope.md` replacing this file. This stub exists so links don't break.

## Summary

Four layers. Collection (scanners behind one UI), Understanding (normalize, dedup, enrich from
many sources), Reasoning (graph, deterministic attack paths, chokepoints), Conversation (RAG
assistant with citations).

## Landing zone

Everything at **L2** maturity by month five, with two L3 stretches. Target scale: one domain
plus subdomains, or a 50–200 host range per engagement.

## Out of scope, deliberately

Endpoint agents. Cloud posture management. Source code scanning. Active Directory attack paths.
Autonomous exploitation. Distributed scanner fleets.

A well-drawn boundary reads as judgment. An unbounded one reads as naivety.

## Timeline

| Month | Focus | Done when |
|---|---|---|
| 1 · Aug | Foundations + test lab | A scan from the UI produces normalized, enriched findings |
| 2 · Sep | Normalization, enrichment, **eval harness** | Metrics report generates automatically |
| 3 · Oct | Graph and attack paths | Every path edge clicks through to its evidence |
| 4 · Nov | The assistant | Faithfulness above 0.80 on the golden set |
| 5 · Dec | Integration, reporting, hardening | Feature freeze |
| 6 · Jan | Demo, docs, write-up | Rehearsed demo plus recorded fallback |

**October is protected.** The graph and path engine is the differentiating work.

**The eval harness is built in September, not January.** Bad numbers in month two are fine.
Missing numbers in month six are fatal.
