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

Five months, September to January (see `DECISIONS.md` D-022 — the original plan assumed six,
starting in August; the old integration month is merged into January).

| Month | Focus | Done when |
|---|---|---|
| 1 · Sep | Phase 0 groundwork, Layer 1, lab, eval skeleton | A scan produces stored, provenanced observations |
| 2 · Oct | Layer 2 — normalize, dedup, enrichment fusion | Coverage measured against an NVD-only baseline |
| 3 · **Nov** | **Layer 3 — graph, rules, paths, ERS, chokepoints** | Every edge clicks through to its evidence |
| 4 · Dec | Layer 4 — retrieval, narration, assistant, UI | Faithfulness measured on the golden set |
| 5 · Jan | Integration, demo, write-up | Rehearsed demo plus a recorded fallback |

**November is protected.** The graph and path engine is the differentiating work.

**The eval harness is built in September, not January.** Bad numbers in month two are fine.
Missing numbers in month six are fatal.

Full detail — the cut list, staffing risk, and everything else behind this table — lives in
`docs/02-architecture.md`'s "Sequence" section, which is authoritative for the schedule.
