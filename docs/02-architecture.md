# Architecture

> **Placeholder — this is the next document to write.**

## Decided

- **Knowledge substrate:** BRON, ingested as data (see `DECISIONS.md` D-002)
- **Parser interface:** modelled on DefectDojo's parser pattern
- **Path engine:** ours, deterministic, per-edge provenance
- **Model:** Foundation-Sec-8B-Reasoning, served locally

## Open

1. **Graph store** — Neo4j vs NetworkX + Postgres
2. **Path engine** — Datalog rules vs custom Python rules-as-data
3. **Vector store** — pgvector vs Qdrant
4. **Model serving** — Ollama for dev, vLLM for demo
5. **Multi-tenancy** — row-level vs schema-per-tenant
6. **ERS weights** — hand-tuned and documented, or learned from KEV membership

Log each of these in `DECISIONS.md` as they're settled.

## The pipeline

```
Scan facts (hosts, services, versions, CVEs, reachability)
        |  deterministic
Asset-vulnerability graph
        |  deterministic — named rules
Candidate attack paths (every edge traceable)
        |  scored — EPSS x exploit availability x privilege delta
Ranked paths
        |  LLM here, and only here
Narration, ATT&CK annotation, remediation by chokepoint
```

The LLM narrates. It never creates edges.
