# services/graph

**The heart of the project.** Deterministic attack path construction.

## The one rule

**The LLM never creates graph edges.**

Paths are built by the rules engine. Every edge carries the scan fact and the named rule that
produced it. The model narrates paths that already exist — it never infers them.

The easy version prompts an LLM with a vulnerability list and asks how an attacker might chain
them. What comes back is fluent, confident and unverifiable, and the first person who asks
"how do you know that path is real?" ends the conversation.

## Pipeline

```
Scan facts (hosts, services, versions, CVEs, reachability)
        |  deterministic
Asset-vulnerability graph
        |  deterministic — named rules
Candidate paths (every edge traceable)
        |  ranked only — cost/risk heuristic (D-039, proposed); never adds or prunes paths
Ranked paths
        |  LLM here, and only here
Narration
```

## How it is built (D-046)

```python
from services.graph import analyze, simulate_remediation

result = analyze(engagement_id=..., observations=..., findings=..., topology=..., enriched=...)
```

- **Inputs:** stored observations, findings, optional enriched findings (for fused CWE
  ids), and the engagement's declared `NetworkTopology` (zones, attacker-entry zone,
  crown-jewel zones, multi-homed hosts, allowed flows). The lab's topology is
  `lab/topology.yaml`.
- **Nodes** are attacker states: `attacker:<zone>`, `access:<ip>:<port>/<proto>`,
  `exec:<machine>`, `read:<machine>`, `creds:<machine>`. Goals are every `exec` node plus
  access to any service in a crown-jewel zone.
- **Edges** come only from the seven rules in `rules/core.yaml`, one matcher each in
  `builder.py`. Each edge has a content-derived `edge_id`, the rule name, the evidence ids
  (`obs:`, `finding:`, `topology:`), a confidence, and the findings it depends on.
- **Capabilities** (`rules/capabilities.yaml`) come from scanner tags and CWE ids only.
  Findings no rule classifies are returned in `unclassified_findings` with the reason.
- **Assumptions** (`local_access_exposes_credentials`, `credential_reuse_remote_login`)
  are LOW confidence and say "Assumed, not observed" in their description. A path's
  confidence is its weakest edge.
- **Enumeration** is iterative deepening: every simple path up to `max_depth`, shortest
  first, ties broken by edge ids, capped at `max_paths`, with `truncated` set when a
  limit is hit.
- **Ranking (D-047)** is ordinal: weakest-step confidence, then highest stored ERS on the
  path, then fewer steps, then edge ids. Each path has `rank` and a `rank_explanation`;
  there is no composite `score`. Ranking only reorders the enumerated set.
- **Chokepoints** are ranked by goals cut, then paths broken. **Remediation
  simulation** rebuilds from the same facts without the fixed findings and reports what
  disappeared.
- **Purity:** `tests/architecture/test_graph_purity.py` keeps this package free of
  network, database, clock, randomness and model imports. Byte-identical output for the
  same facts is asserted in `tests/unit/test_graph_engine.py`.

## Neo4j projection (D-003, `viz` profile)

Neo4j is a **read-only, disposable view** of a result the engine already proved, for
Neo4j Browser. The engine never reads it back; drop it at any time and re-project.

- `sinks/neo4j_projection.py` is pure: `projection_statements(result)` returns ordered,
  parameterized Cypher (UNWIND batches). It imports no driver and passes the purity test.
- `apps/api/graph_projection.py` owns the `neo4j` driver and runs the statements in one
  write transaction: delete this engagement's old projection, then write the new one.
  Other engagements are never touched (every element carries `engagement_id`).

```bash
docker compose -f infra/docker-compose.yml --profile viz up -d neo4j   # Browser: http://localhost:7474
# NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD from .env (see .env.example)
curl -X POST http://localhost:8000/engagements/eng-lab-demo/attack-graph/project
python -m apps.api.cli.project_graph --engagement-id eng-lab-demo       # same thing from a shell
```

Both take `max_depth` / `max_paths` like `GET .../attack-graph`, are audit-logged
(`attack_graph.projected` / `attack_graph.project_rejected`), and answer **503** when
Neo4j is not configured or not running (start the `viz` profile), **409** without a
declared topology, **502** if Neo4j rejects the write.

**Model**

| Element | Meaning | Key properties |
|---|---|---|
| `(:GraphProjection)` | one per engagement | `topology_id`, `rules_digest`, `truncated`, counts, `projected_at` |
| `(:AttackState:<Kind>)` | one per graph node; `<Kind>` is `Attacker`, `NetworkAccess`, `CodeExecution`, `FileRead`, `Credentials`; goals also get `:Goal` | `node_id`, `label`, `machine`, `zones`, `goal`, `path_ids` |
| `-[:STEP]->` | one per edge | `edge_id`, `rule_name`, `confidence`, `evidence`, `description`, `finding_ids`, `path_ids`, `path_count` |
| `(:AttackPath)` | one per enumerated path, `-[:STARTS_AT]->` entry, `-[:ENDS_AT]->` goal | `path_id`, `ordinal`, `length`, `confidence`, `edge_ids` (in order), `finding_ids` |

**Demo queries** (Neo4j Browser; set `:param eid => 'eng-lab-demo'` first)

```cypher
// The whole attack graph for one engagement
MATCH (a:AttackState {engagement_id: $eid})-[r:STEP]->(b) RETURN a, r, b;

// The shortest proven path into the data tier, with the rule and evidence per step
MATCH (p:AttackPath {engagement_id: $eid})-[:ENDS_AT]->(g:Goal)
WHERE any(z IN g.zones WHERE z = 'data') WITH p ORDER BY p.ordinal LIMIT 1
MATCH (a)-[r:STEP {engagement_id: $eid}]->(b) WHERE p.path_id IN r.path_ids
RETURN a, r, b;

// The steps shared by the most enumerated paths
MATCH ()-[r:STEP {engagement_id: $eid}]->()
RETURN r.rule_name, r.finding_ids, r.path_count, r.evidence ORDER BY r.path_count DESC LIMIT 10;
```

(`data` is the crown-jewel zone in `lab/topology.yaml`. Chokepoint ranking stays in the
API response, which remains the source of truth; `path_count` is not a ranking.)

## Path Scoring (DECISIONS.md D-039 — proposed, not settled)

D-029's multiplicative heuristic (`EPSS × exploit_availability × privilege_delta`) has known problems: it multiplies a probability by an ordinal, double-counts exploit evidence, and zeroes a path when no public exploit is indexed. **D-039 proposes** a replacement. It is pending sign-off by the graph owner, and D-029 stays Active until then.

**Scope (rule 1 of this README, Hard Rule 1).** Paths are enumerated deterministically and exhaustively by the rules engine first. Cost and risk are used **only to rank** that enumerated set, never to create, infer or prune paths. Ties are broken by path length ascending, then by the lexicographic sequence of edge IDs.

Two heuristic tiers:
1. **Tier 1 — edge cost:**  
   $\text{Cost}(e) = -\ln(\max(\text{EPSS}_e, 0.001)) + \text{Barrier}(\text{privilege\_delta}_e)$, summed along the path.  
   Summing $-\ln \text{EPSS}$ is the same as multiplying EPSS values (log space), so this is still multiplicative in EPSS. It treats EPSS, a CVE-scoped 30-day in-the-wild exploitation likelihood, as if it were a per-hop success probability, and it assumes hops are independent. It is a ranking heuristic, not a likelihood. The barrier values (provisional, unjustified: 0.0 / 1.5 / 3.0), the 0.001 floor (which collapses all low-EPSS edges to one cost) and the cost of edges with no CVE or no EPSS (undefined) are open questions in D-039.
2. **Tier 2 — path risk:**  
   $R(\text{path}) = 0.50 \cdot \max_{e \in \text{path}}(\text{ERS}_e) + 0.30 \cdot C_{\text{target}} + 0.20 \cdot \overline{\text{ERS}}_{\text{path}}$, read from the stored `EnrichedFinding.ers.value` (D-028).  
   $\max(\text{ERS})$ is the most-exposed hop, not the weakest link. Tier 2 can disagree with Tier 1: a path with one high-ERS hop and one low-EPSS hop ranks high here and costly there. The weights 0.50 / 0.30 / 0.20 have no rationale or sensitivity analysis yet (open, as D-027 required for ERS).

## Knowledge substrate

BRON (MIT ALFA group) provides the static CVE -> CWE -> CAPEC -> ATT&CK graph. Ingested as
data, not vendored. See `DECISIONS.md` D-002.

Known coverage gap: roughly 62% CVE->CWE, 35% CWE->CAPEC, 16% CAPEC->ATT&CK before completion.
Our ML gap-filler classifier targets that gap and is measured against the published baseline.

## Chokepoints

Which single fix breaks the most paths. Fix that first, regardless of severity score.

This also powers remediation simulation — mark a vuln fixed, recompute the path set, show what
disappears. Best demo moment we have.

## Rules

1. Every `PathEdge` needs `rule_name` and `evidence`. No exceptions.
2. Rules are data, not code, where possible — so we can cite and extend them.
3. Test path construction thoroughly. Silent wrongness here is the worst failure mode.
