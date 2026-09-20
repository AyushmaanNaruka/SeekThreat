# Architecture

How SeekThreat is built, and why. Decisions logged in `DECISIONS.md` D-003 through D-022.

Read `docs/00-scope.md` for what we are building. This document is how.

---

## The one-paragraph version

An append-only store of immutable, provenance-tagged scan facts, with everything downstream
derived from it by pure functions. Findings, enrichment, the asset graph, attack paths and
scores are all recomputable views — never sources of truth. The attack graph is built in
memory from facts on demand, and paths are constructed by named rules declared as data. The
language model sits strictly downstream of the finished path, narrating it. It cannot reach
the code that builds edges, and a test enforces that.

---

## Design constraints

These shaped every decision below.

| Constraint | Consequence |
|---|---|
| 16 GB laptops with a consumer GPU | Nothing runs all at once. Compose profiles are mandatory |
| Three developers, one strong and two building fluency | Fewest moving parts. One language. Difficulty concentrated in one owned module |
| Five months, September to January | November is protected. A cut list decided in advance |
| Every claim must be defensible in a viva | Determinism and provenance enforced by tests, not by convention |

### The memory budget

Estimates, not measurements. On a 16 GB machine with roughly 6 GB taken by OS, editor and
browser, about 10 GB remains.

| Component | Estimated RAM |
|---|---|
| Postgres 16-alpine | 0.4 GB |
| Redis 7-alpine | 0.05 GB |
| FastAPI + Celery worker | 0.6 GB |
| Next.js dev server | 1.0 GB |
| Lab, 8-12 containers | 3.0 GB |
| Neo4j 5-community, tuned | 1.5 GB |
| Foundation-Sec-8B at 4-bit | 5.5 GB, GPU VRAM where it fits |

Every combination of all of these exceeds the budget. Hence profiles.

---

## The pipeline

```
Engagement + Authorization          <- the gate, checked once, centrally
        |
Scanner adapters ------------------> RawArtifact   (tool output, verbatim, retained)
        |  parse
        v
   Observation      <- APPEND-ONLY, IMMUTABLE, provenance-tagged
        |              "nmap saw apache 2.4.49 on 172.20.1.10:80 at T"
        |  normalize + dedup + identity resolution
        v
    Finding         <- canonical, cross-scanner merged
        |  multi-source fusion, fallback chain
        v
 EnrichedFinding    <- every field carries Provenance
        |  deterministic build (pure function)
        v
   AssetGraph       <- in-memory NetworkX, rebuilt from facts on demand
        |  named YAML rules fire on fact patterns
        v
   AttackPath[]     <- every edge carries rule_name + evidence
        |  ERS scoring, chokepoint analysis
        v
  RankedPath[] --------------------> Neo4j projection (read-only, disposable)
        |
        |  ===== FIREWALL ===== the model enters only here, read-only
        v
  Narration + citations
```

The model narrates. It never creates edges.

---

## Why an append-only fact store

`Observation` is immutable. Everything below it is a derived view. This buys four things.

**Determinism is testable.** The same observations produce byte-identical paths. That is an
assertion in CI, not a claim in a report.

**Re-enrichment without rescanning.** Improve fusion logic in November, re-run it against
September's observations, measure the difference. Impossible if enrichment mutates in place.

**CI runs the whole pipeline without scanning.** Snapshot observations as fixtures in
`tests/fixtures/observations/` and Layers 2 through 4 become testable offline, on a laptop, in
seconds. Given that scanning needs the lab up and roughly 3 GB of containers, this is the
difference between tests that get run and tests that do not.

**Provenance is structural.** Every derived value traces to an immutable observation carrying
a source and a timestamp. It stops being a convention someone has to remember.

The cost is more tables and the discipline of never mutating an observation. Storage is
irrelevant at our scale.

---

## Module map

Dependencies point downward. Nothing imports back up.

| Module | Owns | May import |
|---|---|---|
| `packages/schema` | Every type crossing a boundary | nothing internal |
| `apps/api/core/authorization` | The single scan gate | schema |
| `services/scanners` | Tool invocation to `Observation`. No interpretation | schema, authorization |
| `services/normalize` | Identity resolution, cross-scanner dedup | schema |
| `services/enrichment` | Multi-source fusion, fallback chains, provenance | schema |
| `services/graph` | Graph build, rules, paths, ERS, chokepoints | schema |
| `services/assistant` | Retrieval, narration, citations | schema **only** |
| `apps/api` | HTTP, Celery dispatch, structured logging | all of the above |

`services/normalize` is new. Deduplication previously had no home: it is not a scanner's job,
and it must happen before enrichment so we enrich each real finding once.

`services/assistant` holds both RAG retrieval and path narration. They share a model client
and the same read-only constraint, so they share a module and a single import ban.

---

## Repository layout

```
packages/schema/          Pydantic models, split by concern
  models/                 observation.py, finding.py, graph.py, engagement.py
services/
  scanners/               base.py, nmap_adapter.py, nuclei_adapter.py
  normalize/              identity.py, dedup.py
  enrichment/             sources/, fusion.py, ers.py
  graph/                  builder.py, engine.py, rules/*.yaml, chokepoints.py, sinks/
  assistant/              client.py, retrieval.py, narration.py, citations.py
apps/api/
  routers/  core/  tasks/
apps/web/                 Next.js
tests/
  unit/  integration/  architecture/
  fixtures/observations/  snapshotted facts, so CI needs no lab
evals/  lab/  vendor/  infra/  docs/
```

---

## The two hard rules, as mechanisms

Documented policy is what a tired developer breaks in month five. Both rules are enforced by
tests that fail CI.

### The model firewall

`services/assistant` may import `packages.schema` and nothing else from this tree. It receives
`AttackPath` objects as data and returns text. It cannot construct an edge because it cannot
reach the code that constructs edges.

Three tests in `tests/architecture/`:

1. **Import ban.** Walks the AST of every file under `services/assistant/` and fails if any
   import resolves to `services.graph`, `services.enrichment` or `services.scanners`. A new
   file that violates it fails CI on the pull request that adds it.
2. **Purity** (lands with the graph builder in November). `build_graph(facts)` and
   `find_paths(graph, rules)` are called twice on a fixture and their serialized output must
   be byte-identical. This catches dict ordering, set iteration, timestamps leaking into
   edges, and any future model call sneaking in.
3. **No narration upstream** (lands with the graph builder in November). Every `AttackPath`
   returned by `services/graph` must have `narration is None`. Narration attaches strictly
   downstream.

### The authorization choke point

Every scan routes through one function. Two tests:

1. **Coverage.** Parametrized over every `ScannerAdapter` subclass found by reflection. Each
   must raise `AuthorizationError` for an unauthorized target. A new adapter is covered from
   the moment it exists, with nobody remembering to add a test.
2. **The gate precedes invocation.** Mock `_execute`, call `scan()` with an unauthorized
   target, assert `_execute` was never called. This proves the check happens before the tool
   runs rather than beside it.

**Fixed in Phase 0.** `services/scanners/base.py` previously implemented `permits()` as
`target in self.allowlist` — an exact string match. An allowlist entry of `172.20.0.0/16`
rejected a scan of `172.20.1.10` even though it fell inside that range. It failed closed,
which was the safe direction, but authorization did not work as intended. Phase 0 replaced
this with proper CIDR and wildcard-subdomain matching, verified in
`tests/unit/test_authorization_matching.py`.

---

## Data model

`packages/schema` becomes Pydantic v2 (D-009). Three reasons: validation at every boundary,
deterministic serialization that the purity test depends on, and FastAPI request and response
models for free.

| Type | Status | Purpose |
|---|---|---|
| `Observation` | New | The immutable fact. The keystone of the whole design |
| `RawArtifact` | New | Verbatim tool output, stored once, referenced by observations |
| `Engagement` | New | Owns targets and authorization; scopes every row downstream |
| `Authorization` | Moved | From `services/scanners/base.py` into schema. It crosses boundaries |
| `Service` | New | Replaces the untyped `Asset.services: list[dict]` |
| `Rule` | New | Rules are data. `name`, `description`, `preconditions`, `effect`, `citation` |
| `Chokepoint` | New | A finding, the paths it breaks, the ranked remediation |
| `Citation` | New | Assistant answers cite observations and findings by id |
| `EnrichedFinding` | Split | Separates what a scanner said from what we fused |

`Finding.enrichment` changes from `dict[str, Provenance]` to `dict[str, Attributed[T]]`. Today
the map holds provenance while the value lives elsewhere; pairing them makes an unattributed
value unrepresentable rather than merely discouraged.

### The nmap observation taxonomy

`services/scanners/nmap_xml.py` is the reference parser (D-011, D-012). `services/normalize`
and `services/graph` will both key off its output, so the shape is recorded here rather than
left implicit in the code.

Three `ObservationKind`s are emitted from an `-sV` run: `HOST_UP`, `PORT_OPEN`,
`SERVICE_VERSION`. Non-open ports and `method="table"` service guesses are deliberately not
emitted as evidence — see D-012 for why, and note that nothing is lost, since the `RawArtifact`
is retained verbatim and re-parsing recovers them later without rescanning.

`subject` format, which downstream identity resolution keys on:

| Kind | Subject | Example |
|---|---|---|
| `HOST_UP` | bare canonical address | `172.20.1.10`, `2001:db8::10`, `mac:aa:bb:cc:dd:ee:ff` |
| `PORT_OPEN`, `SERVICE_VERSION` | `<host>:<port>/<proto>` | `172.20.1.10:80/tcp` |

Canonical address selection prefers IPv4, then IPv6 (compressed form), then MAC — deterministic
regardless of XML document order. Hostnames never appear in `subject`: DNS is mutable and PTR
records are attacker-influenced, matching the stance `Authorization` matching already takes by
never resolving DNS. They are carried as `hostname`/`hostnames` attributes instead.

Both `artifact_id` and `observation_id` are content-derived (sha256 over their inputs), not
random or clock-based — replaying the same `RawArtifact` through the parser always yields the
same ids, which is what lets `tests/fixtures/observations/` stand in for a scan.

---

## Decisions

Full reasoning in `DECISIONS.md`.

| ID | Decision |
|---|---|
| D-003 | Postgres facts plus in-memory NetworkX. Neo4j as a read-only projection, landing with the graph builder |
| D-004 | Python rules-as-data in YAML, not Datalog |
| D-005 | pgvector, not Qdrant |
| D-006 | Ollama behind a `ModelClient` interface |
| D-007 | Row-level `engagement_id` scoping, not schema-per-tenant |
| D-008 | ERS weights hand-tuned and documented. KEV membership validates, it does not train |
| D-009 | Pydantic v2 replaces dataclasses in `packages/schema` |
| D-010 | Keep str+Enum for schema enums; suppress ruff UP042 project-wide |
| D-011 | `ScannerAdapter.scan()` returns a `ScanResult` (artifact + observations), not a bare list |
| D-012 | nmap parser taxonomy: open ports only; `method="table"` never yields `SERVICE_VERSION` |
| D-013 | Stdlib `xml.etree.ElementTree` for nmap XML, not `defusedxml` |

### Why the graph is not a database

The graph is small: 50 to 200 hosts, each with a handful to a few dozen findings. A few
thousand nodes. NetworkX traverses that in milliseconds.

The BRON traversal is fixed-depth: CVE to CWE to CAPEC to ATT&CK is three hops, known in
advance. That is three joins, not graph traversal.

The rules engine must be Python regardless, because every edge carries `rule_name` and
`evidence` attached at creation. A graph database would store and re-query what Python already
computed, making it a persistence choice rather than a reasoning one.

Most decisively, remediation simulation — mark a vulnerability fixed, recompute, show which
paths disappear — is natural over an in-memory rebuild and awkward over a persistent store.
Chokepoint analysis has the same shape: remove each finding in turn and recount. Both are
brute-force loops that are free when a rebuild costs milliseconds.

Neo4j remains committed as a **read-only projection** for visualization, rebuilt from facts
and disposable at any time. It lands with the graph builder in November, behind the `viz`
profile.

### The ERS constraint

`services/enrichment/README.md` forbids multiplying EPSS by CVSS, and FIRST is explicit about
why: the product is not probability times severity and means nothing. The ERS combines
components additively with stated weights, each rendering its own explanation through
`ScoreComponent`. This constraint is recorded here so it survives being forgotten.

---

## Runtime and profiles

`infra/docker-compose.yml` gains profiles. Nothing brings up everything.

| Profile | Contains | Used for |
|---|---|---|
| `core` | Postgres, Redis, a one-shot `migrate` service, API, worker | Day-to-day development |
| `lab` | The vulnerable target network | Collection work and ground-truth runs |
| `model` | Ollama | Enrichment derivation, narration, assistant |
| `viz` | Neo4j | Demo and graph inspection, from November |

The API and worker containers landed with Layer 1. Inside the compose network they reach
Postgres and Redis by service name (`postgres`, `redis`), not `localhost` — `environment:`
overrides on both services take precedence over `env_file:`, so the same `.env` still gives
`localhost` for native dev via the published ports. The `migrate` service runs
`alembic upgrade head` once (`restart: "no"`); API and worker wait on it via
`service_completed_successfully` so the schema exists before either starts, and so the two
never race to apply the same DDL.

The lab stays in `lab/docker-compose.yml`, on internal networks with no egress, as it is now.
`infra/docker-compose.lab.yml` is an optional override that attaches the worker to all three
lab networks (`lab_dmz`, `lab_internal`, `lab_data`, referenced as `external: true` — Docker
network names are `<project>_<name>`) at fixed IPs, one per segment, outside the target ranges
in `lab/ground_truth.yaml`. It is not merged into the base compose file: the lab's networks
must already exist or compose refuses to start, and plain `--profile core up` must keep working
with no lab running. Bring the lab up first, then:

```
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core up -d
```

This grants reachability only. The authorization gate still decides whether a scan is
permitted — an engagement's allowlist must cover the target regardless of what the worker can
physically reach (CLAUDE.md hard rule 2). Attaching an additional container to an `internal:
true` network does not weaken it: that flag means no route to the outside internet, not that no
other compose project may join, and every lab target keeps that flag on its own network
regardless of what else is attached.

---

## Testing

| Layer | What it covers |
|---|---|
| `tests/architecture/` | The firewall, authorization coverage, determinism |
| `tests/unit/` | Rules, fusion, scoring, dedup, parsers |
| `tests/integration/` | Pipeline over fixture observations, no scanning |
| `evals/` | Track A brief metrics and Track B system metrics |

`tests/fixtures/observations/` is what makes this work on a laptop. Snapshot real observations
once, and every layer above collection is testable without the lab running.

**No number in this project has been measured yet.** Everything in `evals/README.md` is a
target. Never render a metric we have not measured.

---

## Sequence

Five months, September to January. The original plan assumed six; the old integration month is
merged into January.

| Month | Focus | Done when |
|---|---|---|
| September | Phase 0 groundwork, Layer 1, lab, eval skeleton | A scan produces stored, provenanced observations |
| October | Layer 2 — normalize, dedup, enrichment fusion | Coverage measured against an NVD-only baseline |
| **November** | **Layer 3 — graph, rules, paths, ERS, chokepoints** | Every edge clicks through to its evidence |
| December | Layer 4 — retrieval, narration, assistant, UI | Faithfulness measured on the golden set |
| January | Integration, demo, write-up | Rehearsed demo plus a recorded fallback |

**November is protected.** The graph and path engine is the differentiating work.

**The eval harness is built in September.** Bad numbers in month two are fine. Missing numbers
in month six are fatal.

### The cut list

Decided now, while it is cheap. If we slip, drop in this order:

1. ML gap-filler classifier
2. Neo4j projection
3. Scanner adapters beyond nmap and nuclei
4. Lab configurations two and three

Never cut: the eval harness, `ground_truth.yaml`, the determinism tests, or remediation
simulation. The last is the best demo moment we have.

### Staffing risk

`HOW-THIS-REPO-WORKS.md` assigns normalization, enrichment, graph, paths and ML to developer
B — both differentiators, and the critical path for two consecutive months. Either B is the
strongest developer and becomes a single point of failure for October and November, or B is
not and the differentiators belong to someone still building fluency.

Move the graph engine to whoever is strongest and leave B enrichment alone, or pair explicitly
on the rules engine in November. Decide it in September, not in November.

---

## Still open

Genuinely undecided, to be logged in `DECISIONS.md` when settled.

1. Identity resolution strategy for assets that different scanners describe differently
2. Whether BRON is ingested whole or as a filtered subset, pending a size and licence check
3. Retrieval chunking strategy for the assistant
4. Report output format
