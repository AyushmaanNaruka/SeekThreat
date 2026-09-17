# Decision log

Every decision that changes the plan gets logged here. Same day, while the reasoning is fresh.

**Log a decision when it:**
- diverges from `docs/00-scope.md`
- adds or drops a dependency, tool, or scanner
- changes scope — in or out
- picks between two real options (database, library, approach)
- reverses something we decided earlier

**Don't log:** routine implementation choices, variable names, styling.

**Why this matters:** in month six we write the final report and defend this in a viva. "Why did you choose Neo4j?" and "why did the scope change in October?" are questions with real answers, and this is where we keep them. Reconstructing it from memory in January does not work.

---

## Format

Copy this block, fill it in, add to the top of the log.

```markdown
### D-XXX — <short title>
**Date:** YYYY-MM-DD
**Decided by:** <name(s)>
**Type:** Scope change | Divergence | Tool choice | Reversal | Addition
**Status:** Active | Superseded by D-XXX | Reverted

**Decision**
What we decided, in one or two sentences.

**Why**
What made this the right call. Include what we considered and rejected.

**Impact on plan**
What in the original scope this changes. Timeline effect, if any.

**Cost if we're wrong**
Honest estimate. How hard is this to undo?
```

---

## Log

Newest first.

---

### D-013 — Stdlib `xml.etree.ElementTree` for nmap XML, not `defusedxml`
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
`services/scanners/nmap_xml.py` parses nmap output with the standard library's
`xml.etree.ElementTree`, guarded by a size cap and a DOCTYPE check, rather than adding the
`defusedxml` dependency.

**Why**
On Python 3.11, `xml.etree.ElementTree` does not resolve external general entities, so XXE is
not reachable. The residual concern — the billion-laughs entity-expansion attack — requires a
DOCTYPE with an internal subset, which nmap's own XML writer never emits (nmap emits a bare
`<!DOCTYPE nmaprun>`). A DOCTYPE guard that rejects an internal subset or a `SYSTEM`/`PUBLIC`
external identifier, while explicitly allowing nmap's own bare doctype, closes that gap in five
lines with no dependency. `defusedxml` would defend against input nmap structurally cannot
produce, while the real risk — attacker-controlled banner text flowing into logs, Neo4j and an
LLM prompt — is a sanitization problem, not a parser-choice one, and is handled separately by
stripping control characters and capping attribute length in the parser itself.

**Impact on plan**
None. No new dependency; `THIRD_PARTY.md` is unaffected.

**Cost if we're wrong**
Low. Swapping the parse call for `defusedxml.ElementTree.fromstring` is a one-line change behind
the same guard functions if a future scanner's output turns out to make DTD-based attacks
reachable.

---

### D-012 — nmap parser taxonomy: open ports only, method="table" never yields SERVICE_VERSION
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Divergence

**Decision**
`services/scanners/nmap_xml.py` emits only `HOST_UP`, `PORT_OPEN` and `SERVICE_VERSION`
observations from an `nmap -sV` run. Non-open ports (closed, filtered) are not emitted as
observations in this slice. A `<service>` element with `method="table"` (nmap's guess from the
port-number table, not a fingerprint match) never produces a `SERVICE_VERSION`; its name and
method are recorded as attributes on `PORT_OPEN` instead.

**Why**
Non-open ports are real facts, but nothing in the pipeline consumes them until the graph
engine's reachability rules exist (November), and the `RawArtifact` is retained verbatim, so
re-parsing recovers them later without rescanning — deferring costs nothing. `method="table"` is
zero new evidence over the port number itself (it just means "port 80 is `http` per
`/etc/services`"); emitting it as `SERVICE_VERSION` would let enrichment match CVEs against a
guess nmap never actually verified.

**Impact on plan**
None to timeline. Narrows `services/enrichment`'s input to only nmap's genuinely fingerprinted
services, which should reduce false-positive CVE matches once fusion logic lands in October.

**Cost if we're wrong**
Low. Both are additive: a future `REACHABILITY`-kind emission for non-open ports, or a lower-
confidence `SERVICE_VERSION` for `method="table"`, can be added without touching what already
ships. Any attribute-schema change to the emitted kinds does change every downstream
`observation_id` (see D-011), so the more consequential cost is in that decision, not this one.

---

### D-011 — `ScannerAdapter.scan()` returns a `ScanResult`, not a bare observation list
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Divergence

**Decision**
`services/scanners/base.py`'s `ScannerAdapter.scan()` now returns a new frozen `ScanResult`
(`packages/schema/models/observation.py`) — `{artifact: RawArtifact, observations:
tuple[Observation, ...]}` — instead of `list[Observation]`. The base class constructs the
`RawArtifact` itself, from a new `content_type` class attribute and an overridable
`_captured_at()` hook, and passes the finished artifact into `_parse(artifact, request)`.
`artifact_id` and `observation_id` are both content-derived (sha256), not random or clock-based.

**Why**
`Observation.artifact_id` is required and points at a `RawArtifact` that the architecture
retains verbatim for provenance — but the prior `scan() -> list[Observation]` signature gave
that artifact nowhere to go; it was constructed nowhere and returned nowhere. Provenance was a
dangling pointer from the moment `Observation` was written. Fixing this in the base class, not
each adapter, mirrors why the authorization gate lives there: every adapter gets identical,
correct handling for free. Taking the wall clock exactly once in `scan()` (via `_captured_at`)
and threading it into `_parse` as data is what lets `_parse` be a pure, replayable function —
the property `tests/fixtures/observations/` depends on.

**Impact on plan**
Touches every future scanner adapter (nuclei and beyond): each sets a `content_type` class
attribute, may override `_captured_at()`, and implements `_parse(artifact, request) ->
tuple[Observation, ...]` instead of the old `_parse(raw, request) -> list[Observation]`. No
architecture test broke — `tests/architecture/test_authorization_gate.py` only exercises the
raise-before-`_execute` path.

**Cost if we're wrong**
Low. `ScanResult` is an additive wrapper; reverting to a bare list (with the artifact problem
unsolved) is a small, mechanical change if a future design supersedes it.

---

### D-010 — Keep str+Enum for schema enums; suppress ruff UP042 project-wide
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
`Source`, `Confidence`, and `ObservationKind` in `packages/schema/models/` stay declared as
`class X(str, Enum)` rather than converting to `enum.StrEnum`. Ruff's `UP042` rule, which
suggests the conversion, is suppressed project-wide in `pyproject.toml`.

**Why**
`StrEnum` can subtly change `__str__` and serialization behavior compared to the `(str, Enum)`
mixin, and these three enums sit at the schema package's JSON/Pydantic-v2 serialization
boundary — exactly the kind of change `packages/schema/README.md` asks us to be careful with.
Converting them as an incidental side effect of onboarding CI (rather than a deliberate,
tested decision) would risk changing serialization behavior nobody asked to change.

**Impact on plan**
None. A lint rule is suppressed; no runtime behavior changes.

**Cost if we're wrong**
Very low. If we later want `StrEnum`, it is a small, deliberate, testable conversion — nothing
about this decision blocks it, it only prevents it from happening accidentally.

---

### D-009 — Pydantic v2 replaces dataclasses in packages/schema
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Divergence
**Status:** Active

**Decision**
Convert `packages/schema` from plain `@dataclass` to Pydantic v2 `BaseModel`.

**Why**
`CLAUDE.md` already requires "Pydantic models for anything crossing a boundary," and the
committed code does not do this — the divergence exists today and this resolves it in favour
of the rule. Three concrete gains: validation at every boundary, deterministic serialization
that the graph purity test depends on, and FastAPI request/response models for free.

**Impact on plan**
Phase 0 work, before any feature code depends on the current shapes. Doing it later means
touching every module that imports schema.

**Cost if we're wrong**
Very low. Pydantic v2 models are close enough to dataclasses that reverting is mechanical, and
the conversion happens while almost nothing imports them.

---

### D-008 — ERS weights hand-tuned and documented, not learned
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Exposure Risk Score component weights are chosen by hand, documented with reasoning, and
published with a sensitivity analysis. KEV membership is used to *validate* the resulting
ranking, not as a training target.

**Why**
Learning weights requires labelled data telling us which exposures actually mattered, and we
do not have it. A learned number we cannot justify is worse in a viva than a stated weighting
we can defend line by line. Sensitivity analysis shows which weights actually change the
ranking, which is a more honest result than a fitted model on 200 hosts.

Reinforces the standing constraint from `services/enrichment/README.md`: never multiply EPSS
by CVSS. Components combine additively with stated weights, each rendering its own explanation
through `ScoreComponent`.

**Impact on plan**
Removes a modelling task from the enrichment layer. The ML effort concentrates on the gap-
filler classifier instead, where a published BRON baseline exists to beat.

**Cost if we're wrong**
Low. If hand-tuned weights rank badly and we later obtain labels, the `ScoreComponent`
structure already separates weights from components, so fitting them is a contained change.

---

### D-007 — Row-level engagement scoping, not schema-per-tenant
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Every row carries an `engagement_id`. No schema-per-tenant, no row-level security policies.

**Why**
Deliberate YAGNI. This project has no tenants and will not acquire any before January.
Schema-per-tenant buys isolation we do not need and costs migration complexity in every month
we do have.

**Impact on plan**
None. Simplifies the data layer.

**Cost if we're wrong**
Low within this project's life. If real multi-tenancy is ever needed, `engagement_id` is
already the discriminator a stronger isolation model would key on.

---

### D-006 — Ollama for model serving, behind a ModelClient interface
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Serve Foundation-Sec-8B-Reasoning through Ollama in every environment. Access it only through
a `ModelClient` interface in `services/assistant`.

**Why**
The architecture doc previously assumed "Ollama for dev, vLLM for demo," but vLLM assumes
server-class hardware we do not have — development and the demo both happen on 16 GB laptops.
Running one serving path everywhere also removes a class of demo-day surprise.

The interface means a future vLLM or hosted endpoint is a swap, not a rewrite.

**Impact on plan**
Removes vLLM from the stack. Model runs quantized, in the `model` compose profile, never
alongside the lab.

**Cost if we're wrong**
Low. The interface is the insurance. If Ollama throughput proves inadequate for the demo,
swapping the implementation is a contained change.

---

### D-005 — pgvector, not Qdrant
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Vector storage and retrieval for the assistant use pgvector inside our existing Postgres.

**Why**
Postgres is already in the stack. Qdrant is a second service, a second backup story, and
another ~300 MB on a memory budget that is already oversubscribed. At our corpus size —
findings and observations from a few hundred hosts — pgvector's performance is not a
constraint, and keeping retrieval next to the facts makes citation joins trivial.

**Impact on plan**
One fewer service in `infra/docker-compose.yml`.

**Cost if we're wrong**
Low. Retrieval sits behind an interface in `services/assistant/retrieval.py`; the corpus is
small enough to re-index into a different store in an afternoon.

---

### D-004 — Python rules-as-data, not Datalog
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Attack path rules are declared as YAML in `services/graph/rules/` and evaluated by a small
deterministic Python engine. No Datalog, no Prolog, no XSB.

**Why**
MulVAL's Datalog semantics are worth studying and we will reimplement the ideas, but adopting
Datalog itself means a second language, an XSB dependency, and debugging that is genuinely
hard when a path comes out wrong under time pressure. With one strong developer and two still
building Python fluency, that cost lands in the wrong place.

Rules-as-data still satisfies the standing requirement in `services/graph/README.md` that
rules be data rather than code, so they can be cited in the report and extended without
touching the engine. Each rule carries a `citation` field.

**Impact on plan**
No timeline change. Concentrates November's difficulty in one engine module that a single
developer can own.

**Cost if we're wrong**
Medium. If YAML rules prove too weak to express the semantics we need, we would rewrite the
evaluator — but the rules themselves, being data, largely survive that rewrite.

---

### D-003 — Postgres facts plus in-memory NetworkX; Neo4j as a read-only projection
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Postgres holds an append-only store of immutable, provenance-tagged observations. The attack
graph is rebuilt in memory with NetworkX from those facts on demand and is never a source of
truth. Neo4j is committed as a **read-only projection** for visualization, rebuilt from facts,
disposable at any time, landing with the graph builder in November behind a `viz` profile.

**Why**
Four reasons, in order of weight.

Determinism becomes a structural property rather than a promise: if the graph is a pure
function of facts, the same observations produce byte-identical paths, and that is a test we
run in CI. A mutable graph database accumulates state and drifts, so we would be asserting
determinism on a substrate that does not enforce it.

Remediation simulation — mark a vulnerability fixed, recompute, show which paths disappear —
is our best demo moment, and it is natural over an in-memory rebuild and awkward over a
persistent store. Chokepoint analysis has the same shape. Both are brute-force loops that are
free when a rebuild costs milliseconds.

The rules engine must be Python regardless, because every edge carries `rule_name` and
`evidence` attached at creation. A graph database would only store and re-query what Python
already computed, making it a persistence choice rather than a reasoning one.

Scale does not justify it. At 50–200 hosts the graph is a few thousand nodes, and the BRON
traversal (CVE→CWE→CAPEC→ATT&CK) is fixed-depth — three joins, not graph traversal. Neo4j's
advantages do not activate at this size, but its ~1.5–2.5 GB does.

We considered making Neo4j the graph of record and rejected it: path rules would become
Cypher, which is code rather than data, weakening the claim that our rules are citable.

**Impact on plan**
Neo4j moves from Month 1 infrastructure to a November deliverable alongside the graph builder,
and is second on the cut list. Frees memory during development and removes a second query
language from the two months where the team is least experienced.

**Cost if we're wrong**
Low to medium. If the in-memory graph outgrows a laptop — which would require a scale far
beyond the scoped 50–200 hosts — the graph builder writes through a `GraphSink` interface, so
a persistent backend is an added implementation rather than a rewrite.

---

### D-002 — Adopt BRON as the knowledge graph substrate
**Date:** 2026-08-05
**Decided by:** Full team
**Type:** Divergence
**Status:** Active

**Decision**
Use MIT ALFA group's BRON as our static CVE→CWE→CAPEC→ATT&CK graph rather than building the mapping pipeline ourselves. Ingest its output as data; do not vendor its code.

**Why**
The original scope had us constructing this mapping in month three. BRON already links ATT&CK, CAPEC, CWE, CVE, Engage, D3FEND, CAR and ATLAS with bidirectional edges. Published work using it also documents baseline coverage figures — 62% CVE→CWE, 35% CWE→CAPEC, 16% CAPEC→ATT&CK before completion, 72/85/66 after. That gives our ML gap-filler classifier a measurable baseline to beat instead of an unanchored number.

**Impact on plan**
Frees roughly three weeks in month three. Reallocated to remediation simulation (see D-003 when logged). Our ML classifier is now framed as an improvement over a published baseline rather than a standalone component.

**Cost if we're wrong**
Low. If BRON's data proves unusable we fall back to building the mapping from raw MITRE sources, losing the three weeks we saved. Licence must be verified before ingestion.

---

### D-001 — Build our own enrichment fusion instead of using Vulnerability-Lookup
**Date:** 2026-08-05
**Decided by:** Full team
**Type:** Scope decision
**Status:** Active

**Decision**
Run CIRCL's Vulnerability-Lookup as a comparator and baseline only. Our multi-source fusion logic — provenance tagging, confidence scoring, fallback chains, Exposure Risk Score — stays entirely ours.

**Why**
Vulnerability-Lookup does much of what our Layer 2 does, including a RoBERTa ATT&CK technique classifier close to our planned gap-filler. Adopting it would save weeks and simultaneously remove both of our differentiators. The honest answer to "what did you build?" would become "a UI and some scanner adapters."

It is also AGPL-3.0, so copying any of its code would make our whole project AGPL — closing off a closed deployment or any commercial path later.

**Impact on plan**
No change to scope. Confirms the fusion engine as core original work. Their classifier becomes a published baseline we measure against.

**Cost if we're wrong**
Low. If our fusion underperforms we can still fall back to running theirs as a service, which costs no licence contamination.

---

*Add new entries above this line.*
