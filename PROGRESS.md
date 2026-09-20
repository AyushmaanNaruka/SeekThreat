# Progress tracker

The single place to check what is done, what is not, and what is blocked.

**Last verified:** 2026-09-20, against `main` @ `f145d76`.
**Verified how:** by reading the code, not by trusting earlier status docs. Every claim below
either names a file or is marked unverified.

---

## How to use this file

- Update it in the same PR as the work. A tracker updated a week later is fiction.
- Only tick a box when the thing is **verified working**, not when the code was written.
  Use ⚠️ for "written but unverified" and say what verification is missing.
- Do not put percentages or completion scores in here. `CLAUDE.md` forbids rendering numbers
  we have not measured, and "73% done" is exactly that. Counts of real items are fine.
- If something turns out to be wrong here, fix it rather than working around it.

**Legend:** ✅ done and verified · ⚠️ done but unverified · 🔨 in progress · ⬜ not started ·
🚫 blocked · ⏸️ deliberately deferred (with the reason)

---

## Where we are right now

Layer 1's **engine** is complete and well covered: schema, the authorization gate, two scanner
adapters, both parsers, Postgres persistence, migrations, Celery dispatch, the ten-host lab, and
the ground-truth file. 191 tests pass. CI is green.

Layer 1 as a **milestone** is not complete. Four things are missing, and they are not small:

1. **No read path.** Observations are written to the database and cannot be read back over
   HTTP. There is no endpoint that returns them.
2. **No web interface.** `apps/web` makes zero API calls. Layer 1 is defined as "scanners, one
   web interface, no command line" — the interface part is unbuilt.
3. **`evals/` is two README files.** The architecture doc calls the September eval harness
   un-cuttable and says missing numbers in month six are fatal.
4. **The observation fixture set is too thin to stand on.** 5 facts from 2 of 10 lab hosts, and
   no vulnerability observations at all. Layers 2–4 are supposed to be testable offline against
   this.

Layers 2, 3 and 4 have not started. `services/normalize` does not exist; `services/enrichment`
and `services/graph` are empty `__init__.py` files; `services/assistant` is a docstring.

---

## Timeline: the two planning documents disagree

This needs resolving, because two files give different answers and both are treated as
authoritative elsewhere.

| | `docs/00-scope.md` | `docs/02-architecture.md` |
|---|---|---|
| Span | 6 months, Aug–Jan | 5 months, Sep–Jan |
| Protected month | **October** (graph) | **November** (graph) |
| Current month is | Month 2 — normalization, enrichment, eval harness | September — Layer 1, lab, eval skeleton |

`docs/02-architecture.md` says explicitly: *"Five months, September to January. The original
plan assumed six; the old integration month is merged into January."* That reads as the later,
superseding plan, and it is the one this tracker follows.

**But `docs/00-scope.md` is still a placeholder stub** — its first line is *"**Placeholder.**
Paste the full scope and research document here"* — while `CLAUDE.md`, `HOW-THIS-REPO-WORKS.md`
and the architecture doc all point to it as the authoritative scope. So the document every other
document defers to has never been written.

- ⬜ **Resolve the timeline conflict** and record it in `DECISIONS.md`
- ⬜ **Replace `docs/00-scope.md`** with the real scope document, or delete the references that
  treat the stub as authoritative

Working assumption until then: architecture doc wins, November is protected.

---

## Layer 1 — Collection

> *"Scanners, one web interface, no command line."* — `HOW-THIS-REPO-WORKS.md`
> **Done when:** a scan produces stored, provenanced observations. — `docs/02-architecture.md`

### Schema — `packages/schema/` ✅

- ✅ `Observation`, `RawArtifact`, `ScanResult` — `models/observation.py`, all frozen, content-addressed ids
- ✅ `Engagement`, `Authorization`, `ScanRequest`, `target_matches` — `models/engagement.py`
- ✅ `Asset`, `Service` — `models/asset.py`
- ✅ `Finding`, `EnrichedFinding` — `models/finding.py` (modelled; nothing produces them yet, correct for now)
- ✅ `Rule`, `PathEdge`, `AttackPath`, `Chokepoint` — `models/graph.py` (modelled; Layer 3 populates)
- ✅ `Provenance`, `Attributed[T]`, `Source`, `Confidence` — `models/provenance.py`
- ✅ `ExposureRiskScore`, `ScoreComponent` — `models/scoring.py`, self-explaining per D-008
- ✅ `Citation` — `models/citation.py`
- ✅ Pydantic v2 throughout (D-009); 21 names re-exported from `packages/schema/__init__.py`

### Authorization ✅

- ✅ CIDR + wildcard matching, never resolves DNS — `packages/schema/models/engagement.py`
- ✅ API-layer choke point — `apps/api/core/authorization.py`, called before the scan row is created
- ✅ Gate precedes tool invocation — `services/scanners/base.py`
- ✅ Reflection-based coverage test — `tests/architecture/test_authorization_gate.py`, with an anti-vacuity guard
- ⬜ Discovery is scoped to the `services.scanners` package; an adapter defined elsewhere would not be found. Low risk, worth knowing.

### Scanners — `services/scanners/` ✅

- ✅ `base.py` — `ScannerAdapter`, `AuthorizationError`, `ScannerUnavailableError`, content-addressed artifacts
- ✅ `nmap_adapter.py` + `nmap_xml.py` — emits `host_up`, `port_open`, `service_version` per D-012
- ✅ `nuclei_adapter.py` + `nuclei_json.py` — emits `vuln_candidate` per D-015
- ✅ Fixed argv, no caller-supplied flags (D-017)
- ⏸️ No further adapters — #3 on the cut list. `httpx` is the one candidate **if** Layer 2 proves it needs cross-scanner dedup material. Decide then, not speculatively.

### Persistence — `apps/api/db/` ✅

- ✅ Four tables: `raw_artifacts`, `observations`, `engagements`, `scans`
- ✅ Idempotent upserts, dialect-aware — `repositories.py`
- ✅ Migrations `0001`, `0002`, `0003`
- ✅ Alembic-vs-`create_all` index parity test — `tests/unit/test_alembic.py`

### API — `apps/api/` 🔨

Seven endpoints exist. The write path is complete; **the read path is not**.

- ✅ `POST /engagements`, `GET /engagements`, `GET /engagements/{id}`
- ✅ `POST /scans`, `GET /scans?engagement_id=`, `GET /scans/{id}`
- ✅ `GET /health`
- 🚫 **No endpoint returns observations.** `GET /scans/{id}` returns `observation_count` only. `ObservationRepository.get_by_engagement`, `.count_by_engagement` and `RawArtifactRepository.get` exist and are called by no router. **This is the single largest functional hole in Layer 1** — facts can be written but not read.
- 🚫 **No CORS middleware.** `apps/api/main.py` adds none, so any browser dashboard is blocked before the request lands. Three-line fix; blocks all UI work.
- ⬜ No pagination, filtering or sorting on any list endpoint
- ⬜ `GET /scans` requires `engagement_id` — there is no "list all scans"
- ⬜ No scan cancellation
- ⬜ `main.py` docstring still says "Scaffold only"

### Async execution ✅

- ✅ Celery + Redis (D-014) — `apps/api/worker.py`, `apps/api/tasks/scans.py`
- ✅ Permanent failures not retried; task re-raises so Celery state matches the DB row (D-019)
- ✅ `is_available()` checked before invoking a scanner

### Lab — `lab/` ✅

- ✅ 10 targets across 3 `internal: true` segments (D-016)
- ✅ `ground_truth.yaml` — 10 hosts, 10 expected CVEs, 3 multi-hop paths, 2 known false positives
- ✅ Consistency test against the compose file — `tests/unit/test_ground_truth.py`
- ✅ Worker can reach all three segments (D-020) — `infra/docker-compose.lab.yml`

### Web interface — `apps/web/` ⬜

**The remaining Layer 1 deliverable.** Owner: Dev C. Full brief in
[`docs/03-dashboard-spec.md`](docs/03-dashboard-spec.md).

- ⬜ Engagement create + list
- ⬜ Scan launch + status polling
- ⬜ Any real API call at all — currently zero across the whole app
- ⬜ Remove leftover mock content: a literal `CVE-2024-XXXX` on screen, invented IP `10.10.20.15` (the lab is `172.20.x.x`), a fictional terminal transcript, a "Live" feed over frozen rows
- ⬜ ~14 Tailwind-style class names used but never defined in `globals.css` — they silently do nothing
- ⬜ `app/page.module.css` is dead `create-next-app` leftover
- ✅ Fabricated *metrics* were removed in PR #2 and a guard comment added to `ThreatStats.tsx`

### Layer 1 "done when" 🚫

- 🚫 **Not demonstrated.** No end-to-end `POST /scans` → worker → stored observation run against a real lab target has been completed. Blocked on the `pgvector/pgvector:pg16` image pull (see Blockers).
- ⚠️ The pinned nuclei binary in `apps/api/Dockerfile` (v3.11.1, checksum-verified) has **never been built** — same blocker. The nuclei path has not run against the lab.

---

## Cross-cutting — the things that outlive any one layer

### Eval harness — `evals/` ⬜ 🚫

The largest gap against the project's own stated priorities.

> *"The eval harness is built in September. Bad numbers in month two are fine. Missing numbers
> in month six are fatal."* — `docs/02-architecture.md`, which also lists it under **never cut**.

Current state: `evals/README.md` and `evals/golden/README.md`. Zero code, zero data.

- ⬜ Harness / runner — no `.py` file exists anywhere under `evals/`
- ⬜ Track A: accuracy, precision, recall, F1 vs `ground_truth.yaml`; macro-F1; MAE; BLEU/ROUGE
- ⬜ Track B: faithfulness, context precision/recall, answer relevancy, citation accuracy, attack path validity, enrichment coverage vs NVD-only, dedup precision/recall
- ⬜ Golden dataset, ~500 items across 6 categories — none of the six specified `.jsonl` files exist
- ⬜ Nothing in CI invokes anything under `evals/`
- ✅ The denominator exists and is schema-tested — `lab/ground_truth.yaml`

Note the sequencing trap: Track A needs only Layer 1 output plus ground truth, so **the
detection-accuracy half can be built now**. It does not need Layers 2–4. Co-owned by all three
of us per `HOW-THIS-REPO-WORKS.md`.

### Test fixtures — `tests/fixtures/observations/` ⚠️

Exists, is real, is drift-guarded — and is far too thin for the job the architecture doc gives
it (*"Layers 2 through 4 become testable offline"*).

- ✅ `lab_baseline.json` — a serialized `ScanResult`, re-parse-verified against the live adapter
- ⬜ Covers **2 of 10** lab hosts, both DMZ. The internal and data tiers have no snapshotted observations at all
- ⬜ **Zero nuclei / `vuln_candidate` observations** — nothing in the fixture set represents a vulnerability
- ⬜ None of the 3 declared multi-hop paths are represented

**This blocks Layer 3.** The rules engine in November needs multi-segment, multi-host facts with
vulnerabilities to run against offline. Extending the fixture set is a Layer 1 task on Layer 3's
critical path — the highest-leverage single item on this list.

### Tests

- ✅ 191 passing — 11 architecture, 180 unit
- ✅ Import firewall, with a planted-violation self-test — `tests/architecture/test_import_firewall.py`
- ✅ Authorization coverage by reflection — `tests/architecture/test_authorization_gate.py`
- ⏸️ Purity / determinism test — November by design, lands with the graph builder
- ⏸️ No-narration-upstream test — November by design
- ⬜ **`tests/integration/` does not exist.** The architecture doc specifies it: "pipeline over fixture observations, no scanning". Currently blocked in practice by the thin fixture set above.

### CI — `.github/workflows/ci.yml`

- ✅ ruff, ruff format, mypy, pytest, architecture guards — runs on PRs to `main`
- ✅ Third-party register check
- ⬜ **`mypy packages services` excludes `apps/`** — every router, task, DB and core module ships without strict type checking, despite `CLAUDE.md` requiring type hints on all Python and `pyproject.toml` setting `strict = true`
- ⬜ Nothing runs `evals/`
- ⬜ Runtime deprecation warnings: Node 20 → 24, `ubuntu-latest` → Ubuntu 26

### Observability

- ✅ Structured audit events with actor, target, engagement, authorization reference — `apps/api/core/audit.py`
- ⬜ **Audit records are in-memory only.** A module-level list, never persisted to any table, lost on restart, and not shared between the API and worker processes
- ⬜ That list is unbounded — it grows for the life of the process
- ⬜ No endpoint exposes the audit trail

### Infrastructure

- ✅ Compose profiles: `core`, `model`, `viz` — nothing starts without one
- ✅ `migrate` one-shot service; api/worker gate on it (D-018)
- ✅ `.dockerignore`; `.env` optional on a fresh clone
- ✅ Worker↔lab network override (D-020)
- ⚠️ **The `core` profile has never been run to completion** — blocked on the image pull below

### Documentation

- ✅ `docs/02-architecture.md` — the binding spec, current as of D-020
- ✅ `DECISIONS.md` — D-001 … D-020
- ✅ `THIRD_PARTY.md` — nmap, nuclei registered
- ✅ `docs/03-dashboard-spec.md` — brief for the dashboard work
- ⬜ `docs/00-scope.md` is a placeholder stub that four other documents treat as authoritative
- ⬜ `docs/mayank_implementation/level_1_status.md` is partly stale — several items marked pending have since shipped

---

## Layer 2 — Understanding ⬜

**October.** Owner: Dev B. Needs its own brainstorm before any code.

- ⬜ `services/normalize/` — does not exist. Referenced by the module map, the repository layout, a scanner README, a code comment, and already forbidden by the import firewall
- ⬜ `identity.py` — identity resolution. **Listed as genuinely open** in the architecture doc's "Still open" section; decide and log before building
- ⬜ `dedup.py` — cross-scanner deduplication
- ⬜ `services/enrichment/` — empty `__init__.py`. Needs `sources/`, `fusion.py`, `ers.py`
- ⬜ Multi-source fusion with fallback chains and per-field provenance
- ⬜ ERS scoring — additive with stated weights, never EPSS × CVSS (D-008)
- ⬜ No `findings` table or migration exists yet
- ⬜ **Done when:** coverage measured against an NVD-only baseline — which requires the eval harness first

**Known constraint:** nmap and nuclei barely overlap (`service_version` vs `vuln_candidate`), so
cross-scanner dedup has thin material. If Layer 2 proves it needs real overlap, add exactly one
lightweight scanner (`httpx`, MIT). Decide when proven.

---

## Layer 3 — Reasoning ⬜

**November. Protected.** The differentiating work.

- ⬜ `services/graph/` — empty `__init__.py`. Needs `builder.py`, `engine.py`, `rules/*.yaml`, `chokepoints.py`, `sinks/`
- ⬜ In-memory NetworkX build from facts (D-003)
- ⬜ Rules as data in YAML (D-004); every edge carries `rule_name` + `evidence`
- ⬜ Path enumeration — **deterministic, never LLM-generated** (hard rule 1)
- ⬜ Chokepoint analysis; remediation simulation (**never cut** — the best demo moment)
- ⬜ Neo4j read-only projection — `viz` profile already in compose, nothing writes to it
- ⬜ Purity and no-narration-upstream architecture tests land here
- 🚫 **Blocked on fixtures** — needs multi-segment observations with vulnerabilities to develop against

---

## Layer 4 — Conversation ⬜

**December.** Owner: Dev C.

- ⬜ `services/assistant/` — docstring only. Needs `client.py`, `retrieval.py`, `narration.py`, `citations.py`
- ⬜ `ModelClient` interface over Ollama (D-006)
- ⬜ pgvector retrieval (D-005) — the extension is in the Postgres image, unused
- ⬜ Narration of proven paths only, strictly downstream of the firewall
- ⬜ Citations resolving to real observation/finding ids
- ⬜ No assistant or query endpoint exists
- ⬜ **Done when:** faithfulness measured on the golden set — needs the eval harness and a golden set

---

## Blockers

### 1. Docker Hub image pulls fail on this machine 🚫

Repeated mid-transfer `EOF` from `production.cloudfront.docker.com`. Reproduces on unrelated
images (`redis:7-alpine`), so it is environmental, not project configuration. Blocks:

- The `core` profile coming up (`pgvector/pgvector:pg16` specifically)
- Verifying the nuclei Dockerfile install
- Demonstrating Layer 1's "done when" end to end
- Bringing up 8 of the 10 lab hosts

Cached and usable: `vulnerables/web-dvwa`, `bkimminich/juice-shop`, `instrumentisto/nmap`,
`redis:7-alpine`, `postgres:16-alpine`.

### 2. No CORS 🚫

Blocks all dashboard work. Three-line fix in `apps/api/main.py`.

### 3. No observations endpoint 🚫

Blocks any UI that shows scan results, and blocks Track A of the eval harness from reading
results over HTTP (it can read the DB directly instead).

---

## Ownership

Per `HOW-THIS-REPO-WORKS.md`. Ownership means accountable, not sole author.

| Area | Owner |
|---|---|
| Platform & orchestration — scanners, queue, auth, infra, lab | A |
| Data & intelligence — normalize, enrichment, graph, paths, ML | B |
| AI & interface — retrieval, model serving, assistant, UI | C |
| **Eval harness** | **All three** |

**Recorded staffing risk** (architecture doc): B owns both differentiators across two
consecutive months and is the critical path for October and November. The doc's own advice is to
either move the graph engine to whoever is strongest or pair explicitly on the rules engine —
and to *"decide it in September, not in November."* September is now.

- ⬜ Make that call and log it in `DECISIONS.md`

---

## Next actions, in order

1. **CORS middleware** — unblocks Dev C entirely. Smallest high-value change on the list. *(A)*
2. **`GET /observations`** — closes the read path; repository methods already exist. Agree the shape with Dev C first, since he consumes it. *(A)*
3. **Dashboard phase 1** — engagements + scans. **Completes Layer 1.** *(C)*
4. **Extend `tests/fixtures/observations/`** — all 10 hosts, all 3 segments, including nuclei `vuln_candidate` facts. Unblocks `tests/integration/` and Layer 3 development. *(A/B)*
5. **Eval harness, Track A** — buildable now against Layer 1 output + ground truth; does not need Layers 2–4. *(All)*
6. **Layer 2 brainstorm** — identity resolution strategy is explicitly open; decide before coding. *(B)*
7. **Resolve the timeline conflict and the `00-scope.md` stub.** *(All)*
8. **Decide the staffing question** the architecture doc raises. *(All)*

---

## Smaller items worth not losing

- ⬜ `apps/api/worker.py` has an uncommitted local fix (`autodiscover_tasks` → explicit import) — needs verifying and committing
- ⬜ `mypy` scope excludes `apps/`
- ⬜ Audit log unbounded and non-durable
- ⬜ `main.py` docstring says "Scaffold only"
- ⬜ CI runner deprecations (Node 20→24, ubuntu-latest→26)
- ⬜ Stale remote branches: `mayank-development`, `fix/layer-1-review-followups`
- ⬜ Dead file `apps/web/app/page.module.css`
- ⬜ Undefined CSS classes across `apps/web/components/`
