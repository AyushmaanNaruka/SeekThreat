# Progress tracker

The single place to check what is done, what is not, and what is blocked.

**Last verified:** 2026-09-20, against `main` @ `cc38571` plus the Layer 1 completion PR
(Celery fix, CORS, read path, full-lab fixtures, `tests/integration/`, mypy on `apps/`, timeline
fix — D-021/D-022).
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

Layer 1's **backend** is now complete: schema, the authorization gate, two scanner adapters, both
parsers, Postgres persistence, migrations, Celery dispatch (registration bug fixed, D-021), the
full read path (`GET /observations`, `GET /scans/{id}/observations`, both paginated), CORS
middleware, the ten-host lab, the ground-truth file, and an observation fixture set covering all
10 hosts across all 3 segments including nuclei `vuln_candidate` facts. `tests/integration/`
exists and proves the fixture-to-persistence-to-API round trip end to end. `mypy` runs on
`packages`, `services`, **and `apps/`** in CI, strict, clean. 219 tests pass. CI is green.

Two things remain before Layer 1 is complete as a **milestone**, and neither is backend work:

1. **No web interface.** `apps/web` makes zero API calls. Layer 1 is defined as "scanners, one
   web interface, no command line" — the interface part is unbuilt. Owned by Dev C; brief is
   [`docs/03-dashboard-spec.md`](docs/03-dashboard-spec.md).
2. **`evals/` is two README files.** The architecture doc calls the September eval harness
   un-cuttable and says missing numbers in month six are fatal. Not blocked on anything — Track A
   can be built now against Layer 1's output plus `ground_truth.yaml`. Not yet started.

Also still open: **8 of the 10 lab hosts have never been scanned for real** — the Docker Hub CDN
blocker (below) means their fixtures are synthetic (hand-authored, parser-verified, every fact
copied from `ground_truth.yaml`) rather than captured, and Layer 1's own "done when" — a real
end-to-end scan against the lab — has never been demonstrated for that reason.

Layers 2, 3 and 4 have not started. `services/normalize` does not exist; `services/enrichment`
and `services/graph` are empty `__init__.py` files; `services/assistant` is a docstring.

---

## Timeline: resolved — five months, November protected

`docs/00-scope.md` and `docs/02-architecture.md` used to disagree (6 months/October vs. 5
months/November). Resolved in `DECISIONS.md` D-022: `docs/00-scope.md`'s Timeline section was
rewritten to match `docs/02-architecture.md`'s "Sequence" section and now points to it as the
authoritative schedule instead of carrying its own copy. Five months, September–January,
**November protected** for the graph and attack-path engine.

**`docs/00-scope.md` is otherwise still a placeholder stub** — its intro still reads
*"**Placeholder.** Paste the full scope and research document here"* — while `CLAUDE.md` and
`HOW-THIS-REPO-WORKS.md` point to it as the authoritative scope for everything else (out-of-scope
list, layer summary, etc.). Only the Timeline section has been reconciled; the rest of the real
scope/research document still needs to replace the stub.

- ✅ **Timeline conflict resolved** — `DECISIONS.md` D-022
- ⬜ **Replace `docs/00-scope.md`** with the real scope document, or delete the references that
  treat the stub as authoritative

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

### API — `apps/api/` ✅

Nine endpoints exist. Both the write path and the read path are complete.

- ✅ `POST /engagements`, `GET /engagements`, `GET /engagements/{id}`
- ✅ `POST /scans`, `GET /scans?engagement_id=`, `GET /scans/{id}`
- ✅ `GET /observations?engagement_id=&kind=&limit=&offset=` — paginated, provenance included per row
- ✅ `GET /scans/{id}/observations?kind=&limit=&offset=` — paginated, scoped to one scan's artifact
- ✅ `GET /health`
- ✅ CORS middleware — `CORS_ORIGINS` env var, comma-separated (`Annotated[list[str], NoDecode]` — pydantic-settings 2.7.0 JSON-decodes plain `list[str]` fields before validators run otherwise)
- ⬜ No filtering or sorting beyond `kind` on any list endpoint
- ⬜ `GET /scans` requires `engagement_id` — there is no "list all scans"
- ⬜ No scan cancellation

### Async execution ✅

- ✅ Celery + Redis (D-014) — `apps/api/worker.py`, `apps/api/tasks/scans.py`
- ✅ Permanent failures not retried; task re-raises so Celery state matches the DB row (D-019)
- ✅ `is_available()` checked before invoking a scanner
- ✅ Task registration fixed (D-021) — `worker.py` explicitly imports the task module instead of `autodiscover_tasks(["apps.api.tasks"])`, which silently registered nothing. Invisible to every existing test (they import the task module directly); caught by a subprocess-based regression test, `tests/unit/test_worker_registration.py`

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

### Test fixtures — `tests/fixtures/observations/` ✅

Exists, is real, is drift-guarded, and now covers what the architecture doc asks for
(*"Layers 2 through 4 become testable offline"*).

- ✅ `lab_baseline.json` — a serialized `ScanResult` from a **real** capture, re-parse-verified against the live adapter (dvwa, juiceshop)
- ✅ `lab_dmz_extended.json`, `lab_internal.json`, `lab_data.json` — synthetic (hand-authored nmap XML run through the real `parse_nmap_xml`), one file per remaining segment. **Covers all 10 lab hosts.** Every host/port/service/version fact copied verbatim from `lab/ground_truth.yaml`
- ✅ `lab_extended_nuclei.json` — synthetic nuclei findings for the 5 HTTP-exposed hosts, run through the real `parse_nuclei_json`. First `vuln_candidate` observations in the fixture set
- ✅ Built and kept reproducible by `scripts/build_observation_fixtures.py` — mirrors `ScannerAdapter._artifact`'s content-addressing exactly; re-running it is a no-op diff
- ✅ Cross-consistency tests — `tests/unit/test_observation_fixtures.py` (full-host coverage, every synthetic CVE traceable to `ground_truth.yaml`)
- ⚠️ **8 of 10 hosts are still synthetic, not captured.** Real captures replace them as soon as the Docker Hub blocker (below) clears; `tests/fixtures/observations/README.md` tracks which file maps to which blocked image
- ⬜ None of the 3 declared multi-hop paths are represented as a connected fixture set yet (each file is one segment; nothing currently threads a path across all three)

### Tests

- ✅ 219 passing — 11 architecture, 203 unit, 5 integration
- ✅ Import firewall, with a planted-violation self-test — `tests/architecture/test_import_firewall.py`
- ✅ Authorization coverage by reflection — `tests/architecture/test_authorization_gate.py`
- ✅ **`tests/integration/test_fixture_pipeline_roundtrip.py`** — loads every fixture, persists via `save_scan_result`, reads back through both the repository layer and `GET /observations` / `GET /scans/{id}/observations`, and asserts provenance, artifact-scoping, idempotency, and gapless pagination all survive the round trip. No scanning, no lab, runs in ~1s
- ⏸️ Purity / determinism test — November by design, lands with the graph builder
- ⏸️ No-narration-upstream test — November by design

### CI — `.github/workflows/ci.yml`

- ✅ ruff, ruff format, mypy, pytest, architecture guards — runs on PRs to `main`
- ✅ Third-party register check
- ✅ **`mypy` now runs on `packages services apps`** — the 5 pre-existing `apps/` errors (two `Insert` union-type inferences, one untyped-decorator false positive on `@celery_app.task`, one untyped `JSONB()` call, one `NmapAdapter`/`NucleiAdapter` union inference) are fixed with explicit annotations and one targeted `# type: ignore[misc]` for celery's missing stubs — not scope suppressions
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

- ✅ `docs/02-architecture.md` — the binding spec, current as of D-022 (header bumped)
- ✅ `DECISIONS.md` — D-001 … D-022
- ✅ `THIRD_PARTY.md` — nmap, nuclei registered
- ✅ `docs/03-dashboard-spec.md` — brief for the dashboard work
- ✅ `docs/00-scope.md`'s Timeline section reconciled with `docs/02-architecture.md` (D-022)
- ⬜ `docs/00-scope.md` is otherwise still a placeholder stub for the rest of the real scope/research document (out-of-scope list, layer summary, etc. are still stub prose)
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

### 2. No CORS ✅ resolved

`CORSMiddleware` added to `apps/api/main.py`, origins from `CORS_ORIGINS`. No longer blocks Dev C.

### 3. No observations endpoint ✅ resolved

`GET /observations` and `GET /scans/{id}/observations` both ship, paginated, with provenance.

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

1. ✅ ~~CORS middleware~~ — done
2. ✅ ~~`GET /observations`~~ — done
3. **Dashboard phase 1** — engagements + scans. **Completes Layer 1.** In progress, owned by Dev C. *(C)*
4. ✅ ~~Extend `tests/fixtures/observations/`~~ — done, all 10 hosts, all 3 segments, nuclei included
5. **Eval harness, Track A** — buildable now against Layer 1 output + ground truth; does not need Layers 2–4. **Biggest remaining gap against the project's own stated priorities.** *(All)*
6. **Layer 2 brainstorm** — identity resolution strategy is explicitly open; decide before coding. *(B)*
7. ✅ ~~Resolve the timeline conflict~~ — done (D-022). `docs/00-scope.md` stub itself still needs replacing, lower priority
8. **Decide the staffing question** the architecture doc raises. *(All)*

---

## Smaller items worth not losing

- ⬜ Audit log unbounded and non-durable
- ⬜ CI runner deprecations (Node 20→24, ubuntu-latest→26)
- ⬜ Stale remote branches: `mayank-development`, `fix/layer-1-review-followups`
- ⬜ Dead file `apps/web/app/page.module.css`
- ⬜ Undefined CSS classes across `apps/web/components/`
- ⬜ **`requirements.txt`/`requirements-dev.txt` are all unpinned (`>=`)**, so CI can silently
  resolve newer major versions than whatever a developer has installed locally. Bit us once
  already: local mypy 1.16 accepted `# type: ignore[misc]` on the celery task decorator and
  needed an ignore on `JSONB()`; CI's freshly-resolved mypy 2.3.1 + SQLAlchemy 2.0.54 split that
  into its own `untyped-decorator` error code and made the `JSONB()` ignore unused, failing CI
  on a PR that was locally green. Worth pinning, or at minimum periodically syncing local envs
  against CI's resolved versions before trusting a local mypy/pytest pass.
