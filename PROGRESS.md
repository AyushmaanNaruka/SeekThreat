# Progress tracker

The single place to check what is done, what is not, and what is blocked.

**Last verified:** 2026-11-10, on branch `feat/e2e-demo`, which is based on
`feat/layer4-assistant` @ `1f6c11f`. That branch carries Layers 1 to 4 and is **not merged to
`main`**. `main` @ `491780f` has Layers 1 and 2 only.
**Verified how:** by reading the code and running it, not by trusting earlier status docs.
Every claim names a file, or is marked unverified. On 2026-11-10 the whole suite ran:
1393 passed, 9 skipped (`python -m pytest -q -p no:cacheprovider`). `ruff check .`,
`ruff format --check .` and `mypy --python-version 3.12 packages services apps` were clean.

---

## How to use this file

- Update it in the same PR as the work. A tracker updated a week later is fiction.
- Only tick a box when the thing is **verified working**, not when the code was written.
  Use ⚠️ for "written but unverified" and say what verification is missing.
- No percentages or completion scores. `CLAUDE.md` forbids rendering numbers we have not
  measured. Eval numbers appear only as they appear in `evals/results/*.md`, with that file's
  caveats.
- If something here turns out to be wrong, fix it rather than working around it.

**Legend:** ✅ done and verified · ⚠️ done but unverified · 🔨 in progress · ⬜ not started ·
🚫 blocked · ⏸️ deliberately deferred (with the reason)

---

## Where we are right now

January's milestone is *integration, demo, write-up: rehearsed demo plus a recorded
fallback* (`docs/02-architecture.md`, Sequence).

- All four layers have code, tests and a dashboard view on `feat/layer4-assistant`.
- `tests/integration/test_full_pipeline.py` drives the whole chain through the API in one
  test. It covers authorization, fixture observations, enrichment, the attack graph,
  ranking, chokepoints, simulation, assistant ask and narration, citation resolution, and the
  403 for an off-allowlist target.
- `docs/04-demo-runbook.md` is the demo script. Fixture mode (no Docker) was run end to end
  on 2026-11-10 with `scripts/seed_fixture_demo.py`. Live mode (Docker + lab) was **not**
  re-run that day, because the Docker daemon was not running.

Merged into `feat/layer4-assistant` on 2026-11-10: the `services/normalize` identity and
dedup work (D-045), version-matched CVE candidates (D-049), the path-1 analysis (D-050) and
the engagement report export (D-051) and the assistant quality changes (D-052, not yet
re-measured).

### Open decisions and gaps (the short list)

| Item | State | Where |
|---|---|---|
| **D-045** Track 1 identity resolution + dedup | **Proposed**, merged and wired into the scan task. Needs Utkarsh's review | `DECISIONS.md`, `services/normalize/` |
| **D-047** ordinal path ranking | Active, **pending Ayushmaan's confirmation** | `DECISIONS.md` |
| **D-048** assistant design | Active, **pending Ayushmaan's confirmation** | `DECISIONS.md` |
| **D-039** numeric path score | **Proposed, not adopted**. Its open items (barrier values, the 0.001 EPSS floor, cost of edges with no CVE/EPSS, Tier 2 weights, tier disagreement) are all still open | `DECISIONS.md` |
| **Ground-truth path-1** (dvwa → internal-api → db-primary) | **Infeasible as the lab is wired** — no network route between the hops, and dvwa / internal-api / db-primary versions do not match the claimed CVEs. Path-2's last hop has the same problem (CVE-2022-0543 does not apply to `redis:alpine`). **D-050 Proposed**: A = change the lab, B = restate the ground truth. Ground truth left unedited | D-050; `evals/results/attack_paths_results.md` |
| **Live-lab classifiable findings** | **D-049 Proposed**: deterministic version-match rules turn nmap `service_version` facts into LOW-confidence, "unconfirmed" CVE candidates; edges on them are capped LOW. Every range in `services/normalize/rules/version_cves.yaml` is `verified: false` (written without network access) and needs checking against its advisory. Fixture-tested only; not run against the live lab | D-049; `docs/04-demo-runbook.md` §3.3 |
| **Foundation-Sec-8B-Reasoning** | D-006's target model. **Not pulled, never measured.** No Ollama tag for it has been checked. The only real assistant measurement used `qwen2.5:7b` | D-006, D-048; `evals/results/assistant_eval_qwen2_5_7b.md` |
| **`docs/00-scope.md`** | Still a **placeholder stub** ("Paste the full scope and research document here"). Only its Timeline section is real (D-022), yet `CLAUDE.md` and `HOW-THIS-REPO-WORKS.md` call it authoritative | `docs/00-scope.md` |
| Neo4j `THIRD_PARTY.md` rows | Marked "Claude agent — human to confirm" | `THIRD_PARTY.md` |
| **D-052** assistant quality | **Proposed**, not re-measured; overfitting risk to the golden templates | `DECISIONS.md`, `services/assistant/` |
| Report output format | **D-051, Ayushmaan to confirm**: Markdown + JSON from one pure builder, `GET /engagements/{id}/report?format=md\|json`, dashboard download buttons. Narrations are not in the API export (they are not stored) | D-051; `services/report/` |
| Staffing question (graph engine owner) | The architecture doc asked for a decision in September. None is logged | `docs/02-architecture.md` |

---

## Layer 1 — Collection ✅

> **Done when:** a scan produces stored, provenanced observations (`docs/02-architecture.md`).
> Demonstrated live from the dashboard against the lab on 2026-10-15 (D-043, D-044).

- ✅ Schema — `packages/schema/models/` (`Observation`, `RawArtifact`, `ScanResult`,
  `Engagement`, `Authorization`, `Finding`, `EnrichedFinding`, graph, topology, assistant,
  citation, scoring, provenance). Pydantic v2 (D-009)
- ✅ Authorization gate in the API — `apps/api/core/authorization.py`, before any scan row
  is created. Also in the adapter base, `services/scanners/base.py`. Reflection coverage
  test — `tests/architecture/test_authorization_gate.py`. `%` scope-id bypass closed (D-043)
- ✅ Four adapters, fixed argv (D-017, D-023): nmap, nuclei, nikto, ssh-audit —
  `services/scanners/`. Nikto and ssh-audit restricted to non-destructive checks (D-043)
- ✅ Batch targets with server-side planning — `POST /scans/plan` (dry run),
  `POST /scans/batch`. Every target is gated — `apps/api/core/targets.py`,
  `apps/api/routers/scans.py`
- ✅ Celery + Redis dispatch (D-014, D-019, D-021). Separate `enrichment-worker` and `beat`
  services (D-041) — `infra/docker-compose.yml`
- ✅ Read path — `GET /observations`, `GET /observations/{id}`, `GET /scans/{id}/observations`
- ✅ Lab — 10 hosts, 3 internal segments, `lab/ground_truth.yaml`. Every image pulls after
  D-042
- ✅ Dashboard — `apps/web/app/dashboard/page.tsx`: engagements, scan launch with scope
  preview, live status, observations, Findings, Attack Paths, Assistant, Feed Health.
  Fabricated UI was removed (D-044)
- ⚠️ Fixtures — `tests/fixtures/observations/`. `lab_baseline.json` is a real capture.
  **8 of 10 hosts are still synthetic** (hand-authored tool output run through the real
  parsers). The lab now pulls, so real captures could replace them; none has yet
- ⬜ Audit trail is a Python log line plus an unbounded in-memory list
  (`apps/api/core/audit.py`). It is not persisted, not shared across processes, and no
  endpoint exposes it

## Layer 2 — Understanding ⚠️

> **Done when:** coverage measured against an NVD-only baseline. Measured once on real
> mirrors (below).

- ✅ Enrichment fusion with per-field provenance — `services/enrichment/fusion.py`. Sources:
  CVE.org, CISA Vulnrichment, NVD, ENISA EUVD, EPSS, CISA KEV, ExploitDB, Metasploit
  (identifiers only) — `services/enrichment/sources/`
- ✅ ERS, additive with documented weights (D-008, D-027). Self-explaining
  `ExposureRiskScore` — `services/enrichment/ers.py`
- ✅ Feed sync off the request path (D-033, D-036, D-041). CLI
  `python -m services.enrichment.sync_feeds`, beat at 02:00 UTC
- ✅ `enriched_findings` table, `/findings` API, engagement-scoped (D-031, D-032).
  Provenance gate: findings must cite the engagement's observations (D-040)
- ✅ Interim observation→Finding bridge — `services/normalize/interim_bridge.py` (D-044)
- ⚠️ Identity resolution + cross-scanner dedup (Track 1, D-045 Proposed) —
  `services/normalize/{identity,dedup,pipeline}.py`, called from `apps/api/tasks/scans.py`
  with the engagement's stored observations as context. Awaiting Utkarsh's review. The
  assistant golden generator and web fixture generator still use the D-044 bridge
- ⚠️ Version-matched CVE candidates (D-049 Proposed) — `services/normalize/version_match.py`,
  rules in `services/normalize/rules/version_cves.yaml`, all ranges unverified. Added after
  dedup; never merged with scanner reports

## Layer 3 — Reasoning ✅

> **Done when:** every edge clicks through to its evidence. Checked by
> `scripts/verify_attack_graph_evidence.py`, which `tests/integration/test_full_pipeline.py`
> now runs against the API. On 2026-11-10 it was also run against the fixture-mode API:
> 37 of 37 evidence ids and 39 of 39 edges resolved.

- ✅ Deterministic engine — `services/graph/builder.py`, `engine.py`. Seven named rules in
  `rules/core.yaml`, capability map from tags and CWEs only in `rules/capabilities.yaml`
  (D-046). Purity guard — `tests/architecture/test_graph_purity.py`. Import firewall —
  `tests/architecture/test_import_firewall.py`
- ✅ Declared topology — `packages/schema/models/topology.py`,
  `PUT/GET /engagements/{id}/topology`, `apps/api/cli/load_topology.py`, `lab/topology.yaml`
- ✅ Paths, chokepoints, unclassified findings — `GET /engagements/{id}/attack-graph`
- ✅ Ordinal ranking with a one-line explanation per path (D-047). `AttackPath.score` stays
  `None`
- ✅ Remediation simulation — `POST /engagements/{id}/attack-graph/simulate`
- ✅ Read-only Neo4j projection (D-003) — `POST .../attack-graph/project`,
  `apps/api/cli/project_graph.py`. Tested over a fake driver; a run against a real Neo4j is
  not recorded here ⚠️
- ✅ Dashboard Attack Paths view — `apps/web/components/AttackPathsView.tsx`

## Layer 4 — Conversation ⚠️

> **Done when:** faithfulness measured on the golden set. Measured once with `qwen2.5:7b` on
> a fixture-derived golden set (below). Not yet with the target model.

- ✅ `services/assistant/`: documents (one fact per document), hybrid retrieval, citations,
  grounding check, answers, narration (D-048). It imports only `packages.schema`
- ✅ `ModelClient` over Ollama, plus `FakeModelClient` for tests (D-006) —
  `services/assistant/client.py`
- ✅ pgvector store (D-005) — `apps/api/assistant_store.py`, migration `0006`
- ✅ API — `POST /engagements/{id}/assistant/index`, `.../assistant/ask`,
  `.../attack-graph/paths/{path_id}/narrate`, `GET /assistant/status`
- ✅ Dashboard Assistant view and Narrate button — `apps/web/components/AssistantView.tsx`,
  `AttackPathsView.tsx`
- ⚠️ Assistant quality changes (D-052 Proposed): unambiguous citation repair, partial
  answers, entity-first retrieval. **Not re-measured** — the qwen2.5:7b numbers above predate
  them. Needs a real run, ideally on Foundation-Sec and a held-out question set

## Eval harness — `evals/`

Numbers below are copied from the result files. Read the file before quoting any of them.

| Eval | Result file | What it says | Caveats (from the file) |
|---|---|---|---|
| Enrichment coverage vs NVD-only | `evals/results/enrichment_coverage_real.md` (generated 2026-10-15) | Four-field headline 4.5% (9/200) NVD-only vs 30.0% (60/200) multi-source. Excluding `epss_score`: 6.0% (9/150) vs 6.7% (10/150) | The NVD-only baseline never loads EPSS, so EPSS adds a definitional gain. The like-for-like row is the one excluding EPSS. 50 CVEs. The mirror snapshot is not archived |
| ERS ranking corroboration | `evals/results/ers_validation_results.md` (2026-10-15) | Top-5 precision 100.0% balanced vs 40.0% no-EPSS control and CVSS-only. AUC-ROC 0.7308 balanced | **Smoke-level only.** The target is not independent of ERS: EPSS uses exploit availability (D-038) |
| Attack path validity | `evals/results/attack_paths_results.md` | Strict FOUND 2/3, lenient FOUND 2/3. path-1 is infeasible per topology. 22 paths, 4 chokepoints | **Fixture-based, not a lab run.** 8 of 10 hosts synthetic. Not the manual N=50 validity metric |
| Assistant, `qwen2.5:7b` | `evals/results/assistant_eval_qwen2_5_7b.md` (2026-11-07) | Faithfulness (answered, entity proxy) 0.500. Citation accuracy 0.481. Context recall 0.732. False refusal rate 0.600. Refusal accuracy 1.000. Answered 46/138 | **Fixture-based.** Entity-level faithfulness proxy, **not RAGAS**. Golden set generated from the same fixtures. Run on a dirty tree at `8484ba6` |
| Assistant harness check | `evals/results/assistant_eval_harness_check.md` | — | `FakeModelClient`. **Do not report any number from it** |
| Synthetic smoke runs | `enrichment_coverage_results.md`, `ers_validation_synthetic.md` | — | Hand-authored fixtures. Harness checks, not measurements |

- ⬜ Track A detection accuracy (precision/recall/F1 vs `lab/ground_truth.yaml`): no harness
  exists under `evals/`
- ⬜ Golden set is 138 items, against the README's ~500 target. That is deliberate, and the
  reason is stated in `evals/README.md`
- ⬜ Nothing in CI runs `evals/` (`.github/workflows/ci.yml`)
- ⚠️ `evals/README.md` is stale in two places. Its enrichment-coverage row quotes a
  2026-10-11 run whose numbers differ from the committed `enrichment_coverage_real.md`
  (2026-10-15). It also says no Layer 4 measurement has been committed, but the `qwen2.5:7b`
  run is committed. Treat the result files as authoritative

## Integration and demo (January)

- ✅ `tests/integration/test_full_pipeline.py`: one test through the real API over the test
  database, plus a rerun-safety test for the seed script. Shared fixtures are in
  `tests/integration/conftest.py`
- ✅ `scripts/seed_fixture_demo.py`: fixture-mode seed. Run 2026-11-10 against a native API
  on SQLite: 34 observations, 5 findings, 22 paths, 4 chokepoints, 66 assistant documents
  indexed with the local Ollama
- ✅ `docs/04-demo-runbook.md`: prerequisites, live and fixture modes, the views,
  remediation simulation, the recorded-fallback plan. Every command is marked verified or
  not
- ⚠️ Live mode (Docker stack + lab) not re-run since Layers 3 and 4 landed. Docker was down
  on 2026-11-10
- ⚠️ Dashboard not started on 2026-11-10 (`npm run dev`)
- ⬜ Rehearsal and the recording itself

---

## Smaller items worth not losing

- ⬜ `requirements*.txt` are unpinned (`>=`). CI once resolved a newer mypy than local and
  failed a locally green PR
- ⬜ CI runner deprecations (Node 20→24, `ubuntu-latest`)
- ⬜ Dead file `apps/web/app/page.module.css`
- ⬜ `docs/mayank_implementation/` status files are partly stale
- ⬜ Many local branches and worktrees are not pushed. Check `git branch` before assuming
  `main` has a layer

---

## Ownership

Per `HOW-THIS-REPO-WORKS.md`. Ownership means accountable, not sole author.

| Area | Owner |
|---|---|
| Platform & orchestration — scanners, queue, auth, infra, lab | A |
| Data & intelligence — normalize, enrichment, graph, paths, ML | B |
| AI & interface — retrieval, model serving, assistant, UI | C |
| **Eval harness** | **All three** |
