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

### D-022 — Correct `docs/00-scope.md`'s timeline to five months, November protected
**Date:** 2026-09-20
**Decided by:** Ayushmaan (confirmed with the team)
**Type:** Divergence
**Status:** Active

**Decision**
`docs/00-scope.md`'s Timeline section is rewritten to match `docs/02-architecture.md`'s
"Sequence" section: five months, September through January, with November (not October)
protected for the graph and attack-path engine. `docs/00-scope.md` now points to
`docs/02-architecture.md` as the authoritative schedule instead of carrying its own
independent copy.

**Why**
`docs/00-scope.md` was left as an unfilled placeholder ("Paste the full scope and research
document here...") from before the project started, but its Timeline table was real prose — a
six-month plan (August–January, October protected) that predates the team's actual start date.
`docs/02-architecture.md` was written after the team confirmed the real constraint: five months,
starting in September, with the integration month that the old plan gave itself in addition
folded into January. The two documents disagreed on both the length of the project and which
month is protected, and every other planning document (`PROGRESS.md`, `HOW-THIS-REPO-WORKS.md`)
had already been written against the five-month version. Left unresolved, a five-months read of
`docs/02-architecture.md` and a six-months read of `docs/00-scope.md` would each look equally
authoritative to whoever opened the repo next.

**Impact on plan**
No schedule changes — `docs/02-architecture.md`'s Sequence section was already correct and
already what the team has been building against. This only removes the contradiction: Layer 1
(the current month) is unaffected, and every layer after it is described once instead of twice.

**Cost if we're wrong**
Trivial to undo — a doc edit, not a code or architecture change.

---

### D-021 — Fix Celery task registration: explicit import, not `autodiscover_tasks`
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
`apps/api/worker.py` replaces `celery_app.autodiscover_tasks(["apps.api.tasks"])` with an
explicit `from apps.api.tasks import scans as _scans_tasks`. Verified in a subprocess (the only
way to observe this correctly — see below): importing `apps.api.worker` alone now registers
`seekthreat.scans.execute`; on `main` it registered nothing.

**Why**
`autodiscover_tasks` treats each entry in its list as a *package* and imports `"<entry>.tasks"`.
Passing `["apps.api.tasks"]` — the tasks package itself — made Celery look for the nonexistent
`apps.api.tasks.tasks` and silently register nothing. The correct call would have been
`autodiscover_tasks(["apps.api"])`. This was never caught because every existing test imports
`apps.api.tasks.scans` directly (to call `execute_scan.run.__func__` for the bypass-the-broker
pattern documented for this test suite), which registers the task as a side effect regardless of
what `worker.py` does — so the bug was invisible to every test that exists. A real
`celery -A apps.api.worker.celery_app worker` process imports only `worker.py`, hits the actual
bug, and rejects every dispatched job as unregistered: `execute_scan.delay()` enqueues work, and
nothing ever runs it. Every scan would sit at `pending` forever. This is why D-020's compose
verification could bring the worker container up but never actually completed a real scan.

Found and fixed locally (native `uvicorn`/`celery`, not Docker) before this decision was logged;
`tests/unit/test_worker_registration.py` pins it going forward. The test runs the check in a
**subprocess** on purpose — an in-process assertion would pass regardless of whether `worker.py`
registers anything, for the same reason the bug went unnoticed.

**Impact on plan**
None to scope. This was a live defect blocking the actual "done when" criterion for Layer 1 —
worse than the Docker Hub pull failures, because those are environmental and this was not: even
with a fully working Docker pull, scans dispatched through a real worker process would never
have executed.

**Cost if we're wrong**
None — the fix is strictly more correct than what it replaces, and it is regression-tested.

---

### D-020 — Worker-to-lab network attachment via a separate compose override
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
Added `infra/docker-compose.lab.yml`, an optional override (not merged into
`infra/docker-compose.yml`) that attaches the `worker` service to all three
lab networks -- `lab_dmz`, `lab_internal`, `lab_data`, declared
`external: true` -- at fixed IPs (`172.20.{1,2,3}.251`, one per segment,
outside every range in `lab/ground_truth.yaml` and clear of the lab's own
`scanner` helper at `.250`). Brought up with:

```
docker compose -f lab/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml \
    --profile core up -d
```

Attached to all three segments, not `dmz` only: Layer 1's own "done when"
criterion is stored observations from a real scan, and `ground_truth.yaml`
requires coverage of the internal and data tiers, not just the perimeter.
The graph engine (Layer 3) models multi-hop pivoting on top of these
observations later; the scanner does not need to literally pivot to gather
them now.

**Why**
A separate override rather than editing the base file: external networks
must exist before `docker compose up` runs, or compose refuses to start. The
base file must keep working with no lab running -- day-to-day API/DB
development doesn't need the lab, and the memory budget in
`docs/02-architecture.md` already treats the two as mutually exclusive on a
16 GB machine.

Attaching an additional container to an `internal: true` network does not
weaken that network's isolation. The flag means "no default route to the
outside internet" -- it says nothing about which other containers may join
the same L2/L3 segment, and it is a property of the network, not of who is
attached to it. Verified directly rather than assumed: brought the worker up
attached to all three lab networks, confirmed reachability to the real
`dvwa`/`juiceshop` dmz targets and to substitute containers standing in for
the internal/data tiers (their own images fail to pull on this machine, see
D-018), and confirmed `docker network inspect` still reports
`Internal=true` on all three lab networks afterward -- the authoritative
check, since an in-container egress test using missing tooling would not
have been conclusive.

This grants reachability only. `apps/api/core/authorization.py` still
decides whether a scan is *permitted* -- an engagement's allowlist must
cover the target regardless of what the worker can physically reach
(CLAUDE.md hard rule 2). No code changed; this is compose configuration
only.

**Impact on plan**
Closes backlog item #1 from the compose-fix task (D-018): "the worker still
cannot reach the lab targets." Layer 1's "a scan produces stored,
provenanced observations" criterion is not yet fully demonstrated end to
end -- that also needs `pgvector/pgvector:pg16` to build, which is still
blocked by the same Docker Hub CDN failures documented in D-018 and D-019.
This change removes the networking half of that blocker; the image-pull half
is environmental and outside this change's scope.

**Cost if we're wrong**
Low. One new file, no changes to the base compose file or to application
code. Deleting `infra/docker-compose.lab.yml` fully reverts this.

---

### D-019 — Non-retried permanent scan failures; pinned nuclei binary; migration/ORM index parity
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
Three contained fixes from the PR #2 follow-up list, closed together:
1. `apps/api/tasks/scans.py` no longer retries permanent failures. A new
   `PERMANENT_ERRORS` tuple (`ValueError` for an unsupported scanner name,
   the new `ScannerUnavailableError` for a missing binary, `AuthorizationError`)
   is checked before handing the exception to `self.retry()`. The task also
   now re-raises after marking a scan `failed`, so Celery's own task state
   (FAILURE) agrees with the database row, instead of the task returning
   normally and being recorded SUCCESS.
2. `apps/api/Dockerfile` installs a pinned nuclei release binary
   (`v3.11.1`, linux_amd64, verified against the release's published sha256)
   alongside the existing apt-installed nmap. `adapter.is_available()` is
   checked before `adapter.scan()` inside the task, turning a missing binary
   into `ScannerUnavailableError` instead of an opaque subprocess `OSError`
   retried three times.
3. New migration `0003_add_scans_artifact_id_index` adds `ix_scans_artifact_id`,
   which `apps/api/db/models.py` declared (`index=True`) but migration 0002
   never created. `tests/unit/test_alembic.py` gained a test that upgrades a
   fresh DB via Alembic, builds a second one via `create_all`, and asserts
   their indexes match on every table -- so this class of drift fails CI
   going forward instead of silently diverging between what tests exercise
   and what a real deployment gets.

**Why**
Every retry of a permanent failure is a full rescan; an unsupported scanner
or a missing binary was retried 3 times before being marked failed for an
outcome that could never change. Separately, the task swallowing the
exception after marking a scan `failed` meant Celery itself reported the task
SUCCESS -- anything monitoring Celery task state (Flower, a future ops
dashboard) would see no failure at all. Both close on the same code path, so
fixed together rather than in separate changes touching the same function.

The Dockerfile fix was already called out on the backlog as a known gap
(nuclei has no apt package; needs the pinned GitHub release approach nmap
does not need). Bundled with the retry fix because `is_available()` needing
to run somewhere is what the retry fix's `ScannerUnavailableError` is for.

**Impact on plan**
None to scope or timeline. Chosen as the second of two contained PRs closing
the PR #2 follow-up list (the first, apps/api/routers, is a separate PR from
the same base so either can merge first). The Dockerfile change is
**not yet verified by an actual image build** -- Docker Hub image pulls are
failing on this machine for reasons unrelated to this change (see the compose
fix's PR); `pip install`/pytest/mypy/ruff all pass, but nobody has confirmed
`docker build` actually produces a working `nuclei` binary at this container's
`glibc`/architecture. Flagging this explicitly rather than claiming it works.

**Cost if we're wrong**
Low for the retry/re-raise logic -- covered by unit tests calling the task
body directly, no live Celery or Redis needed. Medium for the Dockerfile: if
the binary turns out incompatible with `python:3.11-slim`'s base image, the
fix is confined to that one `RUN` block and does not touch application code.

---

### D-018 — Fix the `core` compose profile: in-network hostnames, a migration step, and a normalized DB driver everywhere
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
`docker compose -f infra/docker-compose.yml --profile core up` did not work. Fixed with four
changes:
1. `api`, `worker`, and a new one-shot `migrate` service get `environment:` overrides pointing
   `DATABASE_URL`/`REDIS_URL` at the `postgres`/`redis` compose service names, not `localhost`.
   `environment:` outranks `env_file:`, so one `.env` still serves native dev via the published
   ports.
2. `migrate` runs `alembic upgrade head` once (`restart: "no"`); `api` and `worker` gate on
   `service_completed_successfully` so tables exist before either starts, and so the two never
   race to apply the same DDL.
3. `.dockerignore` added — `context: ..` was copying the whole repo, including
   `apps/web/node_modules` and `.env`, into the build context.
4. `env_file` on postgres/api/worker/neo4j changed to the long form with `required: false`.
   `.env` is gitignored and absent on a fresh clone; compose treats a missing plain-string
   `env_file` as fatal, which was the actual first failure, ahead of the networking one.

**Why**
While implementing this, found that `apps/api/core/config.py` normalized `DATABASE_URL` to the
psycopg3 driver (`postgresql+psycopg://`) only inside a Pydantic `default_factory` — which
pydantic-settings skips whenever the env var is *set*. Every value actually in use
(`.env.example`, the new compose `environment:` overrides) is a bare `postgresql://`, which
SQLAlchemy resolves to psycopg2 — not installed; this project ships `psycopg[binary]`
(psycopg3). This was already a live bug on the native-dev path (`cp .env.example .env` and run)
and would have reproduced inside every container the compose fix touches. Moved the
normalization into a `field_validator(mode="after")` so it applies to every source — env var,
`.env` file, and default alike — with a regression test in `tests/unit/test_config.py`. Folded
into this decision rather than a separate one since it was found while implementing this task
and the compose fix does not work correctly without it.

**Impact on plan**
None to scope or timeline — infra-only. Worker-to-lab network attachment (`172.20.x.x`) remains
a separate, still-open follow-up: a scan dispatched at a lab IP records a failure until that
exists.

**Cost if we're wrong**
Low. Compose config only; reverting is a `git revert`. The driver-normalization fix has a unit
test pinning the behavior it corrects.

---

### D-017 — Remove `options["extra_args"]` from scanner adapters; fixed argv only
**Date:** 2026-09-20
**Decided by:** Ayushmaan (review of mayank-development, PR #1)
**Type:** Reversal
**Status:** Active

**Decision**
`NmapAdapter._execute` and `NucleiAdapter._execute` no longer splat
`request.options.get("extra_args", [])` into the tool's argv. The command line is now fixed
except for the target itself, and nmap's invocation adds a literal `--` before the target so it
can never be parsed as a flag.

**Why**
`ScanRequest.options` is a `dict[str, Any]` that reaches the adapter straight from the
`POST /scans` HTTP body (`apps/api/routers/scans.py`) with no validation beyond Pydantic's
`dict[str, Any]` typing. `request.authorization.permits()` only ever checks `request.target`
against the allowlist — it has no visibility into `options`. A caller could therefore pass
`{"extra_args": ["-u", "https://unauthorized.example.com"]}` (nuclei accumulates repeated `-u`
flags) or `{"extra_args": ["203.0.113.10"]}` (nmap scans every positional target given, so this
adds a second host ahead of the authorized one) and scan a target that was never checked against
any allowlist. This is a direct violation of CLAUDE.md hard rule 2 — "no scan without
authorization enforced at the API layer" — found during review of PR #1 before merge to `main`.

**Impact on plan**
None to timeline; this is a revert of an unreviewed pattern that shipped in the same PR that
introduced the HTTP scan-dispatch path. If tool-specific flags are needed later (e.g. nmap
timing templates), they must be a fixed, named, server-side option
(`options: {"timing": "T3"}` mapped to a small allowlist of flag values in the adapter) — never
an arbitrary argv fragment sourced from the request body.

**Cost if we're wrong**
None — this closes a real bypass with no loss of legitimate functionality; nothing in the
codebase or tests depended on `extra_args`.

---

### D-016 — Lab network topology, 10-host multi-tier architecture & ground truth baseline
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Architecture / Evaluation
**Status:** Active

**Decision**
`lab/docker-compose.yml` defines 10 target containers plus 1 scanner container partitioned across three isolated network segments (`dmz`: 172.20.1.0/24, `internal`: 172.20.2.0/24, `data`: 172.20.3.0/24). All networks enforce `internal: true` with zero egress to the internet and no exposed host ports. `lab/ground_truth.yaml` serves as the authoritative ground truth denominator for Track A (accuracy, precision, recall, F1) and Track B (attack path validity) evaluation metrics.

The topology intentionally embeds realistic multi-hop attack paths:
1. External DMZ SSRF (`dvwa` 172.20.1.10) -> Internal API credential leak (`internal-api` 172.20.2.10) -> Data Tier PostgreSQL (`db-primary` 172.20.3.10).
2. External API Gateway SpEL Injection (`spring-gateway` 172.20.1.13, CVE-2022-22947) -> Internal Jenkins CLI Arbitrary File Read (`jenkins-ci` 172.20.2.25, CVE-2024-23897) -> Bastion SSH pivot (`bastion-ssh` 172.20.2.50) -> Data Tier Redis Lua Sandbox Escape RCE (`cache-redis` 172.20.3.20, CVE-2022-0543).
3. External DMZ Reverse Proxy Smuggling (`dmz-proxy` 172.20.1.12) -> Internal Wiki OGNL Injection RCE (`internal-wiki` 172.20.2.40, CVE-2022-26134).

**Context**
Layer 3 (Graph / Path Engine) requires realistic attack paths that span multiple hops across segmented subnets; a flat network with isolated single vulnerabilities gives the graph reasoning engine nothing meaningful to discover. Furthermore, evaluation metrics cannot be retrofitted—Track A and Track B metrics require a verifiable ground truth denominator recording every host, service, version, expected CVE, and known scanner false positive.

**Consequences**
- Evaluation metrics have a strict, declarative baseline to calculate precision, recall, and false-positive rates.
- `tests/unit/test_ground_truth.py` enforces consistency between `lab/ground_truth.yaml` and `lab/docker-compose.yml`.
- Target containers remain fully isolated and legally safe to scan from the internal `scanner` container (172.20.1.250).

---

### D-015 — Nuclei as second core scanner; NDJSON output via `-jsonl -silent`
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Tool choice
**Status:** Active

**Decision**
`services/scanners/nuclei_adapter.py` invokes `nuclei -u <target> -jsonl -silent` and
`services/scanners/nuclei_json.py` parses the NDJSON output into `ObservationKind.VULN_CANDIDATE`
observations. Nuclei's native severity, CVE IDs, CVSS scores and matcher metadata are
preserved verbatim in observation `attributes`; no risk-score computation happens here.

**Why**
- Nuclei is MIT-licensed; we invoke the binary, never vendor its source.
- `-jsonl` produces one JSON object per line, making streaming and partial-failure recovery
  trivially safe. A JSON array would require buffering the full output before parsing.
- `-silent` suppresses non-finding output (progress bars, version banners) so stdout is
  pure NDJSON that can be round-tripped through `RawArtifact.content` and re-parsed
  deterministically from the stored artifact.
- Nuclei findings map directly to `VULN_CANDIDATE` — the tool reports confirmed template
  matches, not heuristics. Risk scoring (CVSS weighting, EPSS, KEV correlation) stays in
  `services.enrichment`, preserving the collection/enrichment boundary.

**Impact on plan**
- `NucleiAdapter` is auto-discovered by `tests/architecture/test_authorization_gate.py`
  (now 7 tests: 3 per adapter × 2 adapters + 1 discovery guard).
- `apps/api/tasks/scans.py` gained an `elif scanner == "nuclei"` dispatch branch.
- `requirements.txt` unchanged — nuclei binary is a system dependency, not a Python package.

**Cost if we're wrong**
Low. Switching to `-json` (array) changes only `_load_records()` in `nuclei_json.py`.
Removing Nuclei entirely is a two-file delete.

---

### D-014 — Celery + Redis for async scan execution, replacing FastAPI `BackgroundTasks`
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Tool choice
**Status:** Active

**Decision**
Scan jobs are dispatched via `execute_scan.delay()` (a Celery task) rather than
FastAPI's built-in `BackgroundTasks`. The task runs in a dedicated `worker`
container, reading from a `scans` Redis queue.

**Why**
`BackgroundTasks` runs inside the same process as the API server. If the server
restarts mid-scan the job is silently lost. Celery persists the task to Redis
before acknowledging the HTTP response (`task_acks_late=True`), so a worker
restart re-queues the job automatically.

Additional factors:
- Redis was already present in the `infra/docker-compose.yml` core profile.
- Built-in retry semantics (`max_retries=3`, `default_retry_delay=30s`) without
  any custom code.
- Horizontal scaling: adding more worker replicas is one compose override.
- Celery's JSON serializer (`task_serializer="json"`) prevents pickle-based
  remote code execution vulnerabilities.

**Impact on plan**
- `_execute_scan_task` removed from `apps/api/routers/scans.py` and moved to
  `apps/api/tasks/scans.py` as `@celery_app.task`.
- `apps/api/worker.py` added as Celery app bootstrap.
- `apps/api/Dockerfile` added; `infra/docker-compose.yml` gains `api` and
  `worker` services under the `core` profile (resolves the TODO comment).
- `Authorization` serialized as a JSON-safe dict (`model_dump(mode="json")`)
  when crossing the Celery message boundary, reconstructed via
  `Authorization.model_validate()` inside the task.

**Cost if we're wrong**
Low. The task body is structurally identical to the old `_execute_scan_task`.
Reverting means moving the function back into the router and swapping
`.delay()` for `background_tasks.add_task()`. One hour of work.

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
