# Dashboard specification

**Who this is for:** Dev C, who owns the interface. This answers "how big should the dashboard
be, and what goes in it" so you can design and build without waiting on anyone.

**Status of this document:** written 2026-09-20 against the code as it actually exists on
`main`. Every endpoint, field name and status value below was read out of the source, not
remembered. Where something does not exist yet, this document says so plainly rather than
describing it as if it were there.

Read `HOW-THIS-REPO-WORKS.md` and `CLAUDE.md` first if you have not. The three project rules
apply to the UI as much as anything else.

---

## The short answer on size

**Six screens eventually. Two of them are worth building now, and one of those two is the
thing that finishes Layer 1.**

`apps/web/README.md` already names the six: Engagements, Scan progress, Findings, Attack paths,
Assistant, Reports. That list is right, and it is the finished product. But four of those six
sit on top of code that does not exist yet — there is no findings table, no graph engine, no
assistant. Building their UI now means building against imagination, and imagination is what
produced the mock data we had to strip out in PR #2.

So the shape of the work is:

| Phase | Screens | Buildable when | Why |
|---|---|---|---|
| **1. Now** | Engagements, Scans | Today, after two small API changes | Real endpoints exist. **This completes Layer 1.** |
| **2. Next** | Observations / results detail | After one new endpoint (small) | Data is already in the database, just not exposed |
| **3. October–November** | Findings | Layer 2 lands | Needs `services/normalize` + `services/enrichment` |
| **4. November** | Attack paths | Layer 3 lands | Needs `services/graph`. The centrepiece demo screen |
| **5. December** | Assistant, Reports | Layer 4 lands | Needs `services/assistant` |

Build phase 1 properly — real data, real error states, real empty states. It is more valuable
than five screens of placeholder.

---

## Why phase 1 matters more than it looks

`HOW-THIS-REPO-WORKS.md` defines Layer 1 as:

> **1. Collection** — Scanners, **one web interface, no command line**

Everything else in Layer 1 is done: schema, authorization gate, two scanner adapters, Postgres
persistence, Celery dispatch, the lab, migrations, 191 passing tests. The web interface is the
last piece. Until someone can create an engagement and launch a scan from a browser, Layer 1 is
not finished, and the September milestone in `docs/02-architecture.md` does not close.

That is your first deliverable. It is small, it is real, and it ends a milestone.

---

## Non-negotiable rules

These come from `CLAUDE.md` and `apps/web/README.md`. They are not style preferences.

**1. Never render a number we have not measured.**
No accuracy figures, no "threats blocked", no percentages, no counts we did not compute from
real data on screen. We already shipped `99.7% Detection Accuracy` once and had to remove it.
`ThreatStats.tsx` now carries a comment explaining why — leave it there. If a chart needs data
we do not have, label it **Target** or leave the chart out.

**2. Every score shows its breakdown on click. No opaque numbers.**
This applies from the moment scores exist. `ExposureRiskScore` is built to carry its own
components and an `explain()` method precisely so the UI can render the reasoning. When you get
there, do not render the number alone.

**3. Every assistant answer shows its sources.**
Currently violated by the demo modal, which ends an answer with "see the two citations below"
and then renders no citations. Either render them or cut the line.

**4. Authorization is visible, always.**
Every scan in this system is gated by an authorization record with a named human and a target
allowlist. The UI must make that legible — who authorized this, what is in scope, when does it
expire. This is the project's headline safety property; it should not be invisible in the
product. It is also legally load-bearing (see the README's Legal section).

**5. Real data or an honest empty state. Never filler.**
A "Live" badge over data that never updates is worse than no badge.

---

## Where `apps/web` actually is right now

Be aware of what you are inheriting, because the README describes a product that is not built.

- **One route.** `app/page.tsx`, a single landing page. No `/engagements`, no `/scans`, no
  routing structure. `next/link` is not imported anywhere; nav links are hash anchors with
  `preventDefault()`.
- **Zero network calls.** No `fetch`, no API client, no `lib/`, no typed DTOs, no env var for a
  backend URL. Every value on screen is a literal in component source.
- **Next.js 16.3.5, React 19.2.8.** Three runtime dependencies total. No state library, no
  data-fetching library, no HTTP client, no charting library, no graph library, no component
  library, no test runner.
- **Plain global CSS, no Tailwind.** `app/globals.css` is 1386 lines of hand-written CSS in
  numbered sections. There is no `tailwind.config`, no PostCSS, no `@tailwind` directives.
- **A live bug worth knowing:** several components use Tailwind-style class names
  (`text-slate-400`, `font-mono`, `text-xs`, `mb-4`, and about ten more) that are **not defined
  anywhere in `globals.css`**. They render with no effect. Either define them, adopt Tailwind
  properly, or remove them — but know that they currently do nothing.
- **`app/page.module.css` is dead** — a `create-next-app` leftover imported by nothing.
- **Leftover fabricated demo content.** The invented *metrics* were removed, but invented
  *content* remains: a literal `CVE-2024-XXXX` placeholder rendered on screen, an invented IP
  `10.10.20.15` (our lab is `172.20.x.x`), a fictional terminal transcript, and a threat feed
  with a pulsing "Live Intelligence" dot over four frozen hardcoded rows.

**You are not obliged to keep the landing page.** It is a marketing mockup. Decide whether it
becomes the logged-out home page with the real app at `/app/...`, or whether it goes. Either is
defensible — just do not let the mock data leak into the real product.

---

## Two things must be fixed in the API before any of this works

Both are backend tasks, not yours. Flagging them so you are not blocked and surprised.

### Blocker 1 — There is no CORS middleware. Nothing will work without it.

`apps/api/main.py` is 21 lines and adds no middleware at all. A browser on `localhost:3000`
calling an API on `localhost:8000` is a cross-origin request; every call will be blocked by the
browser before it reaches the server. This is a three-line fix (`CORSMiddleware` with the dev
origin allowlisted) but until it lands you cannot call the API from the browser at all.

### Blocker 2 — Observations are stored but no endpoint returns them.

This one shapes your screens, so understand it precisely. When a scan completes, the worker
writes rows into the `observations` table — every open port, every service version, every
nuclei finding, with full provenance. That data is all there.

**But no route returns it.** `GET /scans/{id}` runs `len(observations)` and sends only the
integer. So today, when a scan succeeds, the most a dashboard can say is *"this scan produced
47 observations"* — not which ports, which hosts, which services, which CVEs.

The repository methods already exist (`ObservationRepository.get_by_engagement`,
`count_by_engagement`) and are simply never called by a router. Adding the endpoint is small.
Until it exists, your scan detail screen has a count and nothing else.

---

## What the API gives you today, exactly

Seven endpoints. Base URL `http://localhost:8000`. Interactive docs at `/docs` (FastAPI
generates them automatically — use them, they are always current).

No authentication on any endpoint. Authentication is deliberately out of scope for this phase
per `docs/00-scope.md`, so do not build a login flow against a backend that has no concept of
users. The "Confirm & Launch Telemetry" auth form in `DemoModal.tsx` is not backed by anything.

### `GET /health`
Returns `{"status": "ok"}`. Note it is a hardcoded literal — it does **not** check Postgres or
Redis. Do not present it as a system-health indicator, because it will say "ok" with the
database on fire.

### `POST /engagements` → `201`

```json
{
  "engagement_id": "eng-001",
  "name": "Lab baseline assessment",
  "authorized_by": "A. Named Human",
  "allowlist": ["172.20.0.0/16"],
  "granted_at": "2026-09-20T10:00:00Z",
  "expires_at": "2026-09-27T10:00:00Z"
}
```

Every field is required. `allowlist` must have at least one entry. **Both datetimes must be
timezone-aware** — send ISO-8601 with an offset or `Z`. A naive datetime is a `422`.

Response echoes all of the above plus a server-set `created_at`. Note the response **flattens**
the authorization — there is no nested `authorization` object in the JSON.

Status codes you must handle: `201` created · `409` the id already exists (the allowlist is
*not* overwritten, by design — this was a security fix) · `422` validation failure.

Two `422` shapes exist and they are not the same: Pydantic validation errors come back as an
**array** of error objects under `detail`, while the explicit `expires_at <= granted_at` check
comes back as `{"detail": "<plain string>"}`. Handle both or your error rendering will crash on
one of them.

### `GET /engagements`
No query parameters. No pagination. Returns the full list, newest first. Empty list, never a
404.

### `GET /engagements/{engagement_id}`
`200` with the object, or `404`.

### `POST /scans` → `202`

```json
{
  "engagement_id": "eng-001",
  "scanner": "nmap",
  "target": "172.20.1.10",
  "options": {}
}
```

`scanner` defaults to `"nmap"`; only `"nmap"` and `"nuclei"` are implemented. **The API does not
validate the scanner name** — an unknown one is accepted with a `202` and fails asynchronously
inside the worker. Constrain it to a two-option select in the UI rather than a free text field.

`options` is an arbitrary JSON object. The only key consumed today is `timeout` (seconds,
default 1800) for nmap. Scanner flags are deliberately **not** accepted from the request body —
that was an authorization bypass we closed in D-017. Do not add a "custom arguments" field.

Status codes: `202` accepted · `404` no such engagement · `403` authorization denied ·
`503` the job queue is down · `422` validation.

The `403` has three distinct causes and the `detail` string tells you which: the window has not
started yet, the window has expired, or the target is not in the allowlist. **Surface that
message to the user verbatim** — "not authorized" alone is unhelpful, and "expires in 2 hours"
vs "target out of scope" are completely different user problems.

On `503`, note the scan row has already been written and set to `failed`. Refetch the list
afterwards or your UI will disagree with the server.

### `GET /scans?engagement_id=<id>`
**The `engagement_id` query parameter is required** — omitting it is a `422`. There is no
"list all scans" capability. No pagination, no status filter, no sorting. Newest first. An
unknown engagement id returns `[]`, not a 404.

### `GET /scans/{scan_id}`

```json
{
  "scan_id": "scan-a1b2c3d4e5f6",
  "engagement_id": "eng-001",
  "scanner": "nmap",
  "target": "172.20.1.10",
  "status": "completed",
  "options": {},
  "observation_count": 47,
  "artifact_id": "sha256:...",
  "error_message": null,
  "created_at": "2026-09-20T10:05:00Z",
  "completed_at": "2026-09-20T10:06:12Z"
}
```

**`status` is one of exactly four strings:** `pending` · `running` · `completed` · `failed`.
It is a plain string column with no database enum and no enum in the OpenAPI schema, so you must
hardcode these four. There is no `cancelled` — scans cannot be cancelled.

`artifact_id` is null until the scan completes. `error_message` carries the failure reason as
`"<ExceptionType>: <message>"` — render it, it is genuinely useful (`ScannerUnavailableError`
means the binary is missing from the worker image, for instance).

**There is no WebSocket and no SSE.** Polling `GET /scans/{scan_id}` is the only way to watch a
scan progress. Poll a few seconds apart while status is `pending` or `running`, and stop once it
reaches `completed` or `failed`.

---

## Screen specifications

### Screen 1 — Engagements

The entry point. An engagement is an authorization record: who said this scan is allowed, what
is in scope, and for how long. Nothing can be scanned without one.

**List view.** All engagements, newest first. Per row: name, id, authorizer, allowlist summary,
and — most importantly — **a live authorization state**, which you compute client-side by
comparing now against `granted_at`/`expires_at`:

- *Not yet active* — the window has not started
- *Active* — scans permitted, show time remaining
- *Expired* — scans will be refused with a `403`

Make expiry visually obvious as it approaches. A user about to launch a scan into an expiring
window should know before they click, not after the 403.

**Create form.** Six fields. Two design notes that matter:

The allowlist is the safety boundary of the entire product. It deserves better than a comma-
separated text input. Let people add entries one at a time, show them as removable chips, and
validate the shape client-side — an entry is an IP, a CIDR, a hostname, or a `*.wildcard`
domain. Be aware that **DNS is never resolved** by the backend matcher: an IP target will never
match a hostname pattern, and `*.example.com` matches subdomains but **not** the apex
`example.com`. That surprises people; a hint near the field will save real confusion.

`authorized_by` is a named human who is accountable. Label it that way — "Authorized by (full
name)" — not "user" or "owner".

**Detail view.** The engagement plus its scans (`GET /scans?engagement_id=…`).

### Screen 2 — Scans

**Launch.** Pick an engagement (must be active), pick a scanner from a two-option select, enter
a target. Before submitting, check the target against the engagement's allowlist client-side and
warn — the server will refuse it anyway, but telling the user *before* the round trip is kinder.
That client-side check is a convenience, never a security control: the server gate is the real
one and it stays.

Targets come from `lab/` only. The lab is `172.20.1.0/24` (dmz), `172.20.2.0/24` (internal),
`172.20.3.0/24` (data) — ten hosts, all listed in `lab/ground_truth.yaml`. Offering them as
suggestions would be genuinely useful and keeps people out of the habit of typing arbitrary IPs.

**Progress.** After `202`, poll. Show the four states honestly. `pending` means queued and no
worker has picked it up — if it sits there, the Celery worker is probably not running, which is
worth saying rather than spinning forever. An nmap `-sV` scan of a single host takes tens of
seconds; a `/24` takes considerably longer. Show elapsed time rather than a fake progress bar,
because the API gives you no percentage and inventing one would be a fabricated metric.

**Result.** On `completed`: scanner, target, duration (`completed_at - created_at`), and the
observation count. **Today that count is all you get** — see Blocker 2. Design the screen so
that when the observations endpoint lands, the detail slots in underneath rather than requiring
a redesign.

On `failed`: render `error_message` prominently. This is a debugging surface for us, not a
polished end-user surface, and the raw exception string is the useful thing.

### Screen 3 — Observations (once the endpoint exists)

The scan result detail. Group by host, then by port. An observation has a `kind` — one of
`host_up`, `port_open`, `service_version`, `vuln_candidate` — a `subject`
(`172.20.1.10:80/tcp`), an `attributes` map, and a `provenance` block carrying source,
confidence (`high`/`medium`/`low`) and timestamp.

**Provenance is not a detail to tuck away.** "Every finding carries source and confidence, no
unattributed data" is a project rule. Which scanner said this, and how confident it was, belongs
in the row — this is the visible difference between our output and a raw tool dump.

Filter by kind, by host, by confidence. Search across subject and attributes.

### Screens 4–6 — Findings, Attack paths, Assistant

Do not build these yet. The backing layers do not exist — `services/enrichment`,
`services/graph` and `services/assistant` are empty files. Anything you build now would be
mock data, and mock data in this repo has a track record of shipping by accident.

What is worth doing now is **thinking about the attack path screen**, because it is the
project's centrepiece and the best moment in the demo. `docs/02-architecture.md` is explicit:
*"Every path edge clicks through to its evidence."* Every edge will arrive carrying a
`rule_name` and an `evidence` tuple of observation ids. The screen has to make that traceable —
click an edge, see the rule that fired and the actual scan facts underneath it. That is the
whole argument of the project rendered as a UI, and it is worth designing early even though you
cannot build it until November.

`lab/ground_truth.yaml` documents the three real multi-hop paths the lab is built to produce.
Read it — it tells you the shape of what you will be drawing.

---

## States you must handle

Skipping these is the main way a demo falls apart:

- **Empty** — no engagements yet. This is the first-run experience; make it a path to the
  create form, not a blank page.
- **Loading** — the API is local and fast, but the *scan* is slow. Distinguish "fetching the
  list" from "the scan is running".
- **API unreachable** — the backend is a separate process that is frequently not running. Say
  "cannot reach the API" clearly. This will be the single most common failure during
  development.
- **Error responses** — 403/404/409/422/503, each with a useful message. Remember the two
  different `422` body shapes.
- **Partial** — a completed scan with zero observations is a real and valid outcome (host down,
  no open ports). It is not an error.

---

## What NOT to build

- A login or signup flow — there is no auth backend
- A scan cancellation button — the API cannot cancel
- Custom scanner arguments — deliberately removed as a security fix (D-017)
- Any chart of data we do not have
- A "system health" widget wired to `/health`, which does not check dependencies
- Pagination controls for endpoints that do not paginate — either add them server-side first or
  leave them out
- Anything about findings, graphs, or chat until those layers exist

---

## Technical choices — yours to make

The frontend is your area, so these are your calls. Some context:

**Data fetching.** There is no library. Something small with caching and polling built in
(SWR or TanStack Query) would suit this well — you need polling for scan status and cache
invalidation after creating things. Plain `fetch` in `useEffect` also works. Either way, put the
calls behind a typed client module rather than scattering `fetch` across components; when the
observations endpoint lands you want one place to add it.

**Styling.** The existing 1386 lines of global CSS work, but the Tailwind-style class names
scattered through the components suggest someone expected Tailwind. Pick one and be consistent.
If you adopt Tailwind, that is a dependency worth a line in `DECISIONS.md`.

**Types.** The API has an OpenAPI schema at `/openapi.json`. Generating TypeScript types from
it keeps the frontend honest when `packages/schema` changes — and it will change, a lot, in
October.

**Graph rendering** is a November question. When it comes, check the licence before adding the
dependency (`docs/01-open-source-policy.md`) — Cytoscape is MIT, some graph libraries are not.

Anything you add goes in `apps/web/package.json`, and a new dependency is worth flagging per
`CLAUDE.md`.

---

## Suggested build order

1. **Ask for the CORS fix** — you are blocked without it, and it is a three-line backend change.
2. **API client module + generated types.** One file, typed, all seven endpoints.
3. **Routing structure.** Decide the landing page's fate. Get `/engagements` and `/scans`
   existing as real routes.
4. **Engagements list + create.** First real data on screen. First real empty state.
5. **Scan launch + polling detail.** **At this point Layer 1 is complete** — a human can drive
   a real scan from a browser with no command line.
6. **Observations screen**, once the endpoint exists.
7. Stop. Design the attack path screen on paper while October and November happen underneath
   you.

---

## Definition of done for phase 1

A person who has never used a terminal can:

1. Open the app and see there are no engagements yet
2. Create one, naming a human authorizer and a target allowlist
3. See it listed as Active, with an expiry
4. Launch an nmap scan against a lab host from that engagement
5. Watch the status move `pending → running → completed`
6. See how long it took and how many observations it produced
7. Try an out-of-scope target and get a clear explanation of why it was refused

That last one is not an edge case. It is the project's central safety property, demonstrated. It
belongs in the demo.

---

## Questions worth raising rather than guessing

- Should the marketing landing page survive as the logged-out home page, or go?
- Do you want the observations endpoint shaped a particular way (grouped by host? flat with
  filters?) — it has not been written yet, so you can influence its design rather than adapting
  to it afterwards. Say so before it gets built.
- Tailwind or the existing CSS?

Ask on the PR or in `DECISIONS.md`. Anything that changes the plan gets logged there.
