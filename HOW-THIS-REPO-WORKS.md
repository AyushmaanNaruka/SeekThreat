# How this repo works

Read this first. It should take five minutes.

---

## What we are building

One platform that scans a target, understands what it found, works out how an attacker would chain those weaknesses together, and lets you ask it questions in plain English.

Four layers, stacked. Each one makes the layer below more useful.

| Layer | What it does | Where the code lives |
|---|---|---|
| **4. Conversation** | Chat assistant over our own data, answers with citations | `apps/web`, `services/assistant` |
| **3. Reasoning** | Graph of assets and techniques. Real attack paths, chokepoints | `services/graph` |
| **2. Understanding** | One schema, deduplicated, enriched from many sources | `services/enrichment`, `packages/schema` |
| **1. Collection** | Scanners, one web interface, no command line | `services/scanners`, `apps/api` |

Full detail in `docs/00-scope.md`.

---

## The three rules

These are not style preferences. Breaking one damages the project.

**1. The LLM never invents an attack path.**
It only explains paths the graph engine already proved. Every edge in every path traces back to a scan fact and a named rule. If you find yourself writing a prompt that asks a model to guess how vulnerabilities connect, stop.

**2. Nothing gets scanned without authorization.**
Every scan job carries an authorization record with a named authorizer and a target allowlist. No exceptions, not even for local testing. Use `lab/` — it is ours and it is safe.

**3. Never copy code from AGPL or GPL projects.**
Read them, learn from them, write our own. Copying makes our entire project AGPL/GPL. Full rules in `docs/01-open-source-policy.md`.

---

## Repo layout

```
apps/api          FastAPI backend
apps/web          Next.js frontend
services/         Our core logic — scanners, enrichment, graph
packages/schema   Shared data models. Change carefully, everything depends on it
vendor/           ALL third-party code. Nowhere else.
lab/              Our vulnerable test network + ground truth
evals/            Test harness and golden dataset
infra/            docker-compose, deployment
docs/             Scope, policy, architecture
```

**The `vendor/` rule:** third-party code lives in `vendor/` and nowhere else in the tree. This makes borrowed code visible in every diff. If you put someone else's code in `services/`, nobody will notice it six months later when it matters.

---

## Getting started

```bash
git clone <repo-url>
cd seekthreat
cp .env.example .env        # fill in your API keys
pip install -r requirements-dev.txt
docker compose -f infra/docker-compose.yml --profile core up -d
```

**Nothing starts without a profile.** The full stack does not fit in 16 GB, so you
choose what to run: `core` (Postgres, Redis), `model` (Ollama), `viz` (Neo4j, from
November). The lab is a separate file. See `docs/02-architecture.md`.

Then bring up the lab separately:

```bash
docker compose -f lab/docker-compose.yml up
```

Never point a scan at anything outside `lab/` unless there is an authorization record for it.

---

## Working with Claude Code and Antigravity

`CLAUDE.md` and `AGENTS.md` sit at the repo root. Both AI tools read them automatically, so the project rules get applied without you having to repeat them every session.

If you find yourself explaining the same constraint to the AI more than twice, that constraint belongs in `CLAUDE.md`. Add it and open a PR.

**Do review what the AI writes.** Generated code that nobody read is how a subtle bug reaches December.

---

## Using third-party code

Four ways to use an external project. Two are safe.

| Mode | What it is | Safe? |
|---|---|---|
| **Run as a service** | Deploy their container, call their API | Yes — preferred |
| **Study and reimplement** | Read their design, write our own | Yes — preferred |
| **Copy code** | Their files in our `vendor/` | Only from MIT / BSD / Apache |
| **Fork wholesale** | Build inside their repo | No. Never |

If you copy anything, you must add a row to `THIRD_PARTY.md` in the same PR. CI will fail the build if you don't.

**The 3-day rule:** if integrating something takes more than three days, it has to be saving more than three days of work. Otherwise drop it and write our own.

---

## Recording decisions

`DECISIONS.md` at the root. Log anything that changes the plan — a new dependency, a scope change, a different approach than the scope doc describes.

Takes two minutes. Write it the same day, not later.

---

## Branches and PRs

```
main              always working
feat/<thing>      your work
```

Branch from `main`, open a PR, get one review, merge. Keep PRs small enough to actually read.

Commit style: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`.

---

## Who owns what

| Area | Owner |
|---|---|
| Platform & orchestration — scanners, queue, auth, infra, lab | A |
| Data & intelligence — normalization, enrichment, graph, paths, ML | B |
| AI & interface — retrieval, model serving, assistant, UI | C |

Ownership means accountable for it working and measured. Not the only person allowed to touch it.

**The eval harness in `evals/` is co-owned by all three of us.** Anything owned by one person becomes nobody's priority in month six.

---

## Where to look

| Question | File |
|---|---|
| What are we building, and how far? | `docs/00-scope.md` |
| Can I use this GitHub repo? | `docs/01-open-source-policy.md` |
| How is it structured? | `docs/02-architecture.md` |
| Why did we change that? | `DECISIONS.md` |
| What have we borrowed? | `THIRD_PARTY.md` |
