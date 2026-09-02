# SeekThreat — project rules

Rules for AI assistants working in this repo. Read before generating code.

---

## What this project is

A vulnerability detection and attack-path reasoning platform. Scans a target, normalizes and enriches findings from many intelligence sources, builds a graph, computes attack paths deterministically, and exposes it all through a RAG assistant.

Final year engineering project, SIH problem statement 25234 (NTRO). Three developers, six months.

Full scope: `docs/00-scope.md`.

---

## Hard rules

### 1. The LLM never creates graph edges

Attack paths are constructed **deterministically** by the rules engine in `services/graph`. Every edge traces to an observed scan fact and a named rule.

The language model narrates paths that already exist. It does not infer, guess, or generate them.

**Never write:** a prompt asking a model to describe how vulnerabilities might chain together, or code that parses model output into graph edges.
**Instead:** enumerate paths in the rules engine, pass the proven path to the model for narration only.

This is the core design constraint of the project. If a request seems to require breaking it, stop and ask.

### 2. No scanning without authorization

Every scan job requires an authorization record: named authorizer, target allowlist, engagement ID. Enforced at the API layer, not the UI.

**Never** generate code that scans an arbitrary target, bypasses the allowlist, or defaults to a public host. Test targets come from `lab/` only.

### 3. Licence discipline

- **Never copy code from AGPL or GPL projects.** Studying is fine, copying is not. Known AGPL/GPL in this space: PatrOwl, Faraday, reNgine, cve-search, Vulnerability-Lookup, OpenVAS/GVM.
- **Copying is allowed only from MIT, BSD, and Apache-2.0** projects, with attribution.
- **All third-party code goes in `vendor/`.** Never inline it into `services/` or `apps/`.
- Any copied code requires a `THIRD_PARTY.md` entry in the same change.
- Nmap: invoke the binary and parse XML output. Never vendor or link its source.

### 4. No autonomous exploitation

The platform reports paths and references public exploit metadata (ExploitDB IDs, Metasploit module names). It does not weaponize, chain, or execute exploits. Verification, if built, is non-destructive only — banner match, benign canary.

---

## Architecture

```
apps/api            FastAPI backend
apps/web            Next.js frontend
services/scanners   One adapter per tool. Subprocess/container, parse output
services/enrichment Multi-source fusion. OUR core work
services/graph      Attack path engine. OUR core work
packages/schema     Shared models. Changes ripple everywhere
vendor/             Third-party code only
lab/                Vulnerable test network
evals/              Harness and golden dataset
```

**Stack:** Python 3.11+ / FastAPI, Next.js + TypeScript, PostgreSQL, Neo4j, Celery + Redis, Ollama or vLLM serving Foundation-Sec-8B-Reasoning.

---

## Conventions

- Type hints on all Python. Pydantic models for anything crossing a boundary.
- Every finding carries `source` and `confidence`. No unattributed data.
- Every risk score must render its own explanation. No opaque numbers.
- Scanner adapters implement the interface in `services/scanners/base.py`.
- Structured logging. Every scan and query logged with actor, target, authorization reference.
- Tests alongside new logic, especially in `services/graph` and `services/enrichment`.

---

## When generating code

**Do:** read `packages/schema` before touching data structures. Check `THIRD_PARTY.md` before adding a dependency. Keep changes scoped to one concern.

**Don't:** add dependencies without flagging it. Refactor beyond what was asked. Generate placeholder data that looks like real measurements — no metric in this project has been measured yet.

**Flag to the developer when:** a change touches the graph engine's determinism, a new dependency has an unclear licence, a request would need scanning outside the lab, or something contradicts `docs/00-scope.md`.

---

## Decisions

If a change diverges from the scope document — new dependency, scope change, different approach — remind the developer to log it in `DECISIONS.md`. The format is in that file.
