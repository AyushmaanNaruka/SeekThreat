# SeekThreat

**Centralized vulnerability detection and intelligent query interface.**

One platform that scans a target, understands what it found, works out how an attacker would
chain those weaknesses together, and lets you ask it questions in plain English.

SIH problem statement 25234 · National Technical Research Organisation · final year project.

---

## The problem

A defender today has eleven browser tabs open. Nmap output in one terminal, a Nuclei scan in
another, an OpenVAS report loading, a CVE database, an exploit database, and a spreadsheet
where they are trying to make sense of all of it.

Every one of those tools answers a narrow question well. None answers the question the
defender actually has: *given everything we just found, what breaks first, and what do I fix
on Monday morning?*

That gap is this project.

---

## What it does

| Layer | |
|---|---|
| **4. Conversation** | Chat assistant over our own data, answering with citations |
| **3. Reasoning** | A graph of assets and techniques. Real attack paths, and chokepoints |
| **2. Understanding** | One schema, deduplicated, enriched from many intelligence sources |
| **1. Collection** | Multiple scanners behind one web interface, no command line |

---

## The rule that makes it credible

**The language model never invents an attack path.** It only explains paths our graph engine
has already proved. Every edge traces back to a specific scan fact and a specific named rule.

The easy version of this project prompts an LLM with a list of vulnerabilities and asks it to
guess how an attacker might chain them. What comes back is fluent, confident, and completely
unverifiable. We can defend every claim our system makes.

---

## Status

Early development. **No metric in this repository has been measured yet.** Everything in the
scope documents is a target.

---

## Getting started

New to the repo? Read **[HOW-THIS-REPO-WORKS.md](./HOW-THIS-REPO-WORKS.md)** first — it takes
five minutes.

```bash
cp .env.example .env
docker compose -f infra/docker-compose.yml --profile core up -d
docker compose -f lab/docker-compose.yml up -d        # the test network
```

Never point a scan at anything outside `lab/` without an authorization record.

---

## Documentation

| | |
|---|---|
| [HOW-THIS-REPO-WORKS.md](./HOW-THIS-REPO-WORKS.md) | Start here |
| [docs/00-scope.md](./docs/00-scope.md) | What we are building, and how far |
| [docs/01-open-source-policy.md](./docs/01-open-source-policy.md) | Rules for using external code |
| [docs/02-architecture.md](./docs/02-architecture.md) | System design |
| [DECISIONS.md](./DECISIONS.md) | Why things changed |
| [THIRD_PARTY.md](./THIRD_PARTY.md) | What we have borrowed |
| [CLAUDE.md](./CLAUDE.md) | Rules for AI assistants |

---

## Legal

This is a defensive security tool. Scanning systems you do not own or have written permission
to test is illegal in most jurisdictions, including under India's IT Act. Every scan in this
platform requires an authorization record. Do not remove that check.
