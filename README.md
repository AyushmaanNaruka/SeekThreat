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

# 1. The lab first: the worker attaches to its networks.
docker compose -f lab/docker-compose.yml up -d

# 2. Backend (API :8000, scan worker, enrichment worker, scheduler), attached to the lab.
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core up -d --build

# 3. Once: fill the threat-intel mirrors (KEV, EPSS, ExploitDB, Metasploit). Downloads public
#    feeds only; runs again daily at 02:00 UTC.
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core \
  exec enrichment-worker python -m services.enrichment.sync_feeds

# 4. Frontend.
cd apps/web && npm install && npm run dev            # http://localhost:3000/dashboard
```

Then, on the dashboard:

1. **Create Engagement:** name, a named authorizer, and the allowlist. `172.20.0.0/16` is the
   whole lab. The authorization is valid for 7 days.
2. **Launch New Scan:** pick a scanner, enter **one host** (ranges are refused by the gate),
   and add a port where the service is not on the default port. Examples:

   | Scanner | Target | What it is |
   |---|---|---|
   | Nmap | `172.20.1.11` | Juice Shop host |
   | Nuclei | `172.20.1.10:80` | DVWA |
   | Nikto | `172.20.1.11:3000` | Juice Shop web server |
   | ssh-audit | `172.20.2.50:2222` | Bastion SSH |

3. **Recent Scans:** status updates live. **⋮ → View observations** shows what each scanner
   recorded, with source and confidence.
4. **Findings:** each scan's vulnerability observations become findings and are enriched
   automatically (DECISIONS.md D-044). Click **Refresh** once a scan completes, then expand a
   row for the risk-score breakdown and the source of every field.

Never point a scan at anything outside `lab/` without an authorization record.

---

## Documentation

| | |
|---|---|
| [HOW-THIS-REPO-WORKS.md](./HOW-THIS-REPO-WORKS.md) | Start here |
| [PROGRESS.md](./PROGRESS.md) | What is done, what is left, what is blocked |
| [docs/00-scope.md](./docs/00-scope.md) | What we are building, and how far |
| [docs/01-open-source-policy.md](./docs/01-open-source-policy.md) | Rules for using external code |
| [docs/02-architecture.md](./docs/02-architecture.md) | System design |
| [docs/03-dashboard-spec.md](./docs/03-dashboard-spec.md) | What the dashboard contains, and in what order |
| [DECISIONS.md](./DECISIONS.md) | Why things changed |
| [THIRD_PARTY.md](./THIRD_PARTY.md) | What we have borrowed |
| [CLAUDE.md](./CLAUDE.md) | Rules for AI assistants |

---

## Legal

This is a defensive security tool. Scanning systems you do not own or have written permission
to test is illegal in most jurisdictions, including under India's IT Act. Every scan in this
platform requires an authorization record. Do not remove that check.
