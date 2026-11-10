# Demo runbook

How to run the January demo ("integration, demo, write-up: rehearsed demo plus a recorded
fallback", `docs/02-architecture.md`), and what to do when part of the stack is not
available.

There are two ways to run it:

- **Live mode.** Docker stack + lab + Ollama. A real authorized scan runs against the lab.
- **Fixture mode.** No Docker. The API runs natively on SQLite and
  `scripts/seed_fixture_demo.py` loads the recorded lab fixtures into it. This is the
  fallback, and the mode the recorded video is made from.

**Verification status.** Every command below exists in the repo, and each one is marked:

- **[verified 2026-11-10]**: run in this form on 2026-11-10, Windows 11, Python 3.12.10,
  Ollama 0.40.16, against the code this file was committed with.
- **[not run]**: the command exists in the repo but was not run on 2026-11-10. The Docker
  daemon was not running that day, so nothing that needs Docker was checked.
- **[unverified]**: a claim nobody has checked.

---

## 1. Prerequisites

| Need | For | Notes |
|---|---|---|
| Python 3.11+ and `pip install -r requirements-dev.txt` | API, seed script, tests | Verified on 3.12.10 |
| Node.js + npm | Dashboard (`apps/web`) | `npm install` needs network the first time. Node v22.22.2 was installed on 2026-11-10. The dashboard was **not** started that day [not run] |
| Docker Desktop with Compose v2 | Live mode only | Core profile needs `pgvector/pgvector:pg16`, `redis:7-alpine`, and the API image build. The lab needs every image in `lab/docker-compose.yml` (all pulled on 2026-10-15, D-042) |
| Ollama | Assistant (index, ask, narrate) in either mode | Native install, or the compose `model` profile |
| Models | Assistant | See below |

### Which model

- **Target (D-006):** Foundation-Sec-8B-Reasoning. **Not pulled, not measured, and no Ollama
  tag for it has been checked** [unverified]. Do not claim it in the demo.
- **What was actually measured:** `qwen2.5:7b`, with `nomic-embed-text` for embeddings, in
  `evals/results/assistant_eval_qwen2_5_7b.md`. These are the defaults in
  `apps/api/core/config.py` and `.env.example`. On 2026-11-10 the local Ollama reported
  `qwen2.5:7b`, `nomic-embed-text:latest` and `deepseek-r1:7b` pulled
  (`GET /assistant/status`) [verified 2026-11-10].

```bash
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
```

Changing `ASSISTANT_EMBED_MODEL` needs a re-index. Changing `ASSISTANT_MODEL` does not.

---

## 2. Before the demo (both modes)

Run the full-pipeline test. It drives the whole flow through the API in about five seconds,
with no Docker, network or model. **[verified 2026-11-10]**

```bash
python -m pytest -q -p no:cacheprovider tests/integration/test_full_pipeline.py
```

It creates the engagement and authorization, loads the fixtures, enriches findings, builds
the attack graph, checks every edge's evidence through
`scripts/verify_attack_graph_evidence.py`, runs remediation simulation, and asks and narrates
with `FakeModelClient`. It checks that every citation resolves to a stored record and that a
target outside the allowlist is refused. If it fails, fix that before the demo.

---

## 3. Live mode

[not run] on 2026-11-10: the Docker daemon was not running. These are the commands from
`README.md` and `docs/02-architecture.md`. On 2026-10-15 they were last driven end to end
from the dashboard against the lab (D-043, D-044).

### 3.1 Bring up the lab, then the stack

bash:

```bash
cp .env.example .env
docker compose -f lab/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core up -d --build
# Assistant: add the model profile and pull the models into the container once.
docker compose -f infra/docker-compose.yml --profile model up -d ollama
docker compose -f infra/docker-compose.yml exec ollama ollama pull qwen2.5:7b
docker compose -f infra/docker-compose.yml exec ollama ollama pull nomic-embed-text
# Once: fill the threat-intel mirrors (public feeds only; runs again daily at 02:00 UTC).
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core \
  exec enrichment-worker python -m services.enrichment.sync_feeds
```

PowerShell (same commands, one per line):

```powershell
Copy-Item .env.example .env
docker compose -f lab/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core up -d --build
docker compose -f infra/docker-compose.yml --profile model up -d ollama
docker compose -f infra/docker-compose.yml exec ollama ollama pull qwen2.5:7b
docker compose -f infra/docker-compose.yml exec ollama ollama pull nomic-embed-text
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core exec enrichment-worker python -m services.enrichment.sync_feeds
```

If Ollama already runs natively on the host (port 11434), skip the `model` profile. The
compose `api` service is pointed at `http://ollama:11434`, which a native Ollama does not
answer [unverified whether a native Ollama is reachable from the api container]. In that
case use the `model` profile, or fixture mode.

Check: `curl http://127.0.0.1:8000/health` returns `{"status":"ok"}`.
`curl http://127.0.0.1:8000/assistant/status` returns `reachable: true` and the pulled
models.

### 3.2 Dashboard

```bash
cd apps/web && npm install && npm run dev      # http://localhost:3000/dashboard
```

```powershell
Set-Location apps/web; npm install; npm run dev
```

### 3.3 Authorized scan

On the dashboard:

1. **Create Engagement.** Give it a name, a named authorizer, and the allowlist `172.20.0.0/16`
   (the whole lab). The authorization lasts 7 days.
2. **Launch New Scan.** Enter one host. Examples from `README.md`: Nuclei `172.20.1.10:80`
   (DVWA), Nmap `172.20.1.11` (Juice Shop), ssh-audit `172.20.2.50:2222` (bastion).
3. **Show the gate.** Enter a host outside the allowlist, such as `10.20.30.40`. The scope
   preview (`POST /scans/plan`) lists it as rejected, and `POST /scans` answers 403. The
   check runs in the API, not the UI:

   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/scans \
     -H "Content-Type: application/json" \
     -d '{"engagement_id":"<id>","scanner":"nmap","target":"10.20.30.40"}'      # 403
   ```

   ```powershell
   try { Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scans -ContentType "application/json" -Body (@{engagement_id="<id>"; scanner="nmap"; target="10.20.30.40"} | ConvertTo-Json) } catch { $_.Exception.Response.StatusCode.value__ }   # 403
   ```

   Both forms returned 403 against the fixture-mode API [verified 2026-11-10].

4. **Declare the topology** once for the engagement. Attack paths need it (D-046):

   ```bash
   docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml --profile core \
     exec api python -m apps.api.cli.load_topology --engagement-id <id> lab/topology.yaml
   ```

**Known gap for live mode.** Live lab scans have not yet produced findings that the
capability rules classify. The Nuclei `rce` (and OAST) templates are excluded for safety
(D-044, hard rule 4), so a live engagement can show findings and enrichment with **no attack
paths**. This was reported from the Layer 3 live run and is not in a committed result
[not re-checked 2026-11-10]. How the live lab gets classifiable findings is an open decision
(`PROGRESS.md`). Until it is settled, show Attack Paths, simulation and narration from
fixture mode.

### 3.4 The views

| Nav item | What to show |
|---|---|
| **Overview / Engagements / Scans** | Authorization banner (authorizer, scope, expiry). Scan status updates live. **⋮ → View observations** shows each fact with its source and confidence |
| **Findings** | Press **Refresh** after a scan completes. Expand a row: the ERS breakdown and the source of every fused field. Placeholder fields are labelled as estimates |
| **Attack Paths** | Zones, paths by goal, each with rank and a one-line rank explanation (D-047). Assumption steps are labelled. Click any edge to open its evidence |
| **Attack Paths → Chokepoints → Simulate fix** | Remediation simulation: how many paths disappear and which goals are no longer reachable |
| **Attack Paths → Narrate** | The model narrates one proven path. The narration is not written back into the graph |
| **Assistant** | **Index engagement**, then ask. Each answer shows its citations and the grounding check result |
| **Feed Health** | Mirror freshness (`GET /feeds/status`) |

Evidence check against the running API (read-only) [verified 2026-11-10 against the
fixture-mode API]:

```bash
python scripts/verify_attack_graph_evidence.py --engagement-id <id> --api http://127.0.0.1:8000
```

---

## 4. Fixture mode (no Docker)

Use this when Docker, the lab or the network is unavailable. The API runs natively on a
SQLite file. **[verified 2026-11-10]**: the bash commands in 4.1 and 4.2 were run as
written, and the seed step was also run from PowerShell. Port 8000 is what the dashboard
calls by default (`NEXT_PUBLIC_API_BASE_URL`).

**Say it on screen: these are fixture facts.** `lab_baseline.json` is a real capture (dvwa,
juiceshop). The other 8 hosts are synthetic: hand-authored tool output run through the real
parsers (`tests/fixtures/observations/README.md`).

### 4.1 Start the API

bash, from the repo root:

```bash
mkdir -p data
export DATABASE_URL=sqlite:///data/demo.db
python -m alembic upgrade head
python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

PowerShell, from the repo root:

```powershell
New-Item -ItemType Directory -Force data | Out-Null
$env:DATABASE_URL = "sqlite:///data/demo.db"
python -m alembic upgrade head
python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

`data/` is gitignored. Delete `data/demo.db` to start from scratch.

### 4.2 Seed it

In a second terminal, from the repo root, with the **same** `DATABASE_URL`:

```bash
export DATABASE_URL=sqlite:///data/demo.db
python -m scripts.seed_fixture_demo --index-assistant
```

```powershell
$env:DATABASE_URL = "sqlite:///data/demo.db"
python -m scripts.seed_fixture_demo --index-assistant
```

The seed script creates engagement `eng-lab-baseline` (authorizer `lab-operator`, allowlist
`172.20.0.0/16`, valid 7 days) through the API. It writes the fixture observations straight to
the database with `save_scan_result`, the call the scan worker makes. There is deliberately
no HTTP endpoint that accepts observations. It then enriches the findings, declares
`lab/topology.yaml` and reads the attack graph, all through the API. `--index-assistant`
builds the assistant index. Without Ollama that step reports a 503 and the rest still
succeeds. Re-running it is safe.

On 2026-11-10 it printed this, with no feed mirrors on disk:

```
engagement eng-lab-baseline (created)
observations written: 34 (fixtures; 8 of 10 hosts synthetic)
findings enriched: 5
topology: topology:sha256:71f641e935d9d577eded9eda
attack graph: 21 nodes, 39 edges, 22 paths, 4 chokepoints, truncated=False
assistant documents indexed: 66
```

Enrichment reads `ENRICHMENT_CACHE_DIR` (default `data/enrichment_cache`). If real mirrors
from an earlier `sync_feeds` run are there, findings carry real CVSS, EPSS and KEV values.
If they are not, findings show the labelled placeholder fields.

### 4.3 What works and what does not in fixture mode

- Works: Engagements, Findings, Attack Paths (evidence, ranking, chokepoints, **Simulate
  fix**, **Narrate**), Assistant (with Ollama running natively), Feed Health, the 403 gate
  demo.
- Does not work: **launching a scan.** There is no Redis, no worker and no lab. The gate
  check still runs first, so off-allowlist targets get 403. An allowed target would try to
  queue on a broker that is not there. Do not press Launch Scan in fixture mode.
- **Recent Scans is empty.** The seed script records no scan rows, because no scan ran.
  Observations are reachable through the evidence links in Findings and Attack Paths.
- Without Ollama the Assistant view and Narrate show the 503 message, which tells you how to
  start Ollama.

### 4.4 Remediation simulation and the assistant from the command line

Simulation on the top chokepoint (spring-gateway, CVE-2022-22947, finding
`fnd-103129260b2f1a5740feabc1`) gave `22 -> 11` paths with `exec:spring-gateway` no longer
reachable [verified 2026-11-10, fixture mode, no mirrors]:

```bash
curl -s -X POST http://127.0.0.1:8000/engagements/eng-lab-baseline/attack-graph/simulate \
  -H "Content-Type: application/json" -d '{"fixed_finding_ids":["<finding_id>"]}'
curl -s -X POST http://127.0.0.1:8000/engagements/eng-lab-baseline/assistant/ask \
  -H "Content-Type: application/json" -d '{"question":"Which hosts are affected by CVE-2022-22947?"}'
```

```powershell
$g = Invoke-RestMethod http://127.0.0.1:8000/engagements/eng-lab-baseline/attack-graph
$top = ($g.chokepoints | Sort-Object rank | Select-Object -First 1).finding_id
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/engagements/eng-lab-baseline/attack-graph/simulate -ContentType "application/json" -Body (@{ fixed_finding_ids = @($top) } | ConvertTo-Json)
```

With mirrors present the chokepoint order can differ, because ranking reads stored ERS
(D-047). Read the finding id from the graph rather than hard-coding it.

**What to expect from a real model.** On 2026-11-10, `qwen2.5:7b` answered the CVE question
correctly in substance. It cited an id the documents never carried
(`attack_path:path:...`), so the grounding check listed that citation as invalid and four
entities as unsupported. That is the check doing its job: it is shown, not hidden. Say so
if it happens on stage. The measured rates are in
`evals/results/assistant_eval_qwen2_5_7b.md` (fixture-based, entity-level faithfulness
proxy, not RAGAS).

---

## 5. Recorded fallback

1. **Before the day:** record the fixture-mode walkthrough (sections 4.1 to 4.4, then each
   view in 3.4) as a screen capture, with the assistant and narration answered by
   `qwen2.5:7b`. Keep the "fixture facts" caption visible. The screen-capture tool is not
   chosen [unverified].
2. **On the day, in order of preference:**
   1. Live mode, if `GET /health` and `GET /assistant/status` both answer and the lab is up.
      Show the authorized scan, Findings and enrichment live, then switch to the fixture
      engagement for Attack Paths (see the known gap in 3.3).
   2. Fixture mode on the laptop, if Docker or the lab is unavailable.
   3. Fixture mode without Ollama, if the model server is unavailable. Everything except
      the Assistant view and Narrate works. Play the recorded assistant segment for those.
   4. The full recording, if the laptop cannot run the API.
3. Whatever runs, run `tests/integration/test_full_pipeline.py` first (section 2). It takes
   about five seconds and proves the code on the machine still integrates.

---

## 6. Not verified, in one place

- Everything in section 3 that needs Docker (stack, lab, compose `exec`, `load_topology` in
  the container). Last driven end to end on 2026-10-15 (D-043, D-044), before Layers 3 and 4
  existed in the image.
- The dashboard (`npm run dev`) against either mode on 2026-11-10.
- A native Ollama reached from the compose `api` container.
- Any Ollama tag for Foundation-Sec-8B-Reasoning.
- The screen-capture tool for the recording.
