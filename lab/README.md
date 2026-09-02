# lab/

Our deliberately vulnerable test network. **The single most important thing in this repo.**

Every accuracy, precision, recall and F1 number in the final report is measured against
`ground_truth.yaml`. Without this, we cannot measure anything at all.

## Why it exists

- Somewhere safe and legal to scan
- Ground truth — we know exactly what is wrong with each host
- Multi-hop topology so the attack path engine has real chains to find
- Reproducible: reset and re-run for consistent results

## Running it

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml down -v   # full reset
```

Network is isolated with no internet egress from targets.

## Ground truth

`ground_truth.yaml` records every host, service, version and expected CVE. **This file is the
denominator for every accuracy metric.** Update it whenever the lab changes — a stale ground
truth silently corrupts every number downstream.

## Target: 8–12 hosts, 3+ configurations

The topology needs deliberate multi-hop chains — a DMZ web host, an internal app tier, a
database segment. Paths where an SSRF reaches an internal service that has an RCE. Without
chained vulnerabilities the path engine has nothing to find and nothing to demo.

Three or more distinct configurations so we can show generalization, not overfitting to one
topology.

## Rule

**Never scan anything outside this lab without a written authorization record.** Unauthorized
scanning carries real legal exposure. A demo against someone else's domain is the one mistake
that could sink the project.
