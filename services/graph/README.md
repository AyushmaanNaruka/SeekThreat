# services/graph

**The heart of the project.** Deterministic attack path construction.

## The one rule

**The LLM never creates graph edges.**

Paths are built by the rules engine. Every edge carries the scan fact and the named rule that
produced it. The model narrates paths that already exist — it never infers them.

The easy version prompts an LLM with a vulnerability list and asks how an attacker might chain
them. What comes back is fluent, confident and unverifiable, and the first person who asks
"how do you know that path is real?" ends the conversation.

## Pipeline

```
Scan facts (hosts, services, versions, CVEs, reachability)
        |  deterministic
Asset-vulnerability graph
        |  deterministic — named rules
Candidate paths (every edge traceable)
        |  scored — EPSS x exploit availability x privilege delta
Ranked paths
        |  LLM here, and only here
Narration
```

## Knowledge substrate

BRON (MIT ALFA group) provides the static CVE -> CWE -> CAPEC -> ATT&CK graph. Ingested as
data, not vendored. See `DECISIONS.md` D-002.

Known coverage gap: roughly 62% CVE->CWE, 35% CWE->CAPEC, 16% CAPEC->ATT&CK before completion.
Our ML gap-filler classifier targets that gap and is measured against the published baseline.

## Chokepoints

Which single fix breaks the most paths. Fix that first, regardless of severity score.

This also powers remediation simulation — mark a vuln fixed, recompute the path set, show what
disappears. Best demo moment we have.

## Rules

1. Every `PathEdge` needs `rule_name` and `evidence`. No exceptions.
2. Rules are data, not code, where possible — so we can cite and extend them.
3. Test path construction thoroughly. Silent wrongness here is the worst failure mode.
