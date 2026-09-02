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
