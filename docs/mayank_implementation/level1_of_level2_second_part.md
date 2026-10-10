# Level 1 of Layer 2 Second Part — Walkthrough

**Level title:** Decisions & ERS Analysis (D-008 resolution)
**Branch:** `mayank_level2_second`
**Date completed:** 2026-10-05
**PR scope:** `DECISIONS.md` + `services/enrichment/ers.py` docstring + formatting fixes. No runtime code logic changed.

---

## What this level was

Level 1 is the prerequisite for everything else in Layer 2 second part. Before writing a single line of implementation, six open design questions needed settled answers logged in `DECISIONS.md`. The risks without doing this first:

- Writing the feed sync job while the KEV circularity is unresolved → would embed a wrong validation methodology.
- Writing the graph layer (Layer 3) without knowing where ERS computation lives → module import violations.
- Presenting ERS weights in the viva without a documented rationale → "why 0.40/0.35/0.25?" with no answer.

No runtime code changed. CI must stay green before this level is considered done.

---

## Pre-flight fixes done first

Before any design work, two files had mixed CRLF/LF line endings that caused `ruff format --check` to report 2 files would be reformatted:

- [`apps/api/routers/__init__.py`](file:///e:/SeekThreat/SeekThreat/apps/api/routers/__init__.py)
- [`apps/api/tasks/__init__.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/__init__.py)

Fixed by running `python -m ruff format` on both files. After fix: `ruff format --check` reports `144 files already formatted`.

---

## Decisions logged

Six new decisions were added to [`DECISIONS.md`](file:///e:/SeekThreat/SeekThreat/DECISIONS.md) (newest first, D-032 down to D-027):

---

### D-032 — /findings API: engagement_id required on all calls

**Problem:** The `/findings` router (from PR #17 / commit `575bc7b`) now requires `engagement_id` on every call. This was not previously documented as a breaking contract change.

**Decision:** `GET /findings/{finding_id}?engagement_id=...` and `POST /findings/enrich/batch` with `engagement_id` in body are the canonical API shapes. Both validated against an existing engagement row.

**Why it matters:** CLAUDE.md requires every query to be audit-logged with an authorization reference. `finding_id` alone is not unique (see D-031) — the engagement scope is required to resolve the row. Callers that omit it get a 422. The frontend (Level 5) must pass it through.

---

### D-031 — Composite PK (engagement_id, finding_id) on enriched_findings

**Problem:** Why does `enriched_findings` have a composite PK instead of just `finding_id`?

**Decision:** The same `finding_id` string can legitimately appear in two different engagements with different enriched results. A global PK would either reject valid re-enrichment or corrupt cross-engagement data. The composite key makes engagement scoping structural.

**Why it matters:** Upsert conflict targets must include `engagement_id`. The `EnrichedFindingRepository` (from `575bc7b`) already does this correctly — this decision documents why.

---

### D-030 — in_kev=None means "unknown", not "confirmed absent"

**Problem:** When the KEV mirror is not loaded, `in_kev` could be interpreted as `False` (not in KEV). This is wrong.

**Decision:** Missing mirror → `in_kev=None` with `Source.DERIVED` / `Confidence.LOW`. The ERS KEV component explains "unknown" and applies zero boost. It never asserts a confident negative.

**Why it matters:** In a viva: "how do you know this CVE is not actively exploited?" — the honest answer when the mirror is absent is "we don't know", not "no". The `_kev_component` function in `ers.py` already handles this correctly (the `attr is None` branch). This decision documents the reasoning behind that branch.

---

### D-029 — Multiplicative path score does not violate the EPSS × CVSS ban

**Problem:** `services/graph/README.md` shows `EPSS × exploit_availability × privilege_delta`. This looks like it multiplies EPSS. Rule 3 says "Never multiply EPSS by CVSS."

**Decision:** The rule bans `EPSS × CVSS` specifically, and the path score does not multiply by CVSS, so it is within the letter of the rule. It is **not** a conditional probability decomposition, though. `privilege_delta` is not a probability, and EPSS already uses exploit-code availability among its inputs, so multiplying by `exploit_availability` risks double-counting. D-029 marks this as open and a viva risk.

**Why it matters:** The graph owner must justify the product as a heuristic (and handle the double-counting) or switch formulation before Layer 3 path scoring lands.

---

### D-028 — ERS lives in enrichment (Layer 2), graph consumes it (Layer 3)

**Problem:** `docs/02-architecture.md` line 72 places "ERS scoring, chokepoint analysis" under the graph layer. But ERS is computed in `services/enrichment/ers.py`.

**Decision:** ERS *computation* is in enrichment (it depends on CVSS/EPSS/KEV — enrichment data). ERS *consumption* for path ranking is in the graph layer. This moves ERS ownership from `services/graph` to `services/enrichment` and **diverges from `docs/00-scope.md`**, which lists ERS under Layer 3. D-028 records the divergence. The `docs/02-architecture.md` module map and pipeline comment were updated to match.

**Why it matters:** If left unresolved, a future developer might move `ers.py` into `services/graph/`, inverting the module dependency (graph cannot import enrichment per the module map in `docs/02-architecture.md`).

---

### D-027 — D-008 addendum: weight rationale, sensitivity analysis, KEV circularity resolution

This is the main decision of Level 1. Three sub-parts:

#### Part 1: Weight rationale (documenting why 0.40 / 0.35 / 0.25)

| Component | Weight | Why |
|-----------|--------|-----|
| CVSS | 0.40 | Most established severity descriptor; should dominate but not overwhelm exploitation signals |
| EPSS | 0.35 | 30-day exploitation probability; near-parity with CVSS is intentional — "will this be exploited?" is almost as important as "how bad if it is?" |
| KEV | 0.25 | Binary confirmed-exploitation boost; large enough to reorder borderline cases, not large enough to dominate low-severity findings |

Formula: `ERS = cvss × 0.40 + (epss × 10) × 0.35 + kev_flag × 10 × 0.25`

All component values on [0, 10] scale before weighting. Final score in [0, 10].

#### Part 2: Sensitivity analysis (3 weight profiles × 5 CVEs)

Using **synthetic fixture values** from `tests/fixtures/enrichment/`:

| CVE | CVSS | EPSS | KEV |
|-----|------|------|-----|
| CVE-2021-44228 (Log4Shell) | 10.0 | 0.97543 | Yes |
| CVE-2022-22947 (Spring Gateway) | 9.8 | 0.89510 | Yes |
| CVE-2024-23897 (Jenkins CLI) | 9.8 | 0.78120 | Yes |
| CVE-2021-41773 (Apache traversal) | 7.5 | 0.94120 | Yes |
| CVE-2020-7699 (express-fileupload) | 7.3 | 0.14250 | No |

Computed ERS under three profiles:

| CVE | Severity-heavy (0.60/0.25/0.15) | Balanced (0.40/0.35/0.25) | Exploitation-heavy (0.25/0.50/0.25) |
|-----|--------------------------------|--------------------------|--------------------------------------|
| Log4Shell | 9.94 | 9.91 | 9.88 |
| Spring Gateway | 9.62 | 9.55 | 9.43 |
| Jenkins CLI | 9.33 | 9.15 | 8.86 |
| Apache traversal | 8.35 | 8.79 | 9.08 |
| express-fileupload | 4.74 | 3.42 | 2.54 |

**Result (corrected): the ranking is not fully stable.** Under exploitation-heavy weights, Apache traversal (9.08) overtakes Jenkins CLI (8.86). Ranks #1, #2 and #5 hold across all three profiles; #3 and #4 swap. Two synthetic probe cases (high CVSS / low EPSS vs low CVSS / high EPSS, both non-KEV) also flip order between profiles. The numbers come from `python evals/ers_sensitivity.py`, and D-027 has the full table.

> These scores are from **synthetic fixture data**, not real measurements. With real mirror data, both the scores and the orderings may differ.

#### Part 3: KEV circularity resolution

D-008 said KEV "validates" the ranking. With KEV as a 25% input, using it to also validate is circular.

**Resolution chosen (option a):** KEV stays as an input. Validation uses ExploitDB/Metasploit corroboration. This is only **partly** independent of ERS: EPSS (35% of ERS) uses exploit-code availability among its inputs, so a check against ExploitDB/Metasploit partly re-measures an input. The validation has not been run. Level 4 measured coverage only, so this is an open follow-up (D-027).

D-008's "not as a training target" clause unchanged. Only the "validates the ranking" claim is updated to reflect that validation uses a different signal.

---

## Code changes made

### 1. [`services/enrichment/ers.py`](file:///e:/SeekThreat/SeekThreat/services/enrichment/ers.py) — docstring update

- Removed "provisional" qualifier from weight comments.
- Updated module docstring: references D-027 for rationale, correctly describes KEV as an *input* not a *validator*.
- Updated inline weight comments to be precise (EPSS v4, KEV as input).

No logic, no weights, no function signatures changed.

### 2. [`apps/api/routers/__init__.py`](file:///e:/SeekThreat/SeekThreat/apps/api/routers/__init__.py) — CRLF fix

Mixed CRLF/LF line ending normalized. `ruff format` applied.

### 3. [`apps/api/tasks/__init__.py`](file:///e:/SeekThreat/SeekThreat/apps/api/tasks/__init__.py) — CRLF fix

Same CRLF normalization. `ruff format` applied.

---

## CI results

| Check | Result |
|-------|--------|
| `ruff check` | ✅ All checks passed |
| `ruff format --check` | ✅ 144 files already formatted |
| `mypy packages services apps` | ✅ 0 errors (local sqlalchemy 2.0.35 vs CI's 2.0.54 emits a pre-existing `no-untyped-call` — not introduced by this level, documented quirk) |
| `pytest tests` | ✅ 470 passed, 3 skipped |

---

## Level 1 checklist — final status

- [x] D-008 weight rationale written (D-027)
- [x] Sensitivity analysis table written (D-027, 3 profiles × 5 CVEs; stability claim corrected, reproducible via `evals/ers_sensitivity.py`)
- [x] KEV circularity addressed (D-027, option a — ExploitDB/Metasploit as validator; partly circular via EPSS, validation not yet run)
- [x] ERS placement reconciled (D-028 — computation in enrichment, consumption in graph)
- [ ] Multiplicative path score reconciled (D-029 — within the letter of the EPSS × CVSS ban; soundness open, viva risk)
- [x] Composite PK decision logged (D-031)
- [x] in_kev=None semantics logged (D-030)
- [x] /findings API contract logged (D-032)
- [x] No runtime logic changed
- [x] CI green

---

## What Level 2 picks up

Level 2 (Feed Sync Job) now has clear answers to questions it would otherwise need to discover mid-implementation:

- `ENRICHMENT_CACHE_DIR` is the target directory for all mirror files.
- `MIRROR_FILENAMES` (in `sync.py`) defines the exact filenames — the sync job must use these.
- Network is only allowed in the sync job. `test_offline_mirror.py` is the guard.
- KEV mirror absence → `in_kev=None` (D-030) — the sync job's success/failure must be checkable via `is_loaded`.

---

_Walkthrough written: 2026-10-05_
