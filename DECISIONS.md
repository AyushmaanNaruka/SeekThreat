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

### D-043 — Add Nikto and ssh-audit adapters, restricted to non-destructive checks
**Date:** 2026-10-12
**Decided by:** Ayushmaan
**Type:** Addition
**Status:** Active

**Decision**
Add two scanner adapters: Nikto (web server misconfiguration and outdated-software checks) and
ssh-audit (SSH banner, version and algorithm audit). Both are invoked as subprocesses and their
JSON output parsed; neither tool's source is vendored. Nikto runs with an include-list of
`-Tuning 123abde` and an explicit `-Plugins` include-list; ssh-audit runs with `--skip-rate-test`.

**Why**
The lab is mostly HTTP services plus one SSH bastion that pivots into the data segment. Nmap and
Nuclei barely cover SSH configuration, and Nikto is the first web scanner on the planned list in
`services/scanners/README.md`. testssl.sh and sslyze were considered and rejected for now: the
lab exposes no TLS service, so they would produce nothing measurable.

Safety (hard rule 4): Nikto tuning categories 0 (upload), 4 (injection), 5/7 (remote file
retrieval), 6 (DoS), 8 (command execution), 9 (SQLi) and c (remote include) are excluded, and
plugins that act regardless of tuning (`put_del_test`, `auth`, `shellshock`, `strutshock`,
`dictionary`, `apacheusers`) are not enabled. ssh-audit only performs handshakes; its DHEat
rate test opens a burst of ~38 connections, which is a DoS probe, so it is skipped.

Licences: Nikto is GPL-2.0 — invoked only, never copied (rule 3). ssh-audit is MIT (LICENSE
read 2026-10-12).

**Impact on plan**
Two more `Observation` producers. Findings worth knowing about downstream:
- ssh-audit 3.x no longer reports CVEs (`cves` is always empty). SSH CVE matching must come
  from enrichment off the `service_version` observation, not from the scanner.
- Nikto's JSON report carries no timestamp and usually an empty `banner`, so it rarely
  produces a `service_version`; it is mainly a `vuln_candidate` source.
- Both emit endpoints in nmap's `<ip>:<port>/tcp` spelling so findings join to port facts.
- `apps/api/Dockerfile` installs both, pinned to the code the fixtures were captured with:
  Nikto at upstream master commit `464da66` (the `ghcr.io/sullo/nikto` image's revision label;
  archive sha256-verified, `program/` on PATH with `perl` + `libnet-ssleay-perl`) and ssh-audit
  3.9.0 (wheel, `pip --require-hashes`). Nikto is pinned to a commit, not the `2.5.0` release
  tag, because that tag's JSON report plugin is broken: it calls `JSON->new` after loading only
  `JSON::PP` (exit 255 on the first finding) and double-quotes every `msg` (invalid JSON).
- Verified live on 2026-10-15: image built; engagement `eng-d038-live` (allowlist
  172.20.1.10, 172.20.2.50) dispatched through `POST /scans` to the lab-attached worker. Nikto
  vs DVWA `172.20.1.10:80` → completed, 15 `vuln_candidate`; ssh-audit vs bastion
  `172.20.2.50:2222` → completed, 1 `service_version` + 19 `vuln_candidate`. An off-allowlist
  target (172.20.1.11) was refused with 403. The bastion ran `version-8.3_p1-r0`, because
  the lab's `8.2p1` tag does not exist (D-042).
- Review fix (2026-10-15), touching `packages/schema`: `target_matches` now refuses any target
  containing `%`. Python's `ipaddress` accepts free text after `%` as an IPv6 scope id and
  ignores it for network membership, so `fd00::1%x,10.9.9.9` matched an `fd00::/8` allowlist.
  Nikto splits `-host` on commas (and nuclei's `-u` takes lists), so the scan would also have
  reached `10.9.9.9`. The Nikto and nuclei adapters reject `%` too, as ssh-audit already did.
  This only narrows what the gate permits; no valid hostname contains `%`.
- This entry was first numbered D-038, which collided with the ERS corroboration entry
  committed earlier; renumbered to D-043.

**Cost if we're wrong**
Low. Each adapter is self-contained (one adapter, one parser, one dispatch branch). Widening
Nikto's tuning or plugin lists is a scope change and needs its own entry.

---

### D-042 — Two lab image tags never existed: bastion → OpenSSH 8.3p1, internal-wiki → Confluence 7.13.6
**Date:** 2026-10-15
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
`lab/docker-compose.yml` pins `bastion-ssh` to `linuxserver/openssh-server:version-8.3_p1-r0`
instead of `:8.2p1`. `lab/ground_truth.yaml` records the bastion's OpenSSH version as `8.3p1`.
The synthetic `tests/fixtures/nmap/lab_internal.xml` was edited to match, and
`tests/fixtures/observations/lab_internal.json` was regenerated from it with
`scripts/build_observation_fixtures.py`. The walkthrough table in
`docs/mayank_implementation/task_6_level_1_walkthrough.md` was updated too.

**Why**
`linuxserver/openssh-server:8.2p1` returns 404 from Docker Hub (checked 2026-10-15), and no
linuxserver tag carries OpenSSH 8.2p1. The lab could not start, and the bastion that pivots
into the data segment was unscannable. `version-8.3_p1-r0` is the nearest published version.
It is also the server the ssh-audit fixtures were captured from (D-043).

**Impact on plan**
The expected CVE is unchanged: CVE-2020-15778 affects OpenSSH through 8.3p1, so the bastion's
`expected_cves` entry and the attack chain through it still hold. Verified live: ssh-audit
against the bastion reports banner `SSH-2.0-OpenSSH_8.3`. Note that ssh-audit's
`service_version` is `8.3` (from the banner); the `p1` suffix comes only from nmap `-sV`.
The bastion is still covered synthetically in `lab_internal.json` until a real nmap capture
replaces it, which is now possible.

**internal-wiki (same problem, same fix)**
`vulhub/confluence:7.18.0` is also absent from Docker Hub (found by a full
`docker compose pull` on 2026-10-15; vulhub publishes only 6.10.2, 6.11.2, 7.4.10, 7.13.6, 8.5.1
and 8.5.3). The compose file, ground truth, `lab_internal.xml`/`.json` and the walkthrough now
say `7.13.6`. CVE-2022-26134 affects 7.13.0–7.13.6 (fixed in 7.13.7), so `expected_cves` is
unchanged. 7.13.6 is the image vulhub's own CVE-2022-26134 environment uses. As with any vulhub
Confluence image, the setup wizard (database and trial licence) must be completed before
the application is fully live; that was true of the intended 7.18.0 tag too.

After both fixes, every image in `lab/docker-compose.yml` pulls.

**Cost if we're wrong**
Low. Two image tags, two ground-truth fields, one regenerated fixture. Any eval run made
before this change measured against a bastion that could not exist, so it should be re-run
rather than compared.

---

### D-041 — Post-scan sync hardening: engagement-scoped re-enrichment, per-mirror file lock, negative cache, dedicated enrichment worker
**Date:** 2026-10-12
**Decided by:** Ayushmaan (review of PR #19)
**Type:** Divergence
**Status:** Active — amends D-036

**Decision**
Post-scan enrichment re-enriches only the scan's own engagement's findings (keyset-paged, 500 rows), and only for CVE IDs that received new records in that run. Per-CVE gaps are computed per source (CVE.org, Vulnrichment, EUVD, NVD) rather than "known to any mirror". Targeted read-merge-write of a mirror runs under a cross-process lock file (`.<mirror>.lock`, `os.open(O_CREAT|O_EXCL)`, pid/host/token inside, 300 s mtime staleness, bounded wait with back-off), never held across network I/O. Upstream not-found results are recorded in `<name>.notfound.json` (`checked_at`) and not re-fetched for 7 days; the mirror format readers parse is unchanged. Each post-scan run sends at most `POST_SCAN_MAX_CVES` (200) distinct CVEs upstream under a time budget inside a Celery soft limit (`POST_SCAN_SOFT_TIME_LIMIT_SECONDS`, 1800 s; hard limit +120 s); the remainder is deferred to the daily beat sync, which now also reads CVE IDs from VULN_CANDIDATE observations. The `enrichment` queue gets its own compose service (`enrichment-worker`, concurrency 1); the scan worker consumes only `scans`. Post-scan audit events carry the scan authorization's `authorized_by` as actor, `engagement:<id>/scan:<id>` as target, and the CVE IDs sent upstream plus per-source results; enqueue failures are audited, and dispatch uses `apply_async(retry=False)` after `scan.completed` is audited.

**Why**
Review of PR #19 found that a scan in engagement A rewrote engagement B's enriched rows with no authorization reference (D-031/D-032 violation); that concurrent post-scan and beat syncs could drop each other's merged records; that a CVE present in CVE.org was never fetched from NVD/Vulnrichment/EUVD; that unbounded post-scan runs on the shared prefork worker could starve scans; and that a down broker could delay scan completion through kombu publish retries. Rejected: fcntl/msvcrt locks (not portable; do not cover containers on a shared volume uniformly); a Redis lock (couples mirror writes to broker availability and the CLI to Redis); an in-mirror negative marker (would change the reader format).

**Impact on plan**
New settings `POST_SCAN_MAX_CVES`, `POST_SCAN_SOFT_TIME_LIMIT_SECONDS`. One more compose service. A CVE newly seen in a large scan may wait for the next beat run (02:00 UTC) if it falls outside the per-run cap or time budget. A CVE that upstream reports as not found is retried after 7 days rather than daily.

**Cost if we're wrong**
Low. The lock, the negative cache and the cap are local to `services/enrichment/sources/sync.py` / `locking.py` and the post-scan task; removing the sidecar file restores the old re-fetch behaviour, and the cap/time limits are configuration.

---

### D-040 — Finding Ingestion Contract between Track 1 Normalization and Layer 2 Enrichment
**Date:** 2026-10-11
**Decided by:** Mayank (Layer 2 owner); sign-off pending from Utkarsh (Track 1 owner)
**Type:** Addition
**Status:** Active

**Decision**
We establish and enforce a formal schema and interface contract between Track 1 (`services/normalize`) and Layer 2 (`services/enrichment`):
1. **`asset_id` standardization (contract — not yet enforced by a model validator; enforced when Track 1 lands):** Normalized to canonical address prefixes (`host:<canonical_ip>`, `host:<canonical_fqdn>`, or `host:mac:<lowercase_mac>`) following deterministic IPv4 > IPv6 > MAC > FQDN precedence. IPv6 is written unbracketed, compressed and lowercase (`host:2001:db8::10`), matching nmap HOST_UP subjects; FQDN and MAC are lowercase. Decoupled fixture prefixes (`asset-*`, `ast-*`) remain valid for offline unit testing.
2. **`cve_ids` canonicalization & segregation:** All entries must fully match `CVE-[0-9]{4}-[0-9]{4,7}` (ASCII digits only, `re.ASCII` + `fullmatch`), are automatically uppercased, and deduplicated in order. Non-CVE identifiers (e.g. GHSA, CWE, scanner-specific template IDs) must never be passed in `cve_ids` and belong in `Observation.attributes` or finding metadata.
3. **Observation provenance requirement:** Every `Finding` must link to at least one valid, stored `observation_id` under the same `engagement_id`, enforced at model construction by Pydantic (`Finding._must_trace_to_observations`) and at the API boundary by `_verify_findings_provenance()`.

**Why**
Deduplication and normalization in Track 1 produce `Finding` models consumed by Layer 2's enrichment fusion and ERS scoring. Without this agreement, inconsistent asset identifiers prevent joining Nmap port facts with Nuclei vulnerability candidates, lowercase or malformed CVE IDs cause cache misses against per-CVE local mirrors, non-CVE identifiers pollute mirror lookups, and untraced findings break the core architectural invariant that all derived data traces back to immutable observations.

**Impact on plan**
Unblocks Track 1 (`services/normalize`) implementation while protecting Layer 2 (`services/enrichment`) from schema discrepancies. Formally documents the boundary in `docs/02-architecture.md`, `packages/schema/README.md`, and `packages/schema/models/finding.py`.

**Cost if we're wrong**
Low. The contract aligns directly with the existing Pydantic validation and API verification paths already implemented and covered by unit tests.

---

### D-039 — Proposed graph path-scoring formula to replace the multiplicative heuristic
**Date:** 2026-10-11 (revised 2026-10-12 after PR #19 review)
**Decided by:** Proposed by Mayank; pending sign-off by Ayushmaan (graph owner)
**Type:** Reversal
**Status:** Proposed

**Decision**
Proposal to retire the multiplicative path score (`EPSS × exploit_availability × privilege_delta`) that D-029 flagged as a viva risk, and replace it with two separately defined tiers. The proposal is not settled. D-029 stays Active until the graph owner signs off.

**Scope of cost (Hard Rule 1).** Neither tier creates, removes or infers an edge or a path. The rules engine in `services/graph` first enumerates candidate paths deterministically and exhaustively from observed scan facts and named rules. Tier 1 cost and Tier 2 risk are then used **only to rank that already-enumerated path set**. No search heuristic may prune paths based on cost before enumeration finishes. Ties are broken deterministically: equal cost (or risk) is ordered by path length ascending, then by the lexicographic sequence of edge IDs. The exact edge-ID format is to be fixed when `PathEdge` IDs are defined.

1. **Tier 1 — edge cost (heuristic):**
   $\text{Cost}(e) = -\ln(\max(\text{EPSS}_e, 0.001)) + \text{Barrier}(\text{privilege\_delta}_e)$, and path cost $= \sum_{e} \text{Cost}(e)$.
   - **This is still multiplicative in EPSS.** $\sum_e -\ln(\text{EPSS}_e) = -\ln \prod_e \text{EPSS}_e$, so ranking by the EPSS part of the cost is the same as ranking by the product of EPSS values along the path. The log form changes the arithmetic, not the model.
   - **EPSS is not a per-hop success probability.** EPSS is a CVE-scoped estimate of the probability of exploitation activity in the wild in the next 30 days. It says nothing about whether this attacker succeeds at this hop on this host. Treating it as a hop probability, and multiplying across hops, also assumes the hops are independent. That assumption is stated here, not justified.
   - The result is a **heuristic ranking cost**, not a likelihood, and must not be called "statistically rigorous" or "statistically valid".
   - **The 0.001 floor** maps every EPSS at or below 0.001 to the same cost ($-\ln 0.001 \approx 6.91$), so low-EPSS edges are indistinguishable from each other. Whether that is acceptable, or whether the floor should be lower, is open.
   - **Barrier values (provisional, unjustified):** `0.0` for no privilege change, `1.5` for user-level traversal, `3.0` for kernel/root escalation (taken from `docs/mayank_implementation/task5_level2_work.md`). No rationale or sensitivity analysis exists for these numbers, or for their scale relative to the $-\ln$ EPSS term. They must not be quoted as calibrated.
   - **Open question: edges without a CVE or without EPSS.** Many edges (credential reuse, network reachability, misconfiguration) carry no CVE, and some CVEs have no EPSS. Their cost is **undefined** in this proposal. Defaulting them to the floor cost or to zero would silently decide rankings. This must be settled before Layer 3 ranking code lands.

2. **Tier 2 — path risk (heuristic composite of stored ERS):**
   $$R(\text{path}) = 0.50 \cdot \max_{e \in \text{path}}(\text{ERS}_e) + 0.30 \cdot C_{\text{target}} + 0.20 \cdot \overline{\text{ERS}}_{\text{path}}$$
   with $C_{\text{target}} \in [0, 10]$ the target criticality, reading the stored `EnrichedFinding.ers.value` (D-028).
   - **Max ERS is the most-exposed hop, not the "weakest link".** In chain terms the weakest link limits the chain, so it would be the *hardest* hop (min). $\max(\text{ERS})$ rewards a path for its single riskiest vulnerability, whatever the other hops cost.
   - **Tier 1 and Tier 2 can disagree.** A path with one KEV-listed, high-ERS hop and one very low-EPSS hop scores high on Tier 2 but has a high Tier 1 cost. Which tier drives the displayed order, and how the disagreement is shown to the analyst, is open.
   - **Weights 0.50 / 0.30 / 0.20 are open.** No rationale or sensitivity analysis has been written. D-027 required both for ERS weights, and the same applies here before these weights are used.

**Why**
D-029 found three problems with the multiplicative score: it multiplies a probability by an ordinal (`privilege_delta`), it double-counts exploit availability (EPSS already uses it), and a zero `exploit_availability` zeroes the whole path. This proposal removes the explicit `exploit_availability` factor and keeps `privilege_delta` as an additive barrier instead of a multiplier. It does **not** remove the multiplication of EPSS across hops (see Tier 1), and it adds its own unjustified constants. Rejected: keeping the D-029 product unchanged (the zero-factor and double-counting problems remain).

**Impact on plan**
`services/graph/README.md` describes this as a proposal. Before Layer 3 ranking is implemented (November), the graph owner must sign off or amend, and these items must be closed: barrier rationale and sensitivity, the 0.001 floor, cost for edges without CVE/EPSS, Tier 2 weight rationale and sensitivity, and how Tier 1/Tier 2 disagreement is resolved. Path enumeration is unaffected (Hard Rule 1).

**Cost if we're wrong**
Moderate. No graph code exists yet, so changing the formula is cheap now. The real cost is credibility and correctness: if the heuristic is presented as a probability, or if the open constants are quoted as calibrated, analysts get confident orderings that nothing supports, and the viva exposes it. If cost were ever used to prune enumeration, it would also break the determinism guarantee of Hard Rule 1.

---

### D-038 — ERS exploit-catalogue corroboration: smoke-level only, with EPSS circularity disclosed
**Date:** 2026-10-11 (revised 2026-10-12 after PR #19 review)
**Decided by:** Mayank
**Type:** Addition
**Status:** Active

**Decision**
`evals/ers_validation.py` ranks the golden CVEs by ERS under four weight profiles and checks the share of the top k that have an ExploitDB or Metasploit catalogue entry. This is **smoke-level corroboration, not validation**. The target is not independent of ERS. EPSS (35% of ERS) uses exploit-code availability among its features, **including both ExploitDB entries and Metasploit modules** (D-029). Neither catalogue is an independent check. The earlier "independent Metasploit corroboration" mitigation is withdrawn.

**Result of the one real run (2026-10-11, pre-review harness)**
- The EPSS marginal gain at top 5 (balanced minus no-EPSS control) is **0.0 pp** (`epss_marginal_precision_gain_pp`). This run gives no evidence that EPSS adds discriminating power.
- n = 50 hand-picked CVEs. The base rate (random-ranking precision) is 72.0%. Cohort E was selected for exploit presence, and cohort C on KEV membership, which is an ERS input.
- At top 5, one CVE is 20 pp. The pre-review harness broke ties by dataset input order. The "+20.0 pp vs CVSS-only" figure is one CVE admitted that way, and it is 0.0 pp under the revised tie rule (recomputed from the committed scores; see the reviewer notes in `evals/results/ers_validation_results.md`).

**Method revised in review (rerun pending)**
Deterministic tie rule (score descending, then `cve_id` ascending), boundary-tie counts and the precision range over tie orders, random-baseline and Metasploit-only precision, and safe output paths. Synthetic fixtures write to `ers_validation_synthetic.*`. Real results are written only to explicitly passed paths, and there is no silent fallback to fixtures. The committed real results come from the pre-review harness and must be regenerated (Mayank's next task).

**Why**
D-008 proposed KEV as the validator. D-027 rejected that as circular (KEV is an ERS input) and moved to ExploitDB/Metasploit, noting the overlap with EPSS. Disclosing the overlap does not remove it. The honest claim is that the check is a smoke-level sanity test on a small, biased set.

ERS stays additive and never multiplies EPSS by CVSS: D-008, and `services/enrichment/README.md` rule 3. (An earlier version cited "Hard Rule 1" for this. Hard Rule 1 is about the LLM never creating graph edges.)

**Impact on plan**
Closes D-027's open follow-up "ERS validation has not been run": it has now been run once, on real mirrors, at smoke level, with the method revised and a rerun pending. Real validation would need a larger set with a documented selection rule, and a target that EPSS does not use.

**Cost if we're wrong**
Low for code, since weights and the scorer are unchanged. The cost is credibility if any number from this harness is presented as validation of ERS or of EPSS.

---

### D-037 — Absence from exploit mirrors is medium-confidence False, not high
**Date:** 2026-10-11
**Decided by:** Ayushmaan (review of PR #18)
**Type:** Reversal
**Status:** Active

**Decision**
A CVE absent from a loaded ExploitDB or Metasploit mirror yields `has_public_exploit` / `has_metasploit_module` = False at MEDIUM confidence, noted "absence is not proof no exploit exists". An unloaded mirror, and any finding without a CVE ID, yields None (DERIVED/LOW, unknown). KEV absence stays HIGH-confidence False because KEV is an authoritative catalog of its own scope.

**Why**
ExploitDB and Metasploit index a subset of public exploits; a CVE missing from them can still have one (GitHub PoCs, vendor advisories, commercial kits). Reporting HIGH-confidence False overstated what the data shows. The old non-CVE note ("ExploitDB/Metasploit track only CVEs") was false: both index non-CVE entries; we simply look them up by CVE.

**Impact on plan**
Provenance confidence changes only; ERS inputs and eval signal classification (source + boolean) are unchanged.

**Cost if we're wrong**
Trivial; one confidence constant per field in `services/enrichment/fusion.py`.

---

### D-036 — Targeted per-CVE sync for record sources; full mirrors only for bounded catalogs
**Date:** 2026-10-11
**Decided by:** Ayushmaan (review of PR #18)
**Type:** Divergence
**Status:** Active — supersedes the download design in D-033

**Decision**
FeedSyncer mirrors CISA KEV (catalog JSON), FIRST EPSS (daily bulk CSV `epss_scores-current.csv.gz`), ExploitDB (`files_exploits.csv` id/codes only) and Metasploit (`modules_metadata_base.json`, `type == "exploit"` modules by `fullname`) in full. CVE.org (`cveawg.mitre.org/api/cve/{id}`), CISA Vulnrichment (per-CVE GitHub files), ENISA EUVD (`euvdservices.enisa.europa.eu/api/search?text={id}`, exact alias match) and NVD 2.0 (`?cveId=`) are synced per CVE, only for CVE IDs present in `enriched_findings` (plus any passed in), and merged into the existing mirror files keyed by CVE ID. The scheduled task (`seekthreat.sync_feeds.run`, 02:00 UTC via a dedicated `beat` compose service) syncs all eight sources every run.

**Why**
The original endpoints did not work: `api.first.org/data/v1/epss?all=true` returns 100 of ~385k rows; `cveawg.mitre.org/api/cve?state=PUBLISHED&resultsPerPage=1000` returns HTTP 400; `vulnrichment.json` does not exist (the repo is per-CVE files); `euvd.enisa.europa.eu/api/...` is the SPA, not the API. Mirroring CVE.org/Vulnrichment/EUVD/NVD whole means hundreds of thousands of records (and, for NVD, days of rate-limited requests without a key) for a platform that looks up the CVEs its scans found. Rejected: cvelistV5 bulk ZIPs (large, and covers only CVE.org); keeping the bulk endpoints (broken). NVD is now in the chain and synced, so the fallback chain is CVE.org -> Vulnrichment -> NVD -> EUVD -> derived (README rule 2 updated).

**Impact on plan**
Enrichment for a CVE first seen in a scan uses fallbacks until the next sync (daily, or on demand via the CLI `--cve`). Mirrors gain atomic writes with fsync, a shrink guard (refuse empty / <50% replacement), compact JSON, and a `.meta.json` sidecar (synced_at, source_url, record_count, sha256 of the written file; the sha256 records what was written, it does not validate against an upstream checksum). Readers use `synced_at` as provenance date when a record has none. Downloads are bounded (User-Agent, byte caps, timeouts, https-only redirects). Sync failures are reported per source, audited (`system:celery_beat` / `system:cli`) and fail the task. EUVD, CVE.org and NVD terms of use are still marked TO VERIFY in THIRD_PARTY.md.

**Cost if we're wrong**
Low. If whole-catalog coverage is needed (e.g. for eval cohorts not in enriched_findings), pass the IDs to the task or CLI, or add a bulk path for one source behind the same mirror format; readers do not change.

---

### D-035 — Enrichment coverage eval methodology: offline NVD-only baseline comparison
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Addition
**Status:** Active

**Decision**
Enrichment coverage is evaluated offline by running SeekThreat's multi-source fusion engine and an NVD-only baseline engine over the CVE list in `evals/golden/enrichment_baseline.json` (50 CVEs, five hypothesised cohorts). The headline metric counts four intelligence fields: CVSS, CWE, description and EPSS. KEV membership and exploit availability are reported separately as "mirror loaded" plus positive-hit rate: a loaded mirror gives every CVE a definite True/False, so counting False as "filled" would only measure whether the file exists. Placeholders are excluded by provenance (`Source.DERIVED` / `Confidence.LOW`), never by value.

> **Update 2026-10-12:** coverage has since been measured once on real mirrors dated 2026-10-11 (`evals/results/enrichment_coverage_real.md`). Per field, CVSS, CWE and description coverage were identical to the NVD-only baseline (+0.0 pp excluding EPSS). The four-field +25.0 pp is entirely EPSS, which the baseline does not load. The harness now reports the three-field headline excluding EPSS automatically. The paragraph below describes the state on 2026-10-05.

**No coverage number has been measured yet.** The only committed run (`evals/results/`) is against the hand-authored fixtures in `tests/fixtures/enrichment/` (every file `_synthetic: true`) and is labelled as a synthetic smoke test of the harness. Its numbers describe which CVEs the fixtures happen to contain, not the platform.

**Why**
Layer 2 "Done When" requires coverage measured against an NVD-only baseline. Building the harness before real mirrors exist lets us check its logic offline. "Offline" here means enrichment README rule 5 ("Mirror sources locally. Don't hit APIs on the request path"): the harness reads local mirror files only and makes no network calls.

An earlier version of this entry presented the fixture run's headline as a measurement. That was withdrawn because (a) the fixtures are synthetic; (b) most of the multi-source figure came from KEV and exploit fields counting a definite False as filled, which is 100% whenever the mirror file exists; and (c) the baseline has KEV, EPSS and exploit sources unloaded by construction, so its 0% on those fields is definitional, not a finding about NVD.

Known limitation: the baseline engine parses only NVD CVSS, CWE and description. The real NVD API 2.0 also carries CISA KEV fields (`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`), which `NVDSource` does not parse. The earlier claim that NVD provides no KEV telemetry was wrong.

**Impact on plan**
`evals/enrichment_coverage.md` defines the metric. `evals/enrichment_coverage.py` is the harness. It detects synthetic mirrors from their `_synthetic` key (not the directory name) and, for real mirrors, records each file's sha256, mtime and `synced_at`. The golden dataset is marked `"verification": "unverified"`, and its unchecked `expected_sources` / `notes` fields were removed. A real number needs dated real mirrors (D-033 sync) and a verified CVE list. Until then `evals/README.md` lists the metric as not yet measured, and the Layer 2 "Done When" criterion is not met.

**Cost if we're wrong**
Moderate. If the four-field headline or the provenance-only placeholder rule is the wrong definition, the harness and its tests change, and any number already quoted from it has to be withdrawn. If the cohort hypotheses are wrong, per-cohort results mean nothing until the dataset is verified.
---

### D-034 — Real local-mirror readers for secondary sources and exploit availability signals
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Addition
**Status:** Active

**Decision**
Implement real local-mirror readers and synchronization for secondary intelligence sources:
1. `VulnrichmentSource` (Priority 2): CISA Vulnrichment SSVC decision points, CWE, and fallback CVSS v3.1/v4.0.
2. `EUVDSource` (Priority 6): ENISA European Vulnerability Database fallback metrics.
3. `ExploitDBSource` (Priority 9) & `MetasploitSource` (Priority 10): Exploit availability signals for finding enrichment and Layer 3 attack path scoring.

Strictly enforce CLAUDE.md Hard Rule 4: ExploitDB records contain ONLY exploit IDs (`EDB-XXXXX`); Metasploit records contain ONLY module names (`exploit/...`). No exploit bodies, Ruby scripts, payloads, or execution harnesses are ingested, stored, or executed anywhere in the codebase.

**Why**
In Layer 2 first part, secondary sources were stubs (`load()` merely set `_loaded = True`), meaning the fallback chain in `FusionEngine` could only jump straight from CVE.org to derived placeholders. Real implementations enable a complete 4-tier fallback: `CVE.org -> Vulnrichment -> EUVD -> Derived`.
Furthermore, Layer 3 (Graph / Path Engine) requires an exploit availability signal (`EPSS × exploit availability × privilege delta`). Exposing `has_public_exploit` / `exploit_ids` and `has_metasploit_module` / `metasploit_modules` as attributed enrichment fields provides this data deterministically without violating Hard Rule 4.

**Impact on plan**
`services/enrichment/sources/secondary.py` is now fully operational with dedicated synthetic fixtures. `FeedSyncer` supports syncing all 7 feeds (`include_secondary=True` or `--source vulnrichment|euvd|exploitdb|metasploit`). Zero new third-party Python dependencies needed (standard library `csv`, `json`, `re` suffice).

**Cost if we're wrong**
Low. All sources inherit `BaseEnrichmentSource` contract and lazy loading. Empty or absent mirror files degrade gracefully to `Confidence.LOW` / `Source.DERIVED` without throwing runtime errors or creating false negatives.

---

### D-033 — Off-request-path feed synchronization via FeedSyncer, Celery Beat, and CLI
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Addition
**Status:** Active — download design superseded by D-036

**Decision**
Download external intelligence feeds (CISA KEV, FIRST EPSS v4, CVE.org) strictly off the request path using `FeedSyncer`, scheduled daily via Celery beat (`seekthreat.sync_feeds.run`) on the `enrichment` queue and available on-demand via standalone CLI (`python -m services.enrichment.sync_feeds`). Downloads delegate to `SourceSynchronizer.sync_from_data()` for atomic file writes into `ENRICHMENT_CACHE_DIR`.

**Why**
Adheres strictly to Rule 5 of `services/enrichment/README.md` ("Mirror sources locally. Don't hit APIs on the request path"). Network calls are forbidden inside `EnrichmentService` and `FusionEngine`. Providing both Celery Beat (continuous production worker) and CLI (CI setup, container bootstrapping, manual sync) allows mirrors to be refreshed independently. Using `httpx` (already in `requirements.txt` v0.28.1) introduces zero new external dependencies.

**Impact on plan**
Implements Level 2 of Layer 2 second part. Adds `seekthreat.sync_feeds.run` Celery task and `sync-enrichment-feeds-daily` schedule in `apps/api/worker.py`.

**Cost if we're wrong**
Low. Mirror file contracts (`MIRROR_FILENAMES`) isolate feed download mechanics from source parsers. Switching transport or schedule requires no changes to fusion logic.

---

### D-032 — /findings API contract: engagement_id required on all calls
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Divergence
**Status:** Active

**Decision**
`GET /findings/{finding_id}` requires `?engagement_id=...` as a query parameter.
`POST /findings/enrich/batch` requires `engagement_id` in the JSON body.
Both are validated against an existing engagement row before any enrichment or retrieval occurs.

**Why**
Authorization scoping (CLAUDE.md): every scan and query must be logged with actor, target, and engagement reference. Without `engagement_id`, the audit event has no authorization reference to log. The composite PK `(engagement_id, finding_id)` on `enriched_findings` (D-031) also means a `finding_id` alone is not unique — the engagement scope is needed to look anything up. This is a breaking change from a hypothetical global `/findings/{id}` contract.

**Impact on plan**
The frontend must pass `engagement_id` through all findings calls (tracked in Level 5 dashboard work). The API client in `apps/web/lib/api.ts` has no findings methods yet — wiring them correctly is part of that level.

**Cost if we're wrong**
Low. `engagement_id` is additive — callers that already have it pass it through. Removing the requirement later is a one-line router change.

---

### D-031 — Composite PK (engagement_id, finding_id) on enriched_findings
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Divergence
**Status:** Active

**Decision**
The `enriched_findings` table uses a composite primary key of `(engagement_id, finding_id)`. `finding_id` alone is not unique. Upserts de-duplicate per engagement.

**Why**
D-007 established that every row carries an `engagement_id`. Enrichment is produced per-engagement: the same `finding_id` string could appear in two different engagements (different targets, different observations) and legitimately produce different enriched results. A global PK on `finding_id` would either reject valid re-enrichment or silently overwrite data from a different engagement. The composite key makes the scoping structural rather than enforced by application code.

**Impact on plan**
Upsert logic must include `engagement_id` in the conflict target. `GET /findings/{id}` needs `engagement_id` to resolve the row (D-032).

**Cost if we're wrong**
Low. If global uniqueness of `finding_id` is later proven correct, the constraint is a migration that drops the composite and adds a simple PK.

---

### D-030 — in_kev=None means "unknown", not "confirmed absent"
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Divergence
**Status:** Active

**Decision**
`in_kev` is `None` only when the KEV mirror is not loaded. A CVE checked against a loaded catalog gets a definite answer. Behaviour of `FusionEngine._kev_fields`:

| KEV mirror | CVE listed | `in_kev` | Provenance |
|---|---|---|---|
| Not loaded (file missing, unreadable, or empty catalog) | n/a | `None` | `Source.DERIVED` / `Confidence.LOW`, note "KEV mirror not loaded; KEV status unknown" |
| Loaded | No | `False` | `Source.KEV` / `Confidence.HIGH` |
| Loaded | Yes | `True` | `Source.KEV` / `Confidence.HIGH` |

Findings with no CVE IDs get `False` attributed `Source.DERIVED` / `Confidence.HIGH` (KEV lists only CVEs). The ERS KEV component explains `None` as "unknown" and applies zero boost. It never claims the CVE is confirmed absent from KEV.

**Why**
"Mirror not loaded" and "checked KEV and not listed" mean different things. Conflating them would let a missing download quietly lower ERS scores by asserting a confident negative. In a viva, "your tool said this was not exploited in the wild — how do you know?" needs an honest answer. When the mirror is missing, that answer is "we don't know", not "no".

**Impact on plan**
`_kev_fields` checks `cisa_kev.is_loaded` before reading anything into a lookup miss. `_kev_component` in `ers.py` handles the `None` branch (zero boost, derived provenance, "unknown" explanation). An earlier version of this entry said a CVE missing from a *loaded* mirror also yields `None`. That was wrong, and the table above matches the code.

**Cost if we're wrong**
Low to undo, with one open risk. A loaded but stale mirror still produces confident `False` values: confidence does not reflect mirror age. Fixing that means feeding the mirror's sync date (D-033) into the KEV provenance or confidence.
---

### D-029 — Multiplicative path score in graph layer does not violate the EPSS × CVSS prohibition
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Divergence
**Status:** Active

> **Update 2026-10-12:** D-039 proposes replacing the multiplicative score with a two-tier additive/log-space formulation. D-039 is *Proposed*, pending sign-off by the graph owner, so this entry stays Active until then. Note that D-039's Tier 1 is still multiplicative in EPSS (a sum of −ln EPSS is the log of a product).

**Decision**
`services/graph/README.md` describes a path score of `EPSS × exploit_availability × privilege_delta`. This multiplication does not break the letter of `services/enrichment/README.md` rule 3 ("Never multiply EPSS by CVSS"), because neither of the other factors is CVSS. That is the only claim this entry makes. **Whether the product is a sound score is an open question and a known viva risk** (see below).

**Why**
Rule 3 bans `EPSS × CVSS`. EPSS is a probability of exploitation activity and CVSS is a severity descriptor, so their product is neither. (`docs/02-architecture.md` attributes this point to FIRST. We have not yet pinned the exact FIRST passage, and it must be cited before the viva.)

The graph's path score avoids CVSS, but it is **not** a conditional probability decomposition. Earlier wording saying it was is withdrawn:
- `privilege_delta` measures how much privilege an attacker gains along an edge. It is not a probability, so the product is a heuristic ranking score, not P(path is traversable).
- **Double-counting risk:** EPSS already uses exploit-code availability (for example, public exploits in ExploitDB or Metasploit) among its model inputs. Multiplying EPSS by an `exploit_availability` factor counts that evidence twice.
- `exploit_availability` is binary or ordinal. A zero factor zeroes the whole path, whatever its other evidence.

**Impact on plan**
No code change in this entry. Before Layer 3 path scoring lands, the graph owner must either (a) justify the product as a heuristic and document how double-counting is handled, or (b) switch to an additive or otherwise non-overlapping formulation. Until then this is an open viva risk.

**Cost if we're wrong**
Contained. Path scoring lives inside `services/graph/`, and changing its formula does not touch enrichment or ERS. The bigger cost is in the viva, if the product gets defended as a probability when it isn't one.
---

### D-028 — ERS computation lives in enrichment (Layer 2); ERS consumption lives in graph (Layer 3)
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Divergence
**Status:** Active

**Decision**
ERS is computed by `services/enrichment/ers.py` and stored on `EnrichedFinding`. The graph layer (Layer 3) reads the stored ERS for path ranking and does not recompute it. This moves ERS ownership from `services/graph` to `services/enrichment`.

**This diverges from the scope.** `docs/00-scope.md` lists ERS in the Layer 3 row ("graph, rules, paths, ERS, chokepoints", November), and the original `docs/02-architecture.md` module map gave `services/graph` ownership of ERS. ERS computation is now Layer 2 work. `docs/00-scope.md` is left as the original scope record and this entry records the divergence. `docs/02-architecture.md` is updated to match: the module map puts ERS under `services/enrichment`, `services/graph` consumes the stored score, and the pipeline comment says "ERS-based ranking".

**Why**
ERS depends only on enrichment data (CVSS, EPSS, KEV). Computing it in the graph layer would mean `services/graph` importing from `services/enrichment`, which the module map forbids (both may import only `schema`). Storing ERS on `EnrichedFinding` gives the graph a precomputed field and keeps dependencies flowing one way.

**Impact on plan**
ERS computation and its sensitivity check (D-027, `evals/ers_sensitivity.py`) move from November's Layer 3 work into October's Layer 2. The `ers.py` code was already in enrichment. The change is in ownership and docs. Layer 3 will read `enriched_finding.ers.value` for ranking.

**Cost if we're wrong**
Low. If the graph needs graph-specific inputs such as a reachability factor, it can combine the stored ERS with them in `services/graph` without changing the enrichment computation.
---

### D-027 — D-008 addendum: weight rationale, sensitivity analysis, and KEV circularity resolution
**Date:** 2026-10-05
**Decided by:** Mayank
**Type:** Addition
**Status:** Active

**Decision**
This entry extends D-008, which committed to hand-tuned, documented ERS weights but deferred the rationale and the sensitivity analysis. It provides both and resolves the circular-validation concern with KEV.

#### Weight rationale

ERS combines three additive components. Each component value is on a [0, 10] scale before weighting. Weights sum to 1.0, so the final score is in [0, 10].

| Component | Weight | Component value (0-10) | Reasoning |
|-----------|--------|-----------------|-----------|
| CVSS Base Score | **0.40** | `cvss_score` | CVSS is the most established, most widely cited severity descriptor, so it should dominate. But a CVSS 10 with no exploitation history is less urgent than an actively exploited CVSS 7.5, so the weight is 40%, not 60% or more. |
| EPSS v4 probability | **0.35** | `epss_probability × 10` | EPSS estimates the probability of exploitation activity in the next 30 days. It is the most operationally actionable signal. 35% puts it close to CVSS on purpose: "is someone actually exploiting this?" matters almost as much as "how bad is it if they do?" |
| CISA KEV membership | **0.25** | `10 if in KEV else 0` | KEV membership is a binary, high-confidence signal of confirmed active exploitation. It is added, not multiplied (D-008 forbids multiplying). With a positive weight, a KEV-listed CVE always scores higher than an otherwise identical non-KEV CVE, but KEV alone contributes at most 2.5 points. |

The formula: `ERS = cvss_score × 0.40 + (epss × 10) × 0.35 + (10 if KEV else 0) × 0.25`

#### Sensitivity analysis

Produced by `python evals/ers_sensitivity.py` (tested in `tests/unit/test_ers_sensitivity.py`). The script calls `services.enrichment.ers.calculate_ers` with `ERSWeights` for each profile. Inputs for the five CVEs come from the multi-source fusion engine over the **synthetic** fixtures in `tests/fixtures/enrichment/`, which are hand-authored and not real feed values. The two `SYN-*` rows are hand-chosen probe inputs, not CVEs, added because all five fixture CVEs except one are KEV-listed with high EPSS, so they barely separate the profiles. Nothing below is a measurement.

| Profile | w_cvss | w_epss | w_kev |
|---|---|---|---|
| severity_heavy | 0.60 | 0.25 | 0.15 |
| balanced (current) | 0.40 | 0.35 | 0.25 |
| exploitation_heavy | 0.25 | 0.50 | 0.25 |

Script output:

| Item | Label | CVSS | EPSS | KEV | severity_heavy | balanced | exploitation_heavy |
|---|---|---|---|---|---|---|---|
| CVE-2021-44228 | Log4Shell | 10 | 0.97543 | yes | 9.94 | 9.91 | 9.88 |
| CVE-2022-22947 | Spring Gateway | 9.8 | 0.8951 | yes | 9.62 | 9.55 | 9.43 |
| CVE-2024-23897 | Jenkins CLI | 9.8 | 0.7812 | yes | 9.33 | 9.15 | 8.86 |
| CVE-2021-41773 | Apache traversal | 7.5 | 0.9412 | yes | 8.35 | 8.79 | 9.08 |
| CVE-2020-7699 | express-fileupload | 7.3 | 0.1425 | no | 4.74 | 3.42 | 2.54 |
| SYN-HIGH-CVSS | high CVSS / low EPSS / non-KEV | 9.8 | 0.02 | no | 5.93 | 3.99 | 2.55 |
| SYN-HIGH-EPSS | low CVSS / high EPSS / non-KEV | 5.3 | 0.9 | no | 5.43 | 5.27 | 5.83 |

Rank order of the five fixture CVEs (highest first):

- severity_heavy: Log4Shell > Spring Gateway > Jenkins CLI > Apache traversal > express-fileupload
- balanced: Log4Shell > Spring Gateway > Jenkins CLI > Apache traversal > express-fileupload
- exploitation_heavy: Log4Shell > Spring Gateway > **Apache traversal > Jenkins CLI** > express-fileupload

**Ranking stability (corrected).** An earlier version of this entry called the ranking "fully stable", with "no reordering". The table above shows otherwise. Under the exploitation-heavy profile, Apache traversal (9.08) overtakes Jenkins CLI (8.86). Ranks #1, #2 and #5 hold across all three profiles. Ranks #3 and #4 swap when EPSS is weighted at 0.50.

The probe rows show the weights can change which non-KEV finding comes first. The high-CVSS/low-EPSS case outranks the low-CVSS/high-EPSS case under severity_heavy (5.93 vs 5.43). The order flips under balanced (3.99 vs 5.27) and exploitation_heavy (2.55 vs 5.83). So the choice of weights matters most for the non-KEV middle of the list, where these synthetic inputs give no evidence about which order is right.

What can be defended: on these synthetic inputs, the top two and the bottom one do not depend on the profile, and the current balanced profile already ranks the high-EPSS probe above the high-CVSS probe. What cannot be claimed: that the weights "do not materially change what gets fixed first". They do, for mid-ranked and non-KEV findings. With real mirror data, both the scores and the orderings may differ.

#### KEV circularity resolution

D-008 originally said KEV "validates" the ranking. With KEV now a 25% component of ERS, using it to also validate is circular.

**Resolution (option a):** KEV remains an ERS input. Validation uses a separate signal: "do the top-N ERS-ranked CVEs have public ExploitDB entries or Metasploit modules?"

**This validation is only partly independent.** EPSS carries 35% of ERS and is itself a model whose inputs include exploit-code availability (for example, public exploits in ExploitDB or Metasploit). A high-ERS CVE is therefore partly high *because* exploit code exists, so checking it against ExploitDB/Metasploit partly re-measures an input. The check still carries some information (the CVSS and KEV components do not use it), but a positive result cannot be presented as independent confirmation. Separating the two needs either an ERS variant without EPSS for the validation run, or a validation signal EPSS does not use.

D-008's original sentence "KEV membership is used to *validate* the resulting ranking, not as a training target" is amended: KEV is an *input* to ERS. Validation uses ExploitDB/Metasploit corroboration, with the caveat above. The "not as a training target" clause is unchanged.

**Open follow-up:** this entry originally said the ExploitDB/Metasploit validation "will be measured in the Level 4 eval". It was not. Level 4 (`evals/enrichment_coverage.py`, D-035) measures enrichment coverage only and does not rank anything by ERS. ERS validation has not been run and remains open.

**Update 2026-10-12 (see D-038):** the ExploitDB/Metasploit corroboration has now been run once, on real mirrors dated 2026-10-11 (`evals/ers_validation.py`). It is smoke-level only (n=50, biased selection, 72.0% base rate). The EPSS marginal gain was 0.0 pp. The method was revised in review (deterministic ties, random baseline, Metasploit-only precision), and a rerun is pending. The EPSS overlap noted above applies to Metasploit as well as ExploitDB.

**Impact on plan**
No weight or code changes. `evals/ers_sensitivity.py` reproduces the sensitivity table. ERS validation against exploit corroboration is an open follow-up, with the EPSS overlap above to be addressed in its design.

**Cost if we're wrong**
Low to change: `ERSWeights` keeps the weights separate from the computation. The higher cost is credibility. Claiming more stability or independence than the numbers support is the failure this correction fixes, and repeating it in the viva would be worse than the instability itself.
---

### D-026 — Nuclei observations carry an nmap-shaped `endpoint` join key
**Date:** 2026-09-26
**Decided by:** Hritish
**Type:** Addition
**Status:** Active

**Decision**
`parse_nuclei_json` emits an `endpoint` attribute spelled exactly like nmap's port
subject (`<host>:<port>/<proto>`, IPv6 bracketed), and reads the `port`, `scheme`, `url`,
`matcher-status`, `template-path` and `info.tags` fields nuclei v3 actually emits.

**Why**
nmap keys every `port_open` / `service_version` observation by `172.20.1.10:80/tcp`
(`nmap_xml.py::_port_subject`). A nuclei observation's subject is a URL
(`http://172.20.1.10:80/login`), which shares no key with it, and the parser was storing
only `host`. That was survivable while the fixtures put a whole URL in `host`, but nuclei
v3 reports `host` bare with the port in its own field, so the port was being dropped
entirely. The result: no deterministic way to attach a `vuln_candidate` to the listener it
was found on, which is exactly the edge `services/graph` needs to enumerate a path. Since
CLAUDE.md hard rule 1 forbids letting the model infer edges, this key has to come from the
parser.

`endpoint` is only emitted when a port is actually present in the output. Defaulting to
80/443 from the scheme would be an inference, and every attribute here has to trace to
something the scanner reported.

**Impact on plan**
`tests/unit/test_observation_fixtures.py` now asserts every `vuln_candidate` joins a port
fact in the fixture set. `tests/fixtures/observations/lab_extended_nuclei.json` regenerated.

**Cost if we're wrong**
Low. One helper in `nuclei_json.py`; the fixture set is regenerated by
`scripts/build_observation_fixtures.py`.

---

### D-025 — Nuclei target assembly in the adapter, not URL parsing in the authorization gate
**Date:** 2026-09-26
**Decided by:** Hritish (first live run of the nuclei path)
**Type:** Addition
**Status:** Active

**Decision**
`NucleiAdapter` builds nuclei's `-u` value by appending a validated `port` and `scheme`
option to the target the authorization gate approved, and only when that target is a bare
IP address or a strict DNS hostname. `target_matches()` still refuses to parse a URL down
to a host; its `*.domain` wildcard now matches only a syntactically valid hostname ending
in `.domain` (it previously used `fnmatch`, whose `*` also matched `/`, `#`, `@` and `:`,
so `http://evil.com/.lab.local` passed an allowlist of `*.lab.local`).

**Why**
The nuclei path had never been executed (PROGRESS.md: "the nuclei path has not run against
the lab"). The first time it ran, `tests/integration/test_e2e_flow.py::test_nuclei_adapter_and_persistence`
failed at the gate: nuclei's input model is URLs, and `Authorization.permits("http://127.0.0.1:8799")`
is False against an allowlist of `127.0.0.1`. The gate is right to do that.
`tests/unit/test_authorization_matching.py` deliberately asserts that
`http://attacker.com@172.20.1.10` and friends do **not** match `172.20.1.0/24`: if Python
extracted the host for the allowlist check and Go's URL parser disagreed about where the
host ended, the check would pass on one host and the scan would hit another. Teaching the
gate to parse URLs would have removed that control to make a test pass.

The remaining options were to allowlist exact URL strings (brittle: every port and path
becomes a separate authorization entry) or to have the adapter assemble the URL from an
approved host. The latter keeps the property that matters — the adapter only ever
*appends* to a gate-approved bare host, and appending a validated scheme and numeric port
to a string that is nothing but an IP or a hostname cannot move a scan to a different
host. The adapter re-checks that shape itself rather than trusting the gate's matching, so
a single bug in either layer does not on its own put an unapproved host in front of
nuclei. It also matches the target model the API already
documents (`apps/api/routers/scans.py`: "IP address, CIDR, or hostname to scan").

A URL passed as the target still works, but only when that exact string (case-sensitive)
is a non-wildcard entry of the allowlist; a URL that merely matched a pattern is rejected.
The `port` and `scheme` options are then rejected too, since rewriting it would produce a
target the authorizer never saw.

**Impact on plan**
`options` gains `port`, `scheme` and `omit_http_exchange`. The integration test now scans
`127.0.0.1` with `port`/`scheme` options rather than passing a URL.

**Cost if we're wrong**
High. This is the boundary that decides which host nuclei is pointed at (hard rule 2):
an error here scans a host nobody authorized, as the original wildcard bypass showed. The
code is small — `target_matches()` in `packages/schema/models/engagement.py` and
`_nuclei_target()` in `nuclei_adapter.py` — and both are covered by the bypass cases in
`tests/unit/test_authorization_matching.py` and `tests/unit/test_nuclei_adapter.py`; any
change to either needs a new bypass case, not just a passing happy path.

---

### D-024 — Pin Nuclei templates release archive in Docker image
**Date:** 2026-09-25
**Decided by:** Mayank (PR #15 review resolution)
**Type:** Addition
**Status:** Active

**Decision**
Instead of executing `nuclei -ut` during Docker build (which fetches unversioned mutable templates from GitHub at build time), we pin an official immutable `nuclei-templates` release archive (v10.4.9) and verify its SHA-256 checksum during image build. A corresponding entry is maintained in `THIRD_PARTY.md`.

**Why**
Non-deterministic builds break reproducibility: two image builds created days apart would carry different vulnerability detection templates, causing evaluative testing and test suites to produce drift. Pinning the template archive ensures byte-identical scanner behavior across environments.

**Impact on plan**
Template updates become deliberate, reviewable PRs bumping `NUCLEI_TEMPLATES_VERSION` and `NUCLEI_TEMPLATES_SHA256` in `apps/api/Dockerfile`.

**Cost if we're wrong**
Low. Updating templates requires bumping the version and checksum in `apps/api/Dockerfile`.

---

### D-023 — Constrained scanner execution options and tag allowlists
**Date:** 2026-09-25
**Decided by:** Mayank (PR #15 review resolution)
**Type:** Scope change
**Status:** Active

**Decision**
Scanner execution options passed to `POST /scans` are strictly constrained at the adapter boundary:
1. `NmapAdapter`: accepts only sanitized options (`ports` validated against `^[0-9,\-]+$`, `fast: bool`, `no_ping: bool`, `service_detection: bool`). Arbitrary CLI arguments remain rejected (per D-017).
2. `NucleiAdapter`: accepts only approved non-destructive tags (`APPROVED_TAGS` allowlist), enforces exclusion backstop `-etags dos,intrusive,fuzz,bruteforce,rce,default-login` on every run (including runs with no `-tags`). `rce` and `default-login` are excluded because they send code-execution payloads or attempt authentication, and restricts template paths strictly to in-repo template directories (`services/scanners/nuclei_templates` and test fixtures) with path-traversal prevention.

**Why**
Preventing caller input from expanding scan boundaries or invoking destructive checks (e.g. DoS, brute force, exploit modules) is required by CLAUDE.md hard rule 4 (no autonomous exploitation, non-destructive checks only) and authorization gate determinism (D-017).

**Impact on plan**
Operators cannot run arbitrary custom templates or intrusive tags through the API/dashboard without explicit allowlisting in code.

**Cost if we're wrong**
Zero security risk. New safe tags or template directories can be added to the allowlist as needed.

---

### D-022 — Correct `docs/00-scope.md`'s timeline to five months, November protected
**Date:** 2026-09-20
**Decided by:** Ayushmaan (confirmed with the team)
**Type:** Divergence
**Status:** Active

**Decision**
`docs/00-scope.md`'s Timeline section is rewritten to match `docs/02-architecture.md`'s
"Sequence" section: five months, September through January, with November (not October)
protected for the graph and attack-path engine. `docs/00-scope.md` now points to
`docs/02-architecture.md` as the authoritative schedule instead of carrying its own
independent copy.

**Why**
`docs/00-scope.md` was left as an unfilled placeholder ("Paste the full scope and research
document here...") from before the project started, but its Timeline table was real prose — a
six-month plan (August–January, October protected) that predates the team's actual start date.
`docs/02-architecture.md` was written after the team confirmed the real constraint: five months,
starting in September, with the integration month that the old plan gave itself in addition
folded into January. The two documents disagreed on both the length of the project and which
month is protected, and every other planning document (`PROGRESS.md`, `HOW-THIS-REPO-WORKS.md`)
had already been written against the five-month version. Left unresolved, a five-months read of
`docs/02-architecture.md` and a six-months read of `docs/00-scope.md` would each look equally
authoritative to whoever opened the repo next.

**Impact on plan**
No schedule changes — `docs/02-architecture.md`'s Sequence section was already correct and
already what the team has been building against. This only removes the contradiction: Layer 1
(the current month) is unaffected, and every layer after it is described once instead of twice.

**Cost if we're wrong**
Trivial to undo — a doc edit, not a code or architecture change.

---

### D-021 — Fix Celery task registration: explicit import, not `autodiscover_tasks`
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
`apps/api/worker.py` replaces `celery_app.autodiscover_tasks(["apps.api.tasks"])` with an
explicit `from apps.api.tasks import scans as _scans_tasks`. Verified in a subprocess (the only
way to observe this correctly — see below): importing `apps.api.worker` alone now registers
`seekthreat.scans.execute`; on `main` it registered nothing.

**Why**
`autodiscover_tasks` treats each entry in its list as a *package* and imports `"<entry>.tasks"`.
Passing `["apps.api.tasks"]` — the tasks package itself — made Celery look for the nonexistent
`apps.api.tasks.tasks` and silently register nothing. The correct call would have been
`autodiscover_tasks(["apps.api"])`. This was never caught because every existing test imports
`apps.api.tasks.scans` directly (to call `execute_scan.run.__func__` for the bypass-the-broker
pattern documented for this test suite), which registers the task as a side effect regardless of
what `worker.py` does — so the bug was invisible to every test that exists. A real
`celery -A apps.api.worker.celery_app worker` process imports only `worker.py`, hits the actual
bug, and rejects every dispatched job as unregistered: `execute_scan.delay()` enqueues work, and
nothing ever runs it. Every scan would sit at `pending` forever. This is why D-020's compose
verification could bring the worker container up but never actually completed a real scan.

Found and fixed locally (native `uvicorn`/`celery`, not Docker) before this decision was logged;
`tests/unit/test_worker_registration.py` pins it going forward. The test runs the check in a
**subprocess** on purpose — an in-process assertion would pass regardless of whether `worker.py`
registers anything, for the same reason the bug went unnoticed.

**Impact on plan**
None to scope. This was a live defect blocking the actual "done when" criterion for Layer 1 —
worse than the Docker Hub pull failures, because those are environmental and this was not: even
with a fully working Docker pull, scans dispatched through a real worker process would never
have executed.

**Cost if we're wrong**
None — the fix is strictly more correct than what it replaces, and it is regression-tested.

---

### D-020 — Worker-to-lab network attachment via a separate compose override
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
Added `infra/docker-compose.lab.yml`, an optional override (not merged into
`infra/docker-compose.yml`) that attaches the `worker` service to all three
lab networks -- `lab_dmz`, `lab_internal`, `lab_data`, declared
`external: true` -- at fixed IPs (`172.20.{1,2,3}.251`, one per segment,
outside every range in `lab/ground_truth.yaml` and clear of the lab's own
`scanner` helper at `.250`). Brought up with:

```
docker compose -f lab/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml -f infra/docker-compose.lab.yml \
    --profile core up -d
```

Attached to all three segments, not `dmz` only: Layer 1's own "done when"
criterion is stored observations from a real scan, and `ground_truth.yaml`
requires coverage of the internal and data tiers, not just the perimeter.
The graph engine (Layer 3) models multi-hop pivoting on top of these
observations later; the scanner does not need to literally pivot to gather
them now.

**Why**
A separate override rather than editing the base file: external networks
must exist before `docker compose up` runs, or compose refuses to start. The
base file must keep working with no lab running -- day-to-day API/DB
development doesn't need the lab, and the memory budget in
`docs/02-architecture.md` already treats the two as mutually exclusive on a
16 GB machine.

Attaching an additional container to an `internal: true` network does not
weaken that network's isolation. The flag means "no default route to the
outside internet" -- it says nothing about which other containers may join
the same L2/L3 segment, and it is a property of the network, not of who is
attached to it. Verified directly rather than assumed: brought the worker up
attached to all three lab networks, confirmed reachability to the real
`dvwa`/`juiceshop` dmz targets and to substitute containers standing in for
the internal/data tiers (their own images fail to pull on this machine, see
D-018), and confirmed `docker network inspect` still reports
`Internal=true` on all three lab networks afterward -- the authoritative
check, since an in-container egress test using missing tooling would not
have been conclusive.

This grants reachability only. `apps/api/core/authorization.py` still
decides whether a scan is *permitted* -- an engagement's allowlist must
cover the target regardless of what the worker can physically reach
(CLAUDE.md hard rule 2). No code changed; this is compose configuration
only.

**Impact on plan**
Closes backlog item #1 from the compose-fix task (D-018): "the worker still
cannot reach the lab targets." Layer 1's "a scan produces stored,
provenanced observations" criterion is not yet fully demonstrated end to
end -- that also needs `pgvector/pgvector:pg16` to build, which is still
blocked by the same Docker Hub CDN failures documented in D-018 and D-019.
This change removes the networking half of that blocker; the image-pull half
is environmental and outside this change's scope.

**Cost if we're wrong**
Low. One new file, no changes to the base compose file or to application
code. Deleting `infra/docker-compose.lab.yml` fully reverts this.

---

### D-019 — Non-retried permanent scan failures; pinned nuclei binary; migration/ORM index parity
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
Three contained fixes from the PR #2 follow-up list, closed together:
1. `apps/api/tasks/scans.py` no longer retries permanent failures. A new
   `PERMANENT_ERRORS` tuple (`ValueError` for an unsupported scanner name,
   the new `ScannerUnavailableError` for a missing binary, `AuthorizationError`)
   is checked before handing the exception to `self.retry()`. The task also
   now re-raises after marking a scan `failed`, so Celery's own task state
   (FAILURE) agrees with the database row, instead of the task returning
   normally and being recorded SUCCESS.
2. `apps/api/Dockerfile` installs a pinned nuclei release binary
   (`v3.11.1`, linux_amd64, verified against the release's published sha256)
   alongside the existing apt-installed nmap. `adapter.is_available()` is
   checked before `adapter.scan()` inside the task, turning a missing binary
   into `ScannerUnavailableError` instead of an opaque subprocess `OSError`
   retried three times.
3. New migration `0003_add_scans_artifact_id_index` adds `ix_scans_artifact_id`,
   which `apps/api/db/models.py` declared (`index=True`) but migration 0002
   never created. `tests/unit/test_alembic.py` gained a test that upgrades a
   fresh DB via Alembic, builds a second one via `create_all`, and asserts
   their indexes match on every table -- so this class of drift fails CI
   going forward instead of silently diverging between what tests exercise
   and what a real deployment gets.

**Why**
Every retry of a permanent failure is a full rescan; an unsupported scanner
or a missing binary was retried 3 times before being marked failed for an
outcome that could never change. Separately, the task swallowing the
exception after marking a scan `failed` meant Celery itself reported the task
SUCCESS -- anything monitoring Celery task state (Flower, a future ops
dashboard) would see no failure at all. Both close on the same code path, so
fixed together rather than in separate changes touching the same function.

The Dockerfile fix was already called out on the backlog as a known gap
(nuclei has no apt package; needs the pinned GitHub release approach nmap
does not need). Bundled with the retry fix because `is_available()` needing
to run somewhere is what the retry fix's `ScannerUnavailableError` is for.

**Impact on plan**
None to scope or timeline. Chosen as the second of two contained PRs closing
the PR #2 follow-up list (the first, apps/api/routers, is a separate PR from
the same base so either can merge first). The Dockerfile change is
**not yet verified by an actual image build** -- Docker Hub image pulls are
failing on this machine for reasons unrelated to this change (see the compose
fix's PR); `pip install`/pytest/mypy/ruff all pass, but nobody has confirmed
`docker build` actually produces a working `nuclei` binary at this container's
`glibc`/architecture. Flagging this explicitly rather than claiming it works.

**Cost if we're wrong**
Low for the retry/re-raise logic -- covered by unit tests calling the task
body directly, no live Celery or Redis needed. Medium for the Dockerfile: if
the binary turns out incompatible with `python:3.11-slim`'s base image, the
fix is confined to that one `RUN` block and does not touch application code.

---

### D-018 — Fix the `core` compose profile: in-network hostnames, a migration step, and a normalized DB driver everywhere
**Date:** 2026-09-20
**Decided by:** Ayushmaan
**Type:** Divergence
**Status:** Active

**Decision**
`docker compose -f infra/docker-compose.yml --profile core up` did not work. Fixed with four
changes:
1. `api`, `worker`, and a new one-shot `migrate` service get `environment:` overrides pointing
   `DATABASE_URL`/`REDIS_URL` at the `postgres`/`redis` compose service names, not `localhost`.
   `environment:` outranks `env_file:`, so one `.env` still serves native dev via the published
   ports.
2. `migrate` runs `alembic upgrade head` once (`restart: "no"`); `api` and `worker` gate on
   `service_completed_successfully` so tables exist before either starts, and so the two never
   race to apply the same DDL.
3. `.dockerignore` added — `context: ..` was copying the whole repo, including
   `apps/web/node_modules` and `.env`, into the build context.
4. `env_file` on postgres/api/worker/neo4j changed to the long form with `required: false`.
   `.env` is gitignored and absent on a fresh clone; compose treats a missing plain-string
   `env_file` as fatal, which was the actual first failure, ahead of the networking one.

**Why**
While implementing this, found that `apps/api/core/config.py` normalized `DATABASE_URL` to the
psycopg3 driver (`postgresql+psycopg://`) only inside a Pydantic `default_factory` — which
pydantic-settings skips whenever the env var is *set*. Every value actually in use
(`.env.example`, the new compose `environment:` overrides) is a bare `postgresql://`, which
SQLAlchemy resolves to psycopg2 — not installed; this project ships `psycopg[binary]`
(psycopg3). This was already a live bug on the native-dev path (`cp .env.example .env` and run)
and would have reproduced inside every container the compose fix touches. Moved the
normalization into a `field_validator(mode="after")` so it applies to every source — env var,
`.env` file, and default alike — with a regression test in `tests/unit/test_config.py`. Folded
into this decision rather than a separate one since it was found while implementing this task
and the compose fix does not work correctly without it.

**Impact on plan**
None to scope or timeline — infra-only. Worker-to-lab network attachment (`172.20.x.x`) remains
a separate, still-open follow-up: a scan dispatched at a lab IP records a failure until that
exists.

**Cost if we're wrong**
Low. Compose config only; reverting is a `git revert`. The driver-normalization fix has a unit
test pinning the behavior it corrects.

---

### D-017 — Remove `options["extra_args"]` from scanner adapters; fixed argv only
**Date:** 2026-09-20
**Decided by:** Ayushmaan (review of mayank-development, PR #1)
**Type:** Reversal
**Status:** Active

**Decision**
`NmapAdapter._execute` and `NucleiAdapter._execute` no longer splat
`request.options.get("extra_args", [])` into the tool's argv. The command line is now fixed
except for the target itself, and nmap's invocation adds a literal `--` before the target so it
can never be parsed as a flag.

**Why**
`ScanRequest.options` is a `dict[str, Any]` that reaches the adapter straight from the
`POST /scans` HTTP body (`apps/api/routers/scans.py`) with no validation beyond Pydantic's
`dict[str, Any]` typing. `request.authorization.permits()` only ever checks `request.target`
against the allowlist — it has no visibility into `options`. A caller could therefore pass
`{"extra_args": ["-u", "https://unauthorized.example.com"]}` (nuclei accumulates repeated `-u`
flags) or `{"extra_args": ["203.0.113.10"]}` (nmap scans every positional target given, so this
adds a second host ahead of the authorized one) and scan a target that was never checked against
any allowlist. This is a direct violation of CLAUDE.md hard rule 2 — "no scan without
authorization enforced at the API layer" — found during review of PR #1 before merge to `main`.

**Impact on plan**
None to timeline; this is a revert of an unreviewed pattern that shipped in the same PR that
introduced the HTTP scan-dispatch path. If tool-specific flags are needed later (e.g. nmap
timing templates), they must be a fixed, named, server-side option
(`options: {"timing": "T3"}` mapped to a small allowlist of flag values in the adapter) — never
an arbitrary argv fragment sourced from the request body.

**Cost if we're wrong**
None — this closes a real bypass with no loss of legitimate functionality; nothing in the
codebase or tests depended on `extra_args`.

---

### D-016 — Lab network topology, 10-host multi-tier architecture & ground truth baseline
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Architecture / Evaluation
**Status:** Active

**Decision**
`lab/docker-compose.yml` defines 10 target containers plus 1 scanner container partitioned across three isolated network segments (`dmz`: 172.20.1.0/24, `internal`: 172.20.2.0/24, `data`: 172.20.3.0/24). All networks enforce `internal: true` with zero egress to the internet and no exposed host ports. `lab/ground_truth.yaml` serves as the authoritative ground truth denominator for Track A (accuracy, precision, recall, F1) and Track B (attack path validity) evaluation metrics.

The topology intentionally embeds realistic multi-hop attack paths:
1. External DMZ SSRF (`dvwa` 172.20.1.10) -> Internal API credential leak (`internal-api` 172.20.2.10) -> Data Tier PostgreSQL (`db-primary` 172.20.3.10).
2. External API Gateway SpEL Injection (`spring-gateway` 172.20.1.13, CVE-2022-22947) -> Internal Jenkins CLI Arbitrary File Read (`jenkins-ci` 172.20.2.25, CVE-2024-23897) -> Bastion SSH pivot (`bastion-ssh` 172.20.2.50) -> Data Tier Redis Lua Sandbox Escape RCE (`cache-redis` 172.20.3.20, CVE-2022-0543).
3. External DMZ Reverse Proxy Smuggling (`dmz-proxy` 172.20.1.12) -> Internal Wiki OGNL Injection RCE (`internal-wiki` 172.20.2.40, CVE-2022-26134).

**Context**
Layer 3 (Graph / Path Engine) requires realistic attack paths that span multiple hops across segmented subnets; a flat network with isolated single vulnerabilities gives the graph reasoning engine nothing meaningful to discover. Furthermore, evaluation metrics cannot be retrofitted—Track A and Track B metrics require a verifiable ground truth denominator recording every host, service, version, expected CVE, and known scanner false positive.

**Consequences**
- Evaluation metrics have a strict, declarative baseline to calculate precision, recall, and false-positive rates.
- `tests/unit/test_ground_truth.py` enforces consistency between `lab/ground_truth.yaml` and `lab/docker-compose.yml`.
- Target containers remain fully isolated and legally safe to scan from the internal `scanner` container (172.20.1.250).

---

### D-015 — Nuclei as second core scanner; NDJSON output via `-jsonl -silent`
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Tool choice
**Status:** Active

**Decision**
`services/scanners/nuclei_adapter.py` invokes `nuclei -u <target> -jsonl -silent` and
`services/scanners/nuclei_json.py` parses the NDJSON output into `ObservationKind.VULN_CANDIDATE`
observations. Nuclei's native severity, CVE IDs, CVSS scores and matcher metadata are
preserved verbatim in observation `attributes`; no risk-score computation happens here.

**Why**
- Nuclei is MIT-licensed; we invoke the binary, never vendor its source.
- `-jsonl` produces one JSON object per line, making streaming and partial-failure recovery
  trivially safe. A JSON array would require buffering the full output before parsing.
- `-silent` suppresses non-finding output (progress bars, version banners) so stdout is
  pure NDJSON that can be round-tripped through `RawArtifact.content` and re-parsed
  deterministically from the stored artifact.
- Nuclei findings map directly to `VULN_CANDIDATE` — the tool reports confirmed template
  matches, not heuristics. Risk scoring (CVSS weighting, EPSS, KEV correlation) stays in
  `services.enrichment`, preserving the collection/enrichment boundary.

**Impact on plan**
- `NucleiAdapter` is auto-discovered by `tests/architecture/test_authorization_gate.py`
  (now 7 tests: 3 per adapter × 2 adapters + 1 discovery guard).
- `apps/api/tasks/scans.py` gained an `elif scanner == "nuclei"` dispatch branch.
- `requirements.txt` unchanged — nuclei binary is a system dependency, not a Python package.

**Cost if we're wrong**
Low. Switching to `-json` (array) changes only `_load_records()` in `nuclei_json.py`.
Removing Nuclei entirely is a two-file delete.

---

### D-014 — Celery + Redis for async scan execution, replacing FastAPI `BackgroundTasks`
**Date:** 2026-09-19
**Decided by:** Mayank Narang
**Type:** Tool choice
**Status:** Active

**Decision**
Scan jobs are dispatched via `execute_scan.delay()` (a Celery task) rather than
FastAPI's built-in `BackgroundTasks`. The task runs in a dedicated `worker`
container, reading from a `scans` Redis queue.

**Why**
`BackgroundTasks` runs inside the same process as the API server. If the server
restarts mid-scan the job is silently lost. Celery persists the task to Redis
before acknowledging the HTTP response (`task_acks_late=True`), so a worker
restart re-queues the job automatically.

Additional factors:
- Redis was already present in the `infra/docker-compose.yml` core profile.
- Built-in retry semantics (`max_retries=3`, `default_retry_delay=30s`) without
  any custom code.
- Horizontal scaling: adding more worker replicas is one compose override.
- Celery's JSON serializer (`task_serializer="json"`) prevents pickle-based
  remote code execution vulnerabilities.

**Impact on plan**
- `_execute_scan_task` removed from `apps/api/routers/scans.py` and moved to
  `apps/api/tasks/scans.py` as `@celery_app.task`.
- `apps/api/worker.py` added as Celery app bootstrap.
- `apps/api/Dockerfile` added; `infra/docker-compose.yml` gains `api` and
  `worker` services under the `core` profile (resolves the TODO comment).
- `Authorization` serialized as a JSON-safe dict (`model_dump(mode="json")`)
  when crossing the Celery message boundary, reconstructed via
  `Authorization.model_validate()` inside the task.

**Cost if we're wrong**
Low. The task body is structurally identical to the old `_execute_scan_task`.
Reverting means moving the function back into the router and swapping
`.delay()` for `background_tasks.add_task()`. One hour of work.

---

### D-013 — Stdlib `xml.etree.ElementTree` for nmap XML, not `defusedxml`
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
`services/scanners/nmap_xml.py` parses nmap output with the standard library's
`xml.etree.ElementTree`, guarded by a size cap and a DOCTYPE check, rather than adding the
`defusedxml` dependency.

**Why**
On Python 3.11, `xml.etree.ElementTree` does not resolve external general entities, so XXE is
not reachable. The residual concern — the billion-laughs entity-expansion attack — requires a
DOCTYPE with an internal subset, which nmap's own XML writer never emits (nmap emits a bare
`<!DOCTYPE nmaprun>`). A DOCTYPE guard that rejects an internal subset or a `SYSTEM`/`PUBLIC`
external identifier, while explicitly allowing nmap's own bare doctype, closes that gap in five
lines with no dependency. `defusedxml` would defend against input nmap structurally cannot
produce, while the real risk — attacker-controlled banner text flowing into logs, Neo4j and an
LLM prompt — is a sanitization problem, not a parser-choice one, and is handled separately by
stripping control characters and capping attribute length in the parser itself.

**Impact on plan**
None. No new dependency; `THIRD_PARTY.md` is unaffected.

**Cost if we're wrong**
Low. Swapping the parse call for `defusedxml.ElementTree.fromstring` is a one-line change behind
the same guard functions if a future scanner's output turns out to make DTD-based attacks
reachable.

---

### D-012 — nmap parser taxonomy: open ports only, method="table" never yields SERVICE_VERSION
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Divergence

**Decision**
`services/scanners/nmap_xml.py` emits only `HOST_UP`, `PORT_OPEN` and `SERVICE_VERSION`
observations from an `nmap -sV` run. Non-open ports (closed, filtered) are not emitted as
observations in this slice. A `<service>` element with `method="table"` (nmap's guess from the
port-number table, not a fingerprint match) never produces a `SERVICE_VERSION`; its name and
method are recorded as attributes on `PORT_OPEN` instead.

**Why**
Non-open ports are real facts, but nothing in the pipeline consumes them until the graph
engine's reachability rules exist (November), and the `RawArtifact` is retained verbatim, so
re-parsing recovers them later without rescanning — deferring costs nothing. `method="table"` is
zero new evidence over the port number itself (it just means "port 80 is `http` per
`/etc/services`"); emitting it as `SERVICE_VERSION` would let enrichment match CVEs against a
guess nmap never actually verified.

**Impact on plan**
None to timeline. Narrows `services/enrichment`'s input to only nmap's genuinely fingerprinted
services, which should reduce false-positive CVE matches once fusion logic lands in October.

**Cost if we're wrong**
Low. Both are additive: a future `REACHABILITY`-kind emission for non-open ports, or a lower-
confidence `SERVICE_VERSION` for `method="table"`, can be added without touching what already
ships. Any attribute-schema change to the emitted kinds does change every downstream
`observation_id` (see D-011), so the more consequential cost is in that decision, not this one.

---

### D-011 — `ScannerAdapter.scan()` returns a `ScanResult`, not a bare observation list
**Date:** 2026-09-18
**Decided by:** Full team
**Type:** Divergence

**Decision**
`services/scanners/base.py`'s `ScannerAdapter.scan()` now returns a new frozen `ScanResult`
(`packages/schema/models/observation.py`) — `{artifact: RawArtifact, observations:
tuple[Observation, ...]}` — instead of `list[Observation]`. The base class constructs the
`RawArtifact` itself, from a new `content_type` class attribute and an overridable
`_captured_at()` hook, and passes the finished artifact into `_parse(artifact, request)`.
`artifact_id` and `observation_id` are both content-derived (sha256), not random or clock-based.

**Why**
`Observation.artifact_id` is required and points at a `RawArtifact` that the architecture
retains verbatim for provenance — but the prior `scan() -> list[Observation]` signature gave
that artifact nowhere to go; it was constructed nowhere and returned nowhere. Provenance was a
dangling pointer from the moment `Observation` was written. Fixing this in the base class, not
each adapter, mirrors why the authorization gate lives there: every adapter gets identical,
correct handling for free. Taking the wall clock exactly once in `scan()` (via `_captured_at`)
and threading it into `_parse` as data is what lets `_parse` be a pure, replayable function —
the property `tests/fixtures/observations/` depends on.

**Impact on plan**
Touches every future scanner adapter (nuclei and beyond): each sets a `content_type` class
attribute, may override `_captured_at()`, and implements `_parse(artifact, request) ->
tuple[Observation, ...]` instead of the old `_parse(raw, request) -> list[Observation]`. No
architecture test broke — `tests/architecture/test_authorization_gate.py` only exercises the
raise-before-`_execute` path.

**Cost if we're wrong**
Low. `ScanResult` is an additive wrapper; reverting to a bare list (with the artifact problem
unsolved) is a small, mechanical change if a future design supersedes it.

---

### D-010 — Keep str+Enum for schema enums; suppress ruff UP042 project-wide
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
`Source`, `Confidence`, and `ObservationKind` in `packages/schema/models/` stay declared as
`class X(str, Enum)` rather than converting to `enum.StrEnum`. Ruff's `UP042` rule, which
suggests the conversion, is suppressed project-wide in `pyproject.toml`.

**Why**
`StrEnum` can subtly change `__str__` and serialization behavior compared to the `(str, Enum)`
mixin, and these three enums sit at the schema package's JSON/Pydantic-v2 serialization
boundary — exactly the kind of change `packages/schema/README.md` asks us to be careful with.
Converting them as an incidental side effect of onboarding CI (rather than a deliberate,
tested decision) would risk changing serialization behavior nobody asked to change.

**Impact on plan**
None. A lint rule is suppressed; no runtime behavior changes.

**Cost if we're wrong**
Very low. If we later want `StrEnum`, it is a small, deliberate, testable conversion — nothing
about this decision blocks it, it only prevents it from happening accidentally.

---

### D-009 — Pydantic v2 replaces dataclasses in packages/schema
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Divergence
**Status:** Active

**Decision**
Convert `packages/schema` from plain `@dataclass` to Pydantic v2 `BaseModel`.

**Why**
`CLAUDE.md` already requires "Pydantic models for anything crossing a boundary," and the
committed code does not do this — the divergence exists today and this resolves it in favour
of the rule. Three concrete gains: validation at every boundary, deterministic serialization
that the graph purity test depends on, and FastAPI request/response models for free.

**Impact on plan**
Phase 0 work, before any feature code depends on the current shapes. Doing it later means
touching every module that imports schema.

**Cost if we're wrong**
Very low. Pydantic v2 models are close enough to dataclasses that reverting is mechanical, and
the conversion happens while almost nothing imports them.

---

### D-008 — ERS weights hand-tuned and documented, not learned
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Exposure Risk Score component weights are chosen by hand, documented with reasoning, and
published with a sensitivity analysis. KEV membership is used to *validate* the resulting
ranking, not as a training target.

**Why**
Learning weights requires labelled data telling us which exposures actually mattered, and we
do not have it. A learned number we cannot justify is worse in a viva than a stated weighting
we can defend line by line. Sensitivity analysis shows which weights actually change the
ranking, which is a more honest result than a fitted model on 200 hosts.

Reinforces the standing constraint from `services/enrichment/README.md`: never multiply EPSS
by CVSS. Components combine additively with stated weights, each rendering its own explanation
through `ScoreComponent`.

**Impact on plan**
Removes a modelling task from the enrichment layer. The ML effort concentrates on the gap-
filler classifier instead, where a published BRON baseline exists to beat.

**Cost if we're wrong**
Low. If hand-tuned weights rank badly and we later obtain labels, the `ScoreComponent`
structure already separates weights from components, so fitting them is a contained change.

---

### D-007 — Row-level engagement scoping, not schema-per-tenant
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Every row carries an `engagement_id`. No schema-per-tenant, no row-level security policies.

**Why**
Deliberate YAGNI. This project has no tenants and will not acquire any before January.
Schema-per-tenant buys isolation we do not need and costs migration complexity in every month
we do have.

**Impact on plan**
None. Simplifies the data layer.

**Cost if we're wrong**
Low within this project's life. If real multi-tenancy is ever needed, `engagement_id` is
already the discriminator a stronger isolation model would key on.

---

### D-006 — Ollama for model serving, behind a ModelClient interface
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Serve Foundation-Sec-8B-Reasoning through Ollama in every environment. Access it only through
a `ModelClient` interface in `services/assistant`.

**Why**
The architecture doc previously assumed "Ollama for dev, vLLM for demo," but vLLM assumes
server-class hardware we do not have — development and the demo both happen on 16 GB laptops.
Running one serving path everywhere also removes a class of demo-day surprise.

The interface means a future vLLM or hosted endpoint is a swap, not a rewrite.

**Impact on plan**
Removes vLLM from the stack. Model runs quantized, in the `model` compose profile, never
alongside the lab.

**Cost if we're wrong**
Low. The interface is the insurance. If Ollama throughput proves inadequate for the demo,
swapping the implementation is a contained change.

---

### D-005 — pgvector, not Qdrant
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Vector storage and retrieval for the assistant use pgvector inside our existing Postgres.

**Why**
Postgres is already in the stack. Qdrant is a second service, a second backup story, and
another ~300 MB on a memory budget that is already oversubscribed. At our corpus size —
findings and observations from a few hundred hosts — pgvector's performance is not a
constraint, and keeping retrieval next to the facts makes citation joins trivial.

**Impact on plan**
One fewer service in `infra/docker-compose.yml`.

**Cost if we're wrong**
Low. Retrieval sits behind an interface in `services/assistant/retrieval.py`; the corpus is
small enough to re-index into a different store in an afternoon.

---

### D-004 — Python rules-as-data, not Datalog
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Attack path rules are declared as YAML in `services/graph/rules/` and evaluated by a small
deterministic Python engine. No Datalog, no Prolog, no XSB.

**Why**
MulVAL's Datalog semantics are worth studying and we will reimplement the ideas, but adopting
Datalog itself means a second language, an XSB dependency, and debugging that is genuinely
hard when a path comes out wrong under time pressure. With one strong developer and two still
building Python fluency, that cost lands in the wrong place.

Rules-as-data still satisfies the standing requirement in `services/graph/README.md` that
rules be data rather than code, so they can be cited in the report and extended without
touching the engine. Each rule carries a `citation` field.

**Impact on plan**
No timeline change. Concentrates November's difficulty in one engine module that a single
developer can own.

**Cost if we're wrong**
Medium. If YAML rules prove too weak to express the semantics we need, we would rewrite the
evaluator — but the rules themselves, being data, largely survive that rewrite.

---

### D-003 — Postgres facts plus in-memory NetworkX; Neo4j as a read-only projection
**Date:** 2026-09-05
**Decided by:** Full team
**Type:** Tool choice
**Status:** Active

**Decision**
Postgres holds an append-only store of immutable, provenance-tagged observations. The attack
graph is rebuilt in memory with NetworkX from those facts on demand and is never a source of
truth. Neo4j is committed as a **read-only projection** for visualization, rebuilt from facts,
disposable at any time, landing with the graph builder in November behind a `viz` profile.

**Why**
Four reasons, in order of weight.

Determinism becomes a structural property rather than a promise: if the graph is a pure
function of facts, the same observations produce byte-identical paths, and that is a test we
run in CI. A mutable graph database accumulates state and drifts, so we would be asserting
determinism on a substrate that does not enforce it.

Remediation simulation — mark a vulnerability fixed, recompute, show which paths disappear —
is our best demo moment, and it is natural over an in-memory rebuild and awkward over a
persistent store. Chokepoint analysis has the same shape. Both are brute-force loops that are
free when a rebuild costs milliseconds.

The rules engine must be Python regardless, because every edge carries `rule_name` and
`evidence` attached at creation. A graph database would only store and re-query what Python
already computed, making it a persistence choice rather than a reasoning one.

Scale does not justify it. At 50–200 hosts the graph is a few thousand nodes, and the BRON
traversal (CVE→CWE→CAPEC→ATT&CK) is fixed-depth — three joins, not graph traversal. Neo4j's
advantages do not activate at this size, but its ~1.5–2.5 GB does.

We considered making Neo4j the graph of record and rejected it: path rules would become
Cypher, which is code rather than data, weakening the claim that our rules are citable.

**Impact on plan**
Neo4j moves from Month 1 infrastructure to a November deliverable alongside the graph builder,
and is second on the cut list. Frees memory during development and removes a second query
language from the two months where the team is least experienced.

**Cost if we're wrong**
Low to medium. If the in-memory graph outgrows a laptop — which would require a scale far
beyond the scoped 50–200 hosts — the graph builder writes through a `GraphSink` interface, so
a persistent backend is an added implementation rather than a rewrite.

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
