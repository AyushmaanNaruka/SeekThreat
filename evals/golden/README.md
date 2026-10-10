# Golden dataset

Question/answer pairs with verified ground truth. One JSONL file per category.

```
cve_lookups.jsonl
remediation.jsonl
attack_paths.jsonl
prioritization.jsonl
adversarial.jsonl        # correct answer is "I don't have that data"
multi_hop.jsonl
```

Entry format:

```json
{
  "id": "cve-001",
  "question": "What is the severity of CVE-2021-41773 on our DMZ web host?",
  "reference_answer": "...",
  "required_sources": ["cve.org", "first.epss"],
  "lab_configuration": "baseline",
  "verified_by": "name",
  "verified_at": "2026-09-01"
}
```

Every entry must be verifiable against `lab/ground_truth.yaml` or an authoritative source.
Never write a reference answer from memory.

## `enrichment_baseline.json` (enrichment coverage harness input)

Input list for `evals/enrichment_coverage.py`, not a verified golden set.

- `_synthetic: true` and `"verification": "unverified — ..."`: the cohort labels
  ("NVD control", "NVD gap", "high EPSS / no NVD", ...) are **hypotheses**. Nobody has
  checked them against live NVD, CVE.org, KEV or EPSS data.
- The harness reads only `cve_id` and `cohort`. `title` is a human-readable label and is
  not checked. Earlier versions carried `expected_sources` and `notes`; they were never
  asserted by anything and were removed rather than left looking like verified facts.
- Before any cohort result is quoted as a finding, each item needs a `verified_by` /
  `verified_at` against a dated real mirror (see the entry format above).
