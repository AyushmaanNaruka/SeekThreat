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
