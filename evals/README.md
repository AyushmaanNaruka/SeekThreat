# evals/

The evaluation harness. **Built in September, not January.**

We cannot retrofit measurement onto a finished system. Bad numbers in month two are fine.
Missing numbers in month six are fatal.

**Co-owned by all three of us.** Anything owned by one person becomes nobody's priority.

## Two tracks

**Track A — the brief's metrics, satisfied literally**

| Metric | Applied to |
|---|---|
| Accuracy, precision, recall, F1 | Vulnerability detection vs `lab/ground_truth.yaml` |
| Macro-F1 | CVE -> ATT&CK classifier |
| MAE | Derived CVSS for unenriched CVEs |
| BLEU / ROUGE | Assistant answers |

**Track B — what actually measures the system**

| Metric | Target |
|---|---|
| Faithfulness | >= 0.85 |
| Context precision | >= 0.80 |
| Context recall | >= 0.80 |
| Answer relevancy | >= 0.85 |
| Citation accuracy | >= 0.95 |
| Attack path validity | >= 0.90 (manual, N=50) |
| Enrichment coverage vs NVD-only | our strongest single number |
| Dedup precision/recall | vs DefectDojo on identical input |

Report both. Explain why Track B matters more. Questioning the metric is itself a
differentiator.

## Golden dataset — target ~500 items

| Count | Type |
|---|---|
| 150 | Factual CVE lookups with verifiable ground truth |
| 100 | Remediation questions with authoritative references |
| 75 | Attack path questions against known lab topologies |
| 75 | Prioritization — "what should I fix first and why" |
| 50 | Adversarial / out-of-scope, where the right answer is "I don't have that data" |
| 50 | Multi-hop requiring graph traversal plus retrieval |

Lives in `evals/golden/`.

## Rule

**No number in this project has been measured yet.** Never generate placeholder metrics that
look like results. If a chart needs data we don't have, label it "Target" or leave it out.
