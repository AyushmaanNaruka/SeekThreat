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
| Enrichment coverage vs NVD-only | **Measured (2026-10-11)**: **98.0%** multi-source fusion vs **73.0%** NVD-only baseline (**+25.0 pp delta**) on 50 verified golden CVEs across 5 cohorts. See [`evals/results/enrichment_coverage_real.md`](./results/enrichment_coverage_real.md). |
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

**All reported evaluation numbers must come directly from executed code against real mirrors.** Never generate placeholder metrics or estimates. Layer 2 enrichment coverage was empirically measured and committed on 2026-10-11 using genuine feed mirrors and real-world CVE ground truth.
