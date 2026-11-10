# Assistant evaluation (Layer 4, Track B)

> **FIXTURE-BASED, NOT A LAB RUN. The engagement is tests/fixtures/observations/ (8 of 10 lab hosts synthetic), and the golden set is generated from that same engagement by evals/scripts/build_assistant_golden.py.**

> Faithfulness is an entity-level proxy (deterministic grounding check on CVE ids, IPs, ports and citation ids), not RAGAS LLM-judged claim faithfulness.

**Mode:** measurement (Ollama)  
**Model:** `qwen2.5:7b`; **embed model:** `nomic-embed-text`; **judge:** `off`  
**Ollama:** http://localhost:11434 (version 0.40.15)  
**Golden set:** `evals/golden` sha256 `e53f73b5d74386fc613abc6415fd9179ae4e9b4c3039f16672f9ea103f3a2366` (generator 1.0.0)  
**Items:** 138 (cve_lookups 39, remediation 15, attack_paths 28, prioritization 17, adversarial 23, multi_hop 16); documents indexed 66; retrieval limit 8  
**Run at:** 2026-11-07T04:35:16+00:00; **git:** `8484ba6088a9ac9896de936c00c45892643ba9c3` (dirty)

## Results

| Metric | Overall | cve_lookups | remediation | attack_paths | prioritization | adversarial | multi_hop |
|---|---|---|---|---|---|---|---|
| Faithfulness (answered, entity proxy) | 0.500 | 0.526 | 0.333 | 0.000 | 1.000 | n/a | 0.714 |
| Faithfulness (all items) | 0.833 | 0.769 | 0.867 | 0.643 | 1.000 | 1.000 | 0.875 |
| Claim-entity precision | 0.619 | 0.722 | 0.900 | 0.286 | 1.000 | n/a | 0.722 |
| Context precision | 0.117 | 0.125 | 0.133 | 0.062 | 0.176 | n/a | 0.117 |
| Context recall | 0.732 | 1.000 | 0.633 | 0.500 | 0.882 | n/a | 0.417 |
| Citation accuracy | 0.481 | 0.433 | 0.500 | 0.238 | 1.000 | n/a | 0.545 |
| Uncited answer rate | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | n/a | 0.000 |
| Answer correctness (must-mention recall) | 0.323 | 0.487 | 0.067 | 0.239 | 0.382 | n/a | 0.250 |
| Refusal accuracy | 1.000 | n/a | n/a | n/a | n/a | 1.000 | n/a |
| False refusal rate | 0.600 | 0.513 | 0.800 | 0.643 | 0.588 | n/a | 0.562 |
| Answer relevancy (embedding cosine) | 0.816 | 0.840 | 0.748 | 0.768 | 0.782 | n/a | 0.881 |
| Latency mean / p95 (s) | 16.952 / 40.067 | 19.036 / 79.401 | 14.477 / 26.291 | 21.675 / 44.112 | 16.622 / 37.947 | 11.549 / 27.678 | 14.047 / 26.177 |

Answered 46/138; grounding entities checked 160, unsupported 61; citations 79 (36 invalid).

## Golden-set diagnostics

Every required_ref is an indexed document and holds its must_mention entities.

## Metric definitions

- **faithfulness_answered**: Share of answered (non-refused) items whose grounding check has no unsupported entity and no invalid citation. Entity-level proxy, not RAGAS.
- **faithfulness_all**: Same check over all items; refusals count as faithful, so this is inflated by refusals.
- **claim_entity_precision**: Answered items: sum(checked - unsupported) / sum(checked) grounding entities.
- **context_precision**: Items with required_refs: mean |retrieved ∩ required| / |retrieved| by doc id (plain set overlap, not rank-weighted).
- **context_recall**: Items with required_refs: mean |retrieved ∩ required| / |required|.
- **citation_accuracy**: Citations in answered items: correct when the cited id was retrieved and supplied (not invalid) AND it is a required_ref or its text contains a must_mention entity or alias. Micro-averaged over citations.
- **answer_correctness_proxy**: Non-refusal items: mean share of must_mention entities (or aliases) the answer contains, whole-token, case-insensitive.
- **refusal_accuracy**: expect_refusal items: share the assistant refused.
- **false_refusal_rate**: Items not expecting refusal: share the assistant refused.
- **answer_relevancy_embedding**: Answered items: mean cosine(embed(question), embed(answer)) with the retrieval embed model. Not RAGAS answer relevancy.
- **latency_s**: Wall-clock seconds per answer_question call.
- **uncited_answer_rate**: Answered items whose answer carries no citation at all.

## Unfaithful or wrongly (non-)refused items

| Item | Refused | Expected refusal | Unsupported | Invalid citations |
|---|---|---|---|---|
| cve_lookups-002 | False | False | 172.20.1.12, 80/tcp, CVE-2022-26134, 172.20.2.40, 8090/tcp | chokepoint:path:456a860ed4f55b66 |
| cve_lookups-003 | True | False | - | - |
| cve_lookups-005 | False | False | - | path:08fea8d14814606ae |
| cve_lookups-007 | True | False | - | - |
| cve_lookups-008 | False | False | CWE-94 | - |
| cve_lookups-011 | True | False | - | - |
| cve_lookups-012 | False | False | CWE-444 | - |
| cve_lookups-014 | False | False | 172.20.2.25, 8080/tcp | chokepoint:doc-8 |
| cve_lookups-015 | True | False | - | - |
| cve_lookups-018 | False | False | 172.20.2.40, 8090/tcp, CWE-917 | chokepoint:Step, 4:, Network, access, to, 172.20.2.40:8090/tcp, (http), -[exploit_grants_code_execution, high |
| cve_lookups-019 | True | False | - | - |
| cve_lookups-020 | False | False | CWE-917, 8090/tcp | chokepoint:581f6d5c38e90add221be337e4aa9e95 |
| cve_lookups-021 | True | False | - | - |
| cve_lookups-022 | False | False | lab-dvwa-1.lab_dmz | - |
| cve_lookups-023 | True | False | - | - |
| cve_lookups-024 | True | False | - | - |
| cve_lookups-025 | True | False | - | - |
| cve_lookups-026 | True | False | - | - |
| cve_lookups-027 | True | False | - | - |
| cve_lookups-028 | False | False | - | observation:obs:sha256:6fecb0c090059d0881dae6c1cc96d04e648d07969b64362c4e5313ff1a4c28b2 |
| cve_lookups-029 | True | False | - | - |
| cve_lookups-030 | True | False | - | - |
| cve_lookups-031 | True | False | - | - |
| cve_lookups-032 | True | False | - | - |
| cve_lookups-033 | True | False | - | - |
| cve_lookups-034 | True | False | - | - |
| cve_lookups-036 | True | False | - | - |
| cve_lookups-037 | True | False | - | - |
| cve_lookups-038 | True | False | - | - |
| remediation-001 | False | False | 172.20.2.12 | doc:6 |
| remediation-002 | True | False | - | - |
| remediation-003 | False | False | - | obs:sha256:1e1773838a21e6f6e409f6a59d6546e18453622a6818e91b7e0e4facad984fe |
| remediation-004 | True | False | - | - |
| remediation-005 | True | False | - | - |
| remediation-006 | True | False | - | - |
| remediation-008 | True | False | - | - |
| remediation-009 | True | False | - | - |
| remediation-010 | True | False | - | - |
| remediation-011 | True | False | - | - |
| remediation-012 | True | False | - | - |
| remediation-013 | True | False | - | - |
| remediation-014 | True | False | - | - |
| remediation-015 | True | False | - | - |
| attack_paths-001 | False | False | - | step, 2 |
| attack_paths-002 | True | False | - | - |
| attack_paths-003 | True | False | - | - |
| attack_paths-004 | True | False | - | - |
| attack_paths-005 | True | False | - | - |
| attack_paths-006 | True | False | - | - |
| attack_paths-007 | False | False | 172.20.2.25, CVE-2024-23897, CWE-22, 172.20.2.50, 172.20.3.50, 2222/tcp | - |
| attack_paths-008 | False | False | 172.20.2.50, 172.20.3.50 | path:096cb4fb98f61033#Step, 5, path:096cb4fb98f61033#Steps, path:096cb4fb98f61033#Confidence |
| attack_paths-009 | False | False | 172.20.2.50, 172.20.3.50 | path:548885330dcf2552#Step, 4, 1, 2, 3 |
| attack_paths-010 | True | False | - | - |
| attack_paths-011 | True | False | - | - |
| attack_paths-012 | False | False | 172.20.2.25, 172.20.2.50, 172.20.3.50 | - |
| attack_paths-013 | False | False | 172.20.1.12, 80/tcp, 172.20.2.12, CVE-2021-23017, CWE-787, 172.20.2.50, 172.20.3.50, 2222/tcp | path:4607aa75a14db9bb |
| attack_paths-014 | True | False | - | - |
| attack_paths-015 | False | False | 172.20.2.25, 8080/tcp, 172.20.2.50, 172.20.3.50 | path:70156497ce6bf424 |
| attack_paths-016 | True | False | - | - |
| attack_paths-017 | True | False | - | - |
| attack_paths-018 | True | False | - | - |
| attack_paths-019 | True | False | - | - |
| attack_paths-020 | True | False | - | - |
| attack_paths-021 | False | False | 172.20.2.25, 8080/tcp, 172.20.2.50, 172.20.3.50, 2222/tcp | path:fa8d6d52127db009 |
| attack_paths-022 | False | False | 172.20.2.25, 8080/tcp, 172.20.2.50, 172.20.3.50 | path:301739ec12db08bf |
| attack_paths-023 | True | False | - | - |
| attack_paths-024 | True | False | - | - |
| attack_paths-025 | False | False | 172.20.1.12, 80/tcp, CWE-917, 172.20.2.50, 172.20.3.50, 2222/tcp | path:1595d00ce9530ac0 |
| attack_paths-026 | True | False | - | - |
| attack_paths-027 | True | False | - | - |
| attack_paths-028 | True | False | - | - |
| prioritization-001 | True | False | - | - |
| prioritization-003 | True | False | - | - |
| prioritization-005 | True | False | - | - |
| prioritization-007 | True | False | - | - |
| prioritization-008 | True | False | - | - |
| prioritization-009 | True | False | - | - |
| prioritization-010 | True | False | - | - |
| prioritization-011 | True | False | - | - |
| prioritization-016 | True | False | - | - |
| prioritization-017 | True | False | - | - |
| multi_hop-003 | False | False | CVE-2022-22947, 172.20.1.13, 172.20.2.13, CVE-2022-26134, 172.20.2.40 | exploit_grants_code_execution:fnd-103129260b2f1a5740feabc1, exploit_grants_code_execution:fnd-b9304ff0dffb57c0a8eb7ac5 |
| multi_hop-005 | True | False | - | - |
| multi_hop-006 | True | False | - | - |
| multi_hop-007 | True | False | - | - |
| multi_hop-008 | False | False | - | sha256:5fb6d5dba8bf29154a294e43c885cb4a3b581d849a653faf7795556252b00d58, sha256:703f21796245c5140cd63ea87b5c79f9cedb07ffe7715e16ee9a3f936ec5136e |
| multi_hop-009 | True | False | - | - |
| multi_hop-011 | True | False | - | - |
| multi_hop-012 | True | False | - | - |
| multi_hop-014 | True | False | - | - |
| multi_hop-015 | True | False | - | - |
| multi_hop-016 | True | False | - | - |
