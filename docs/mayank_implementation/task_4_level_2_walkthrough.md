# Walkthrough - Task 4: Exposure Risk Score (ERS) Engine (Track 2 — Enrichment)

> **Document:** `docs/mayank_implementation/task_4_level_2_walkthrough.md`  
> **Topic:** Task 4 (Track 2 Enrichment — Exposure Risk Score Engine & D-008 Invariants) Walkthrough  
> **Status:** Completed & Verified  

---

## 1. Overview & Objective

In accordance with [level2_status.md](file:///e:/SeekThreat/SeekThreat/docs/mayank_implementation/level2_status.md#L154), [services/enrichment/README.md](file:///e:/SeekThreat/SeekThreat/services/enrichment/README.md#L36), and [DECISIONS.md D-008](file:///e:/SeekThreat/SeekThreat/DECISIONS.md#L633), **Task 4** implements SeekThreat's composite **Exposure Risk Score (ERS)** engine in `services/enrichment/ers.py`.

### Load-Bearing Principles & Non-Negotiable Rules

1. **NEVER multiply EPSS by CVSS (Rule 3):**
   * A common industry mistake is computing `Risk = Probability × Impact` by multiplying `EPSS × CVSS`. The FIRST EPSS Special Interest Group is explicit that the mathematical product of EPSS (a probability measure) and CVSS (an ordinal severity score, not a continuous financial loss metric) is meaningless.
   * In SeekThreat, components combine **strictly additively** as a weighted sum.
2. **Hand-Tuned, Documented Weights (D-008):**
   * Learning weights requires labelled real-world exposure loss data that does not exist for academic test networks. In a viva defense, a transparent weighting that can be defended line-by-line is far superior to an unexplainable fitted black box.
   * Weights are normalized such that $\sum w_i = 1.0$.
3. **KEV Validates; It Does Not Train (D-008):**
   * CISA KEV membership provides an additive validation boost reflecting confirmed active weaponization in the wild. It validates the elevated prioritization of critical vulnerabilities, but does not solely dictate the score.
4. **Self-Explaining Breakdown (Rule 4):**
   * Every score is emitted as an [ExposureRiskScore](file:///e:/SeekThreat/SeekThreat/packages/schema/models/scoring.py#L40) model containing individual [ScoreComponent](file:///e:/SeekThreat/SeekThreat/packages/schema/models/scoring.py#L20) records. Every component carries its own human-readable explanation and non-null [Provenance](file:///e:/SeekThreat/SeekThreat/packages/schema/models/provenance.py#L43). Opaque risk numbers are completely unrepresentable.

---

## 2. What Was Built

### A. ERS Engine & Additive Formula
* **[services/enrichment/ers.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/ers.py)**:
  * Hand-tuned documented weights:
    * `DEFAULT_WEIGHT_CVSS = 0.40`: Reflects technical severity, impact on confidentiality/integrity/availability, and exploit vector characteristics.
    * `DEFAULT_WEIGHT_EPSS = 0.35`: Reflects empirical 30-day exploitation probability in the wild from FIRST EPSS v4.
    * `DEFAULT_WEIGHT_KEV = 0.25`: Provides an additive validation boost for confirmed active exploitation.
  * Standardized Component Scaling: All component values are normalized to a consistent `0.0 – 10.0` scale:
    * `CVSS Base Severity`: `cvss_score` directly on `[0.0, 10.0]`.
    * `EPSS Exploit Likelihood`: `epss_score * 10.0` (scaling `[0.0, 1.0]` probability to `[0.0, 10.0]`).
    * `CISA KEV Active Exploitation`: `10.0` if `in_kev` is `True`, else `0.0`.
  * `calculate_ers(fields, weights=...) -> ExposureRiskScore`:
    * Constructs 3 validated `ScoreComponent` instances with detailed explanations and attached provenance.
    * Computes composite value: $\text{ERS} = \sum (\text{value}_i \times \text{weight}_i)$.
    * Guaranteed to satisfy `ExposureRiskScore`'s model validator: $|\text{value} - \sum (c_i \cdot w_i)| \le 10^{-6}$.
  * `ERSWeights`: Immutable configuration dataclass enforcing $\sum w_i = 1.0$.

---

### B. Pipeline Integration
* **[services/enrichment/fusion.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/fusion.py)**:
  * Updated `fuse_to_enriched_finding(finding, compute_ers=True)`:
    * Automatically runs `calculate_ers(fields)` and attaches the verified composite `ExposureRiskScore` to `EnrichedFinding.ers`.
* **[services/enrichment/__init__.py](file:///e:/SeekThreat/SeekThreat/services/enrichment/__init__.py)**:
  * Exported `calculate_ers`, `ERSWeights`, and default weight constants.

---

## 3. Verification & Test Results

### Automated Test Suite
We implemented 8 comprehensive tests in [tests/unit/test_ers_invariants.py](file:///e:/SeekThreat/SeekThreat/tests/unit/test_ers_invariants.py):
1. **Anti-Multiplication Regression Guard (`test_ers_is_never_literally_epss_times_cvss`)**:
   * Evaluates all baseline findings and asserts that `abs(ers.value - (cvss * epss)) > 0.05`.
   * Proves that ERS is an additive weighted sum and never degenerates into the forbidden multiplicative product.
2. **Additive Weighted Sum Invariant (`test_ers_value_matches_weighted_sum_of_components`)**:
   * Asserts `abs(ers.value - sum(c.value * c.weight)) < 1e-6` across all findings.
3. **Weight Validation (`test_weights_sum_to_one` & `test_invalid_weights_raise_value_error`)**:
   * Verifies default weights sum to 1.0 and malformed weights raise `ValueError`.
4. **KEV Additive Boost Behavior (`test_kev_boosts_score_additively` & `test_kev_presence_does_not_solely_determine_high_score`)**:
   * Asserts KEV adds an exact $+2.5$ point boost ($10.0 \times 0.25$) when present.
   * Asserts that a low-severity vulnerability with KEV membership does not artificially inflate to critical ($<4.0$).
5. **Self-Explaining Component Output (`test_every_component_has_explanation_and_provenance`)**:
   * Verifies all components contain non-empty explanations, valid `Provenance`, and that `.explain()` renders a complete textual breakdown.
6. **Full EnrichedFinding Integration (`test_fuse_to_enriched_finding_attaches_ers`)**:
   * Verifies end-to-end attachment of `ExposureRiskScore` to `EnrichedFinding`.

```bash
python -m pytest tests/unit/test_ers_invariants.py -v
```
**Output:**
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\SeekThreat\SeekThreat
configfile: pyproject.toml
plugins: anyio-4.13.0
collected 8 items

tests\unit\test_ers_invariants.py::TestERSAntiMultiplicationInvariant::test_ers_is_never_literally_epss_times_cvss PASSED [ 12%]
tests\unit\test_ers_invariants.py::TestERSAdditiveFormulasAndWeights::test_ers_value_matches_weighted_sum_of_components PASSED [ 25%]
tests\unit\test_ers_invariants.py::TestERSAdditiveFormulasAndWeights::test_weights_sum_to_one PASSED [ 37%]
tests\unit\test_ers_invariants.py::TestERSAdditiveFormulasAndWeights::test_invalid_weights_raise_value_error PASSED [ 50%]
tests\unit\test_ers_invariants.py::TestKEVValidationBoostBehavior::test_kev_boosts_score_additively PASSED [ 62%]
tests\unit\test_ers_invariants.py::TestKEVValidationBoostBehavior::test_kev_presence_does_not_solely_determine_high_score PASSED [ 75%]
tests\unit\test_ers_invariants.py::TestERSSelfExplainingOutput::test_every_component_has_explanation_and_provenance PASSED [ 87%]
tests\unit\test_ers_invariants.py::TestERSSelfExplainingOutput::test_fuse_to_enriched_finding_attaches_ers PASSED [100%]

============================== 8 passed in 1.13s ==============================
```

### Full Regression & Architecture Guard Execution
- Track 2 test suite: **39 passed** across all 4 test files.
- Entire unit test suite: **266 passed, 1 skipped** (`python -m pytest tests/unit/`).
- Architecture gates: **11 passed** (`python -m pytest tests/architecture/`).

---

## 4. Next Step

With Tasks 1 through 4 complete, the enrichment and scoring pipeline is fully functional in memory. We can now proceed to **Task 5: Database Persistence & Idempotent Upsert (`apps/api/db`)**, adding SQLAlchemy ORM models, an Alembic migration, and an idempotent repository for `EnrichedFinding`.
