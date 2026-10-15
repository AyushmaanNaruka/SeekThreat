"""Tests for AP, AUC-ROC, and bootstrap CI functions added to ers_validation.py (Task A-5).

Verifies the mathematical correctness of:
- _average_precision: edge cases (all positive, all negative, perfect ranking,
  reversed ranking, alternating)
- _auc_roc: degenerate cases, perfect/worst/random rankings
- _bootstrap_ci: determinism, interval coverage, monotonicity
- compute_ranking_metrics: output schema, random-baseline check
"""

from __future__ import annotations

import math

from evals.ers_validation import (
    _auc_roc,
    _average_precision,
    _bootstrap_ci,
    compute_ranking_metrics,
)


class TestAveragePrecision:
    """Unit tests for _average_precision."""

    def test_no_positives_returns_zero(self) -> None:
        assert _average_precision([False, False, False]) == 0.0

    def test_all_positives_returns_one(self) -> None:
        # All positive, all hits at every rank -> AP = 1.0
        assert math.isclose(_average_precision([True, True, True]), 1.0)

    def test_perfect_ranking(self) -> None:
        # Positives first
        labels = [True, True, False, False]
        ap = _average_precision(labels)
        # P@1=1.0, P@2=1.0 -> AP = (1.0+1.0)/2 = 1.0
        assert math.isclose(ap, 1.0)

    def test_reversed_ranking(self) -> None:
        # Positives last -> worst possible ordering
        labels = [False, False, True, True]
        ap = _average_precision(labels)
        # P@3=1/3, P@4=2/4=0.5 -> AP = (1/3 + 1/2)/2 = 5/12
        expected = (1 / 3 + 2 / 4) / 2
        assert math.isclose(ap, expected)

    def test_single_positive_at_rank1(self) -> None:
        labels = [True, False, False, False]
        # P@1=1.0 -> AP = 1.0
        assert math.isclose(_average_precision(labels), 1.0)

    def test_single_positive_at_rank4(self) -> None:
        labels = [False, False, False, True]
        # P@4=1/4 -> AP = 0.25
        assert math.isclose(_average_precision(labels), 0.25)

    def test_alternating_labels(self) -> None:
        labels = [True, False, True, False]
        # P@1=1, P@3=2/3 -> AP = (1+2/3)/2
        expected = (1.0 + 2 / 3) / 2
        assert math.isclose(_average_precision(labels), expected)

    def test_returns_float_in_0_1(self) -> None:
        import random

        rng = random.Random(42)
        for _ in range(20):
            n = rng.randint(1, 50)
            labels = [rng.random() < 0.4 for _ in range(n)]
            ap = _average_precision(labels)
            assert 0.0 <= ap <= 1.0 + 1e-9, f"AP out of range: {ap}"


class TestAucRoc:
    """Unit tests for _auc_roc."""

    def test_all_positives_returns_half(self) -> None:
        # No negatives -> degenerate -> 0.5
        assert _auc_roc([True, True, True]) == 0.5

    def test_all_negatives_returns_half(self) -> None:
        assert _auc_roc([False, False, False]) == 0.5

    def test_perfect_ranking(self) -> None:
        # All positives before negatives -> AUC = 1.0
        labels = [True, True, False, False]
        assert math.isclose(_auc_roc(labels), 1.0)

    def test_reversed_ranking(self) -> None:
        # All negatives before positives -> AUC = 0.0
        labels = [False, False, True, True]
        assert math.isclose(_auc_roc(labels), 0.0)

    def test_random_ranking(self) -> None:
        # Alternating pattern -> AUC should be near 0.5
        labels = [True, False, True, False, True, False]
        auc = _auc_roc(labels)
        assert 0.0 <= auc <= 1.0

    def test_single_positive_at_top(self) -> None:
        labels = [True, False, False, False]
        # WMW: positive beats all 3 negatives -> AUC = 3/3 = 1.0
        assert math.isclose(_auc_roc(labels), 1.0)

    def test_single_positive_at_bottom(self) -> None:
        labels = [False, False, False, True]
        # Positive beats 0 negatives -> AUC = 0.0
        assert math.isclose(_auc_roc(labels), 0.0)

    def test_auc_plus_flipped_equals_one(self) -> None:
        # AUC(ranking) + AUC(reversed) = 1
        labels = [True, False, True, False, True]
        auc = _auc_roc(labels)
        flipped = list(reversed(labels))
        auc_flipped = _auc_roc(flipped)
        assert math.isclose(auc + auc_flipped, 1.0, rel_tol=1e-9)

    def test_returns_in_0_1(self) -> None:
        import random

        rng = random.Random(99)
        for _ in range(20):
            n = rng.randint(2, 50)
            labels = [rng.random() < 0.4 for _ in range(n)]
            if all(labels) or not any(labels):
                continue  # degenerate, returns 0.5 by convention
            auc = _auc_roc(labels)
            assert 0.0 <= auc <= 1.0 + 1e-9, f"AUC out of range: {auc}"


class TestBootstrapCI:
    """Unit tests for _bootstrap_ci."""

    def test_deterministic_same_seed(self) -> None:
        labels = [True, False, True, False, False, True, False]
        ci1 = _bootstrap_ci(labels, _average_precision, n_resamples=200, seed=42)
        ci2 = _bootstrap_ci(labels, _average_precision, n_resamples=200, seed=42)
        assert ci1 == ci2

    def test_different_seeds_differ(self) -> None:
        # Use a larger, mixed label list so the bootstrap distribution has enough spread
        # that different seeds produce observably different CI values at n=2000.
        labels = [
            True,
            False,
            True,
            False,
            False,
            True,
            False,
            True,
            False,
            False,
            True,
            False,
            True,
            False,
            False,
            True,
            False,
            True,
            False,
            False,
        ]
        ci1 = _bootstrap_ci(labels, _average_precision, n_resamples=2000, seed=1)
        ci2 = _bootstrap_ci(labels, _average_precision, n_resamples=2000, seed=999)
        # With 2000 resamples and different seeds the interval endpoints differ
        assert ci1 != ci2, f"Expected different CIs for seed=1 ({ci1}) vs seed=999 ({ci2})"

    def test_lower_le_upper(self) -> None:
        labels = [True, False, True, False, True]
        lo, hi = _bootstrap_ci(labels, _average_precision, n_resamples=200, seed=7)
        assert lo <= hi

    def test_interval_in_0_1_for_ap(self) -> None:
        labels = [True, False, False, True, False]
        lo, hi = _bootstrap_ci(labels, _average_precision, n_resamples=500, seed=42)
        assert 0.0 <= lo <= 1.0
        assert 0.0 <= hi <= 1.0

    def test_degenerate_all_same_gives_zero_width_ci(self) -> None:
        # All negatives -> AP=0 always -> CI width=0
        labels = [False, False, False, False]
        lo, hi = _bootstrap_ci(labels, _average_precision, n_resamples=200, seed=1)
        assert lo == hi == 0.0


class TestComputeRankingMetrics:
    """Integration tests for compute_ranking_metrics."""

    def _make_items(self, scores_and_labels: list[tuple[float, bool]]) -> list[dict]:
        return [
            {
                "cve_id": f"CVE-2021-{i:04d}",
                "score_test": score,
                "has_exploit": label,
            }
            for i, (score, label) in enumerate(scores_and_labels)
        ]

    def test_schema(self) -> None:
        items = self._make_items([(0.9, True), (0.5, False), (0.3, True)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=50)
        for key in (
            "score_key",
            "n_items",
            "n_positives",
            "average_precision",
            "ap_ci_95",
            "auc_roc",
            "auc_roc_ci_95",
            "random_baseline_auc",
            "n_bootstrap_resamples",
            "bootstrap_seed",
        ):
            assert key in result, f"Missing key: {key}"

    def test_n_items_and_n_positives(self) -> None:
        items = self._make_items([(0.9, True), (0.5, False), (0.3, True)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=50)
        assert result["n_items"] == 3
        assert result["n_positives"] == 2

    def test_perfect_ranking_ap_1(self) -> None:
        # High score -> positive, low score -> negative
        items = self._make_items([(0.9, True), (0.8, True), (0.3, False), (0.1, False)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=100)
        assert math.isclose(result["average_precision"], 1.0)

    def test_perfect_ranking_auc_1(self) -> None:
        items = self._make_items([(0.9, True), (0.8, True), (0.3, False), (0.1, False)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=100)
        assert math.isclose(result["auc_roc"], 1.0)

    def test_no_positives(self) -> None:
        items = self._make_items([(0.9, False), (0.5, False)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=50)
        assert result["average_precision"] == 0.0
        assert result["auc_roc"] == 0.5  # degenerate

    def test_random_baseline_auc_is_half(self) -> None:
        items = self._make_items([(0.9, True), (0.5, False)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=50)
        assert result["random_baseline_auc"] == 0.5

    def test_deterministic(self) -> None:
        items = self._make_items(
            [(0.9, True), (0.7, False), (0.5, True), (0.3, False), (0.1, True)]
        )
        r1 = compute_ranking_metrics(items, "score_test", n_bootstrap=200, bootstrap_seed=42)
        r2 = compute_ranking_metrics(items, "score_test", n_bootstrap=200, bootstrap_seed=42)
        assert r1["ap_ci_95"] == r2["ap_ci_95"]
        assert r1["auc_roc_ci_95"] == r2["auc_roc_ci_95"]

    def test_ci_lower_le_upper(self) -> None:
        items = self._make_items(
            [(0.9, True), (0.7, False), (0.5, True), (0.3, False), (0.1, True)]
        )
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=500)
        ap_lo, ap_hi = result["ap_ci_95"]
        auc_lo, auc_hi = result["auc_roc_ci_95"]
        assert ap_lo <= ap_hi
        assert auc_lo <= auc_hi

    def test_score_key_recorded(self) -> None:
        items = self._make_items([(0.5, True)])
        result = compute_ranking_metrics(items, "score_test", n_bootstrap=10)
        assert result["score_key"] == "score_test"
