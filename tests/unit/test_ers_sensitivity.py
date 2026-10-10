"""Tests for evals/ers_sensitivity.py (DECISIONS.md D-027 sensitivity table).

The orderings asserted here are what calculate_ers produces on the synthetic fixtures
and hand-chosen probe inputs. They pin the D-027 text, not any real-world ranking.
"""

from __future__ import annotations

import pytest

from evals.ers_sensitivity import PROFILES, Row, compute_rows, main, rank_order
from services.enrichment.ers import DEFAULT_WEIGHT_CVSS, DEFAULT_WEIGHT_EPSS, DEFAULT_WEIGHT_KEV

LOG4SHELL = "CVE-2021-44228"
SPRING = "CVE-2022-22947"
JENKINS = "CVE-2024-23897"
APACHE = "CVE-2021-41773"
EXPRESS = "CVE-2020-7699"


@pytest.fixture(scope="module")
def rows() -> list[Row]:
    return compute_rows()


def _cves(rows: list[Row]) -> list[Row]:
    return [r for r in rows if not r.synthetic_case]


def test_profiles_match_d027() -> None:
    weights = {n: (w.weight_cvss, w.weight_epss, w.weight_kev) for n, w in PROFILES.items()}
    assert weights == {
        "severity_heavy": (0.60, 0.25, 0.15),
        "balanced": (0.40, 0.35, 0.25),
        "exploitation_heavy": (0.25, 0.50, 0.25),
    }
    assert weights["balanced"] == (DEFAULT_WEIGHT_CVSS, DEFAULT_WEIGHT_EPSS, DEFAULT_WEIGHT_KEV)


def test_d027_cve_orderings(rows: list[Row]) -> None:
    cves = _cves(rows)
    expected_stable = [LOG4SHELL, SPRING, JENKINS, APACHE, EXPRESS]
    assert rank_order(cves, "severity_heavy") == expected_stable
    assert rank_order(cves, "balanced") == expected_stable
    # Apache traversal overtakes Jenkins CLI under the exploitation-heavy profile.
    assert rank_order(cves, "exploitation_heavy") == [LOG4SHELL, SPRING, APACHE, JENKINS, EXPRESS]


def test_synthetic_cases_flip_between_profiles(rows: list[Row]) -> None:
    by_id = {r.item_id: r for r in rows}
    high_cvss = by_id["SYN-HIGH-CVSS"].scores
    high_epss = by_id["SYN-HIGH-EPSS"].scores
    assert high_cvss["severity_heavy"] > high_epss["severity_heavy"]
    assert high_epss["balanced"] > high_cvss["balanced"]
    assert high_epss["exploitation_heavy"] > high_cvss["exploitation_heavy"]


def test_full_orderings(rows: list[Row]) -> None:
    top4_stable = [LOG4SHELL, SPRING, JENKINS, APACHE]
    assert rank_order(rows, "severity_heavy") == [
        *top4_stable,
        "SYN-HIGH-CVSS",
        "SYN-HIGH-EPSS",
        EXPRESS,
    ]
    assert rank_order(rows, "balanced") == [*top4_stable, "SYN-HIGH-EPSS", "SYN-HIGH-CVSS", EXPRESS]
    assert rank_order(rows, "exploitation_heavy") == [
        LOG4SHELL,
        SPRING,
        APACHE,
        JENKINS,
        "SYN-HIGH-EPSS",
        "SYN-HIGH-CVSS",
        EXPRESS,
    ]


def test_main_prints_table(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    out = capsys.readouterr().out
    assert "exploitation_heavy" in out
    assert "Not measurements" in out
