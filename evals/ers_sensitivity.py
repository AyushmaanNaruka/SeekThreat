"""ERS weight-profile sensitivity check (DECISIONS.md D-027).

Computes the Exposure Risk Score with ``services.enrichment.ers.calculate_ers`` under the
three weight profiles named in D-027, for:

* the five D-027 CVEs, with inputs taken from the multi-source fusion engine over the
  synthetic fixtures in ``tests/fixtures/enrichment/`` (values are hand-authored, not real
  feed data), and
* two discriminating synthetic cases that separate the profiles: high CVSS / low EPSS /
  not in KEV, and low CVSS / high EPSS / not in KEV. Their inputs are chosen to probe
  the weights; they are not CVEs and not measurements.

Prints the score table and the rank order per profile. Nothing here is a measurement of
the platform; it shows how the formula behaves on fixed inputs.
"""

from __future__ import annotations

# ruff: noqa: E402
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.enrichment_coverage import build_engines
from packages.schema.models.finding import EnrichmentValue, Finding
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source
from services.enrichment.ers import ERSWeights, calculate_ers

FIXTURES_DIR = _REPO_ROOT / "tests" / "fixtures" / "enrichment"

# Weight profiles exactly as listed in DECISIONS.md D-027 (w_cvss, w_epss, w_kev).
PROFILES: dict[str, ERSWeights] = {
    "severity_heavy": ERSWeights(weight_cvss=0.60, weight_epss=0.25, weight_kev=0.15),
    "balanced": ERSWeights(weight_cvss=0.40, weight_epss=0.35, weight_kev=0.25),
    "exploitation_heavy": ERSWeights(weight_cvss=0.25, weight_epss=0.50, weight_kev=0.25),
}

# The five CVEs in D-027's sensitivity table, with the labels used there.
D027_CVES: dict[str, str] = {
    "CVE-2021-44228": "Log4Shell",
    "CVE-2022-22947": "Spring Gateway",
    "CVE-2024-23897": "Jenkins CLI",
    "CVE-2021-41773": "Apache traversal",
    "CVE-2020-7699": "express-fileupload",
}


@dataclass(frozen=True)
class SyntheticCase:
    """Hand-chosen ERS inputs used only to discriminate between weight profiles."""

    case_id: str
    label: str
    cvss: float
    epss: float
    in_kev: bool


SYNTHETIC_CASES: tuple[SyntheticCase, ...] = (
    SyntheticCase("SYN-HIGH-CVSS", "high CVSS / low EPSS / non-KEV", 9.8, 0.02, False),
    SyntheticCase("SYN-HIGH-EPSS", "low CVSS / high EPSS / non-KEV", 5.3, 0.90, False),
)

_FIXED_TIME = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class Row:
    """One scored item: its inputs and its ERS under each profile."""

    item_id: str
    label: str
    synthetic_case: bool
    cvss: float
    epss: float
    in_kev: bool | None
    scores: dict[str, float]


def _synthetic_fields(case: SyntheticCase) -> dict[str, Attributed[EnrichmentValue]]:
    def attr(value: EnrichmentValue, source: Source) -> Attributed[EnrichmentValue]:
        return Attributed[EnrichmentValue](
            value=value,
            provenance=Provenance(
                source=source,
                confidence=Confidence.HIGH,
                retrieved_at=_FIXED_TIME,
                note=f"Synthetic sensitivity input ({case.case_id}); not real data",
            ),
        )

    return {
        "cvss_score": attr(case.cvss, Source.CVE_ORG),
        "epss_score": attr(case.epss, Source.EPSS),
        "in_kev": attr(case.in_kev, Source.KEV),
    }


def _fixture_fields(cve_id: str) -> dict[str, Attributed[EnrichmentValue]]:
    _, multi = build_engines(FIXTURES_DIR)
    finding = Finding(
        finding_id=f"ers-sensitivity-{cve_id}",
        engagement_id="eng-ers-sensitivity",
        asset_id="asset-ers-sensitivity",
        scanner="ers_sensitivity",
        title=f"ERS sensitivity input for {cve_id}",
        description="Synthetic finding used to score fixture data under weight profiles",
        observation_ids=[f"obs-{cve_id}"],
        detected_at=_FIXED_TIME,
        cve_ids=[cve_id],
    )
    return multi.fuse(finding)


def _score(fields: dict[str, Attributed[EnrichmentValue]]) -> dict[str, float]:
    return {name: round(calculate_ers(fields, w).value, 2) for name, w in PROFILES.items()}


def _num(fields: dict[str, Attributed[EnrichmentValue]], key: str) -> float:
    value = fields[key].value
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{key} is not numeric: {value!r}")
    return float(value)


def compute_rows() -> list[Row]:
    """Score the D-027 CVEs and the synthetic cases under every profile."""
    rows: list[Row] = []
    for cve_id, label in D027_CVES.items():
        fields = _fixture_fields(cve_id)
        kev = fields["in_kev"].value
        rows.append(
            Row(
                item_id=cve_id,
                label=label,
                synthetic_case=False,
                cvss=_num(fields, "cvss_score"),
                epss=_num(fields, "epss_score"),
                in_kev=kev if isinstance(kev, bool) else None,
                scores=_score(fields),
            )
        )
    for case in SYNTHETIC_CASES:
        rows.append(
            Row(
                item_id=case.case_id,
                label=case.label,
                synthetic_case=True,
                cvss=case.cvss,
                epss=case.epss,
                in_kev=case.in_kev,
                scores=_score(_synthetic_fields(case)),
            )
        )
    return rows


def rank_order(rows: list[Row], profile: str) -> list[str]:
    """Item ids sorted by descending ERS under ``profile`` (ties broken by id)."""
    return [r.item_id for r in sorted(rows, key=lambda r: (-r.scores[profile], r.item_id))]


def render(rows: list[Row]) -> str:
    """Render the inputs, score table and rank orders as Markdown."""
    names = list(PROFILES)
    lines = [
        "Inputs: D-027 CVEs from synthetic fixtures (tests/fixtures/enrichment/); "
        "SYN-* rows are hand-chosen probe inputs. Not measurements.",
        "",
        "| Profile | w_cvss | w_epss | w_kev |",
        "|---|---|---|---|",
    ]
    for name, w in PROFILES.items():
        lines.append(f"| {name} | {w.weight_cvss:.2f} | {w.weight_epss:.2f} | {w.weight_kev:.2f} |")
    lines.extend(
        [
            "",
            "| Item | Label | CVSS | EPSS | KEV | " + " | ".join(names) + " |",
            "|---|---|---|---|---|" + "---|" * len(names),
        ]
    )
    for r in rows:
        kev = "unknown" if r.in_kev is None else ("yes" if r.in_kev else "no")
        scores = " | ".join(f"{r.scores[n]:.2f}" for n in names)
        lines.append(f"| {r.item_id} | {r.label} | {r.cvss:g} | {r.epss:g} | {kev} | {scores} |")
    cve_rows = [r for r in rows if not r.synthetic_case]
    lines.extend(["", "Rank order, D-027 CVEs only (highest ERS first):", ""])
    for name in names:
        lines.append(f"- {name}: " + " > ".join(rank_order(cve_rows, name)))
    lines.extend(["", "Rank order, all rows (highest ERS first):", ""])
    for name in names:
        lines.append(f"- {name}: " + " > ".join(rank_order(rows, name)))
    return "\n".join(lines)


def main() -> int:
    """Print the sensitivity table and rank orders."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")
    print(render(compute_rows()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
