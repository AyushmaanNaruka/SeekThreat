"""ERS ranking corroboration harness (smoke-level).

Ranks the CVEs in ``evals/golden/enrichment_baseline.json`` by Exposure Risk Score (ERS)
under several weight profiles and checks how many of the top-ranked CVEs have an
ExploitDB or Metasploit catalogue entry.

Read this before quoting any number from it (DECISIONS.md D-027, D-038):

1. No network calls: reads local mirror files only.
2. The corroboration target is NOT independent of ERS. EPSS (35% of ERS) uses public
   exploit code availability, including ExploitDB entries and Metasploit modules, among
   its model features (D-029). Metasploit-only precision is reported as a narrower
   target, not as an independent check.
3. The dataset is small and hand-picked. Cohort E was selected for exploit presence and
   cohort C for KEV membership, which is itself an ERS input. Compare every precision to
   the random-ranking baseline (the dataset base rate), which the harness reports.
4. Ranking ties are broken deterministically (score descending, then ``cve_id``
   ascending). Each slice reports how many CVEs tie at the k boundary and the precision
   range over every possible tie order.

Output safety: with synthetic fixtures (the default ``--cache-dir``) results go to
``evals/results/ers_validation_synthetic.*`` with a SYNTHETIC banner. With real mirrors
the harness refuses to write unless ``--output-json`` and ``--output-md`` are given
explicitly. A missing ``--cache-dir`` is an error, never a silent fallback to fixtures.
"""

from __future__ import annotations

# ruff: noqa: E402
import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path when invoked directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evals.enrichment_coverage import (
    _mirror_paths,
    _rel_posix,
    build_engines,
    describe_mirrors,
)
from packages.schema.models.finding import Finding
from packages.schema.models.provenance import Source
from services.enrichment.ers import ERSWeights, calculate_ers

_DEFAULT_DATASET = Path("evals/golden/enrichment_baseline.json")
_DEFAULT_CACHE_DIR = Path("tests/fixtures/enrichment")
_SYNTHETIC_OUTPUT_JSON = Path("evals/results/ers_validation_synthetic.json")
_SYNTHETIC_OUTPUT_MD = Path("evals/results/ers_validation_synthetic.md")
# Committed real-mirror results. Written only when passed explicitly on the command line.
_REAL_RESULTS_JSON = Path("evals/results/ers_validation_results.json")
_REAL_RESULTS_MD = Path("evals/results/ers_validation_results.md")

SYNTHETIC_BANNER = (
    "SYNTHETIC SMOKE TEST — harness validation on hand-authored fixtures. These are not "
    "measurements of ERS ranking quality."
)

TIE_RULE = "score descending, then cve_id ascending"

_EVAL_DETECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)

# Validation weight profiles:
# 1. Standard Balanced (production default: D-008 / D-027)
# 2. Control: EPSS zeroed out (CVSS + KEV only)
# 3. CVSS-only baseline
# 4. Exploitation heavy
PROFILES: dict[str, ERSWeights] = {
    "balanced": ERSWeights(weight_cvss=0.40, weight_epss=0.35, weight_kev=0.25),
    "no_epss_control": ERSWeights(weight_cvss=0.60, weight_epss=0.00, weight_kev=0.40),
    "cvss_only": ERSWeights(weight_cvss=1.00, weight_epss=0.00, weight_kev=0.00),
    "exploitation_heavy": ERSWeights(weight_cvss=0.25, weight_epss=0.50, weight_kev=0.25),
}


def _has_exploitdb(fields: dict[str, Any]) -> bool:
    """True when ExploitDB (not a placeholder) reports a catalogue entry for the CVE."""
    edb = fields.get("has_public_exploit")
    return edb is not None and edb.provenance.source == Source.EXPLOITDB and edb.value is True


def _has_metasploit(fields: dict[str, Any]) -> bool:
    """True when Metasploit (not a placeholder) reports a module for the CVE."""
    msf = fields.get("has_metasploit_module")
    return msf is not None and msf.provenance.source == Source.METASPLOIT and msf.value is True


def _has_exploit(fields: dict[str, Any]) -> bool:
    """True when an ExploitDB or Metasploit catalogue entry exists for the CVE."""
    return _has_exploitdb(fields) or _has_metasploit(fields)


def rank_items(items: list[dict[str, Any]], score_key: str) -> list[dict[str, Any]]:
    """Sort by ``score_key`` descending, ties broken by ``cve_id`` ascending (TIE_RULE)."""
    return sorted(items, key=lambda x: (-x[score_key], x["cve_id"]))


def _pct(count: int, total: int) -> float:
    return round(count / total * 100.0, 1) if total > 0 else 0.0


def evaluate_ranking(
    scored_items: list[dict[str, Any]],
    score_key: str,
    top_k: int,
) -> dict[str, Any]:
    """Precision/recall for the top_k items ranked by score_key, with tie diagnostics."""
    ranked = rank_items(scored_items, score_key)
    total_exploited = sum(1 for x in scored_items if x["has_exploit"])
    top_slice = ranked[:top_k]
    top_exploited = sum(1 for x in top_slice if x["has_exploit"])
    top_msf = sum(1 for x in top_slice if x.get("has_metasploit", False))

    result: dict[str, Any] = {
        "top_k": top_k,
        "total_exploited_dataset": total_exploited,
        "top_k_exploited_count": top_exploited,
        "precision_pct": _pct(top_exploited, top_k),
        "recall_pct": _pct(top_exploited, total_exploited),
        "top_k_metasploit_count": top_msf,
        "metasploit_precision_pct": _pct(top_msf, top_k),
        "min_score_in_top_k": round(top_slice[-1][score_key], 2) if top_slice else 0.0,
        "ties_at_boundary": 0,
        "tied_outside_top_k": 0,
        "precision_range_over_tie_orders_pct": [_pct(top_exploited, top_k)] * 2,
        "top_cves": [x["cve_id"] for x in top_slice],
    }
    if not top_slice or len(top_slice) == len(ranked):
        if top_slice:
            boundary = top_slice[-1][score_key]
            result["ties_at_boundary"] = sum(1 for x in ranked if x[score_key] == boundary)
        return result

    boundary = top_slice[-1][score_key]
    tied = [x for x in ranked if x[score_key] == boundary]
    above = sum(1 for x in ranked if x[score_key] > boundary)
    above_exploited = sum(1 for x in ranked if x[score_key] > boundary and x["has_exploit"])
    slots = top_k - above
    tied_exploited = sum(1 for x in tied if x["has_exploit"])
    tied_clean = len(tied) - tied_exploited
    best = above_exploited + min(slots, tied_exploited)
    worst = above_exploited + max(0, slots - tied_clean)
    result["ties_at_boundary"] = len(tied)
    result["tied_outside_top_k"] = len(tied) - slots
    result["precision_range_over_tie_orders_pct"] = [_pct(worst, top_k), _pct(best, top_k)]
    return result


def run_ers_validation(
    dataset_path: Path,
    cache_dir: Path,
    nvd_override: Path | None = None,
) -> dict[str, Any]:
    """Score the dataset under every profile and evaluate the rankings."""
    if not cache_dir.exists():
        raise FileNotFoundError(f"Mirror cache directory not found: {cache_dir}")

    with open(dataset_path, encoding="utf-8") as f:
        raw_dataset = json.load(f)

    items = raw_dataset.get("items", [])
    if not items:
        raise ValueError(f"No items found in dataset at {dataset_path}")

    synthetic, mirrors = describe_mirrors(_mirror_paths(cache_dir, nvd_override))
    _, multi_engine = build_engines(cache_dir, nvd_override)

    scored_items: list[dict[str, Any]] = []
    for item in items:
        cve_id = item["cve_id"]
        finding = Finding(
            finding_id=f"eval-ers-{cve_id}",
            engagement_id="eng-ers-validation",
            asset_id="asset-eval-target",
            scanner="eval_harness",
            title=f"ERS Validation finding for {cve_id}",
            description="Finding for ERS exploit-catalogue corroboration",
            observation_ids=[f"obs-{cve_id}"],
            detected_at=_EVAL_DETECTED_AT,
            cve_ids=[cve_id],
        )
        fused = multi_engine.fuse(finding)

        profile_scores: dict[str, float] = {}
        for pname, weights in PROFILES.items():
            ers = calculate_ers(fused, weights=weights)
            profile_scores[f"score_{pname}"] = round(ers.value, 3)

        cvss_attr = fused.get("cvss_score")
        epss_attr = fused.get("epss_score")
        kev_attr = fused.get("in_kev")
        scored_items.append(
            {
                "cve_id": cve_id,
                "cohort": item.get("cohort", "unclassified"),
                "title": item.get("title", ""),
                "cvss": float(cvss_attr.value)
                if cvss_attr and cvss_attr.value is not None
                else None,
                "epss": float(epss_attr.value)
                if epss_attr and epss_attr.value is not None
                else None,
                "in_kev": bool(kev_attr.value)
                if kev_attr and kev_attr.value is not None
                else False,
                "has_exploit": _has_exploit(fused),
                "has_metasploit": _has_metasploit(fused),
                "has_exploitdb": _has_exploitdb(fused),
                **profile_scores,
            }
        )

    n_total = len(scored_items)
    n_exploited = sum(1 for x in scored_items if x["has_exploit"])
    n_msf = sum(1 for x in scored_items if x["has_metasploit"])
    base_rate = _pct(n_exploited, n_total)
    msf_base_rate = _pct(n_msf, n_total)

    cohort_e = [x for x in scored_items if x["cohort"] == "cohort_e_weaponized_exploit"]
    cohort_c = [x for x in scored_items if x["cohort"] == "cohort_c_cisa_kev"]
    selection = {
        "cohort_e_count": len(cohort_e),
        "cohort_e_with_catalogue_entry": sum(1 for x in cohort_e if x["has_exploit"]),
        "cohort_c_count": len(cohort_c),
        "cohort_c_in_kev": sum(1 for x in cohort_c if x["in_kev"]),
        "kev_positive_total": sum(1 for x in scored_items if x["in_kev"]),
    }

    # Slices: top 10%, 20%, 30% of the dataset.
    slice_sizes = [max(1, int(round(n_total * share))) for share in (0.10, 0.20, 0.30)]

    profile_evals: dict[str, dict[str, Any]] = {
        pname: {
            f"top_{s}": evaluate_ranking(scored_items, f"score_{pname}", s) for s in slice_sizes
        }
        for pname in PROFILES
    }

    top_k = slice_sizes[0]
    balanced_top = profile_evals["balanced"][f"top_{top_k}"]
    control_top = profile_evals["no_epss_control"][f"top_{top_k}"]
    cvss_top = profile_evals["cvss_only"][f"top_{top_k}"]
    comparison = {
        "top_slice_size": top_k,
        "one_cve_moves_precision_pp": _pct(1, top_k),
        "random_baseline_precision_pct": base_rate,
        "random_baseline_metasploit_precision_pct": msf_base_rate,
        "balanced_precision_pct": balanced_top["precision_pct"],
        "no_epss_control_precision_pct": control_top["precision_pct"],
        "cvss_only_precision_pct": cvss_top["precision_pct"],
        "balanced_metasploit_precision_pct": balanced_top["metasploit_precision_pct"],
        "no_epss_control_metasploit_precision_pct": control_top["metasploit_precision_pct"],
        "cvss_only_metasploit_precision_pct": cvss_top["metasploit_precision_pct"],
        "epss_marginal_precision_gain_pp": round(
            balanced_top["precision_pct"] - control_top["precision_pct"], 1
        ),
        "ers_vs_cvss_precision_gain_pp": round(
            balanced_top["precision_pct"] - cvss_top["precision_pct"], 1
        ),
        "balanced_vs_random_precision_gain_pp": round(balanced_top["precision_pct"] - base_rate, 1),
    }

    metadata: dict[str, Any] = {
        "banner": SYNTHETIC_BANNER if synthetic else None,
        "dataset_path": _rel_posix(dataset_path),
        "cache_dir": _rel_posix(cache_dir),
        "synthetic_mode": synthetic,
        "tie_rule": TIE_RULE,
        "total_cves": n_total,
        "total_exploited_cves": n_exploited,
        "overall_exploit_rate_pct": base_rate,
        "total_metasploit_cves": n_msf,
        "metasploit_rate_pct": msf_base_rate,
        "selection": selection,
        "mirrors": mirrors,
    }
    if not synthetic:
        metadata["generated_at"] = datetime.now(UTC).isoformat()

    return {
        "metadata": metadata,
        "profiles": profile_evals,
        "comparison": comparison,
        "items": rank_items(scored_items, "score_balanced"),
    }


_PROFILE_DESCRIPTIONS = {
    "balanced": ("Balanced (production default)", "0.40 / 0.35 / 0.25"),
    "no_epss_control": ("No-EPSS control (CVSS+KEV)", "0.60 / 0.00 / 0.40"),
    "cvss_only": ("CVSS-only baseline", "1.00 / 0.00 / 0.00"),
    "exploitation_heavy": ("Exploitation heavy", "0.25 / 0.50 / 0.25"),
}


def generate_markdown_report(results: dict[str, Any]) -> str:
    """Format validation results as a Markdown report."""
    meta = results["metadata"]
    comp = results["comparison"]
    sel = meta["selection"]
    n = meta["total_cves"]
    k = comp["top_slice_size"]
    mode_str = "Synthetic fixtures" if meta["synthetic_mode"] else "Real feed mirrors"

    lines: list[str] = ["# ERS Ranking Corroboration Report (smoke-level)", ""]
    if meta["synthetic_mode"]:
        lines.extend([f"> **{meta['banner']}**", ""])
    lines.extend(
        [
            "> **Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  ",
            f"> **Dataset:** `{meta['dataset_path']}` ({n} CVEs)  ",
            f"> **Mirror cache:** `{meta['cache_dir']}` (Mode: {mode_str})  ",
            f"> **Tie rule:** {meta['tie_rule']}  ",
        ]
    )
    if meta.get("generated_at"):
        lines.append(f"> **Generated at:** {meta['generated_at']}  ")
    lines.extend(
        [
            "",
            "## 1. Summary",
            "",
            "ERS = 0.40 x CVSS + 0.35 x (EPSS x 10) + 0.25 x (10 if KEV). The corroboration "
            "target is whether an ExploitDB or Metasploit catalogue entry exists for the CVE. "
            "That target is not independent of ERS: EPSS uses exploit-code availability, "
            "including ExploitDB and Metasploit, among its features.",
            "",
            f"- **Base rate (random-ranking precision):** {meta['total_exploited_cves']} / {n} "
            f"CVEs ({meta['overall_exploit_rate_pct']}%) have an ExploitDB or Metasploit "
            f"catalogue entry; {meta['total_metasploit_cves']} / {n} "
            f"({meta['metasploit_rate_pct']}%) have a Metasploit module.",
            f"- **Top {k} precision, balanced ERS:** {comp['balanced_precision_pct']}% "
            f"(Metasploit-only {comp['balanced_metasploit_precision_pct']}%).",
            f"- **Top {k} precision, no-EPSS control:** {comp['no_epss_control_precision_pct']}% "
            f"(Metasploit-only {comp['no_epss_control_metasploit_precision_pct']}%).",
            f"- **Top {k} precision, CVSS-only:** {comp['cvss_only_precision_pct']}% "
            f"(Metasploit-only {comp['cvss_only_metasploit_precision_pct']}%).",
            f"- **EPSS marginal gain (balanced - no-EPSS control):** "
            f"{comp['epss_marginal_precision_gain_pp']:+0.1f} pp.",
            f"- **Balanced - CVSS-only:** {comp['ers_vs_cvss_precision_gain_pp']:+0.1f} pp.",
            f"- **Balanced - random baseline:** "
            f"{comp['balanced_vs_random_precision_gain_pp']:+0.1f} pp.",
            f"- **Granularity:** at top {k}, one CVE moves precision by "
            f"{comp['one_cve_moves_precision_pp']} pp.",
            "",
            "## 2. Profile ranking across slices",
            "",
            "| Profile | Weights (CVSS / EPSS / KEV) | Slice | Precision | "
            "Precision range over tie orders | Metasploit-only precision | Recall | "
            "Ties at boundary (outside top k) | Min score |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for pname, (label, w_str) in _PROFILE_DESCRIPTIONS.items():
        for sdata in results["profiles"].get(pname, {}).values():
            lo, hi = sdata["precision_range_over_tie_orders_pct"]
            lines.append(
                f"| {label} | {w_str} | top {sdata['top_k']} | {sdata['precision_pct']}% | "
                f"{lo}% - {hi}% | {sdata['metasploit_precision_pct']}% | "
                f"{sdata['recall_pct']}% | {sdata['ties_at_boundary']} "
                f"({sdata['tied_outside_top_k']}) | {sdata['min_score_in_top_k']} |"
            )

    lines.extend(
        [
            "",
            "## 3. Top-ranked CVEs (balanced ERS)",
            "",
            "| Rank | CVE ID | ERS (balanced) | CVSS | EPSS (%) | In KEV | ExploitDB entry | "
            "Metasploit module | Cohort |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for i, item in enumerate(results["items"][:15], 1):
        cvss = f"{item['cvss']:.1f}" if item["cvss"] is not None else "—"
        epss = f"{item['epss'] * 100.0:.1f}%" if item["epss"] is not None else "—"
        lines.append(
            f"| {i} | `{item['cve_id']}` | {item['score_balanced']:.3f} | {cvss} | {epss} | "
            f"{'yes' if item['in_kev'] else 'no'} | "
            f"{'yes' if item['has_exploitdb'] else '—'} | "
            f"{'yes' if item['has_metasploit'] else '—'} | {item['cohort']} |"
        )

    lines.extend(
        [
            "",
            "## 4. Limitations & circularity disclosure (D-027, D-038)",
            "",
            "1. **Direct inputs.** ExploitDB and Metasploit are not inputs to "
            "`calculate_ers()`; the inputs are CVSS, EPSS and KEV.",
            "2. **Not independent of EPSS.** EPSS uses exploit-code availability, including "
            "ExploitDB entries and Metasploit modules, among its model features (D-029). "
            "Corroborating against either catalogue partly re-measures an ERS input. "
            "Metasploit-only precision is a narrower target, not an independent check.",
            f"3. **Selection bias.** Cohort E was chosen for exploit presence "
            f"({sel['cohort_e_with_catalogue_entry']} of {sel['cohort_e_count']} have a "
            f"catalogue entry). Cohort C was chosen on KEV membership, which is an ERS input "
            f"({sel['cohort_c_in_kev']} of {sel['cohort_c_count']} in KEV; "
            f"{sel['kev_positive_total']} of {n} overall). The base rate is "
            f"{meta['overall_exploit_rate_pct']}%, so precision must be read against it.",
            f"4. **Small n.** {n} hand-picked CVEs. At top {k}, one CVE moves precision by "
            f"{comp['one_cve_moves_precision_pp']} pp. Treat every number here as smoke-level "
            "corroboration, not validation.",
            f"5. **Ties.** Ranking uses {meta['tie_rule']}. Where CVEs tie at the k boundary, "
            "slice membership is decided by that rule; the precision range column shows how "
            "far precision could move under any other tie order.",
            "6. **Additive formula.** ERS never multiplies EPSS by CVSS (D-008; "
            "`services/enrichment/README.md` rule 3). Each component is recorded in its own "
            "`ScoreComponent`.",
            "",
            "---",
            "_Generated by `evals/ers_validation.py`._",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(results: dict[str, Any], output_json: Path, output_md: Path) -> None:
    """Write JSON and Markdown results with LF line endings."""
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(generate_markdown_report(results))


def _same_path(a: Path, b: Path) -> bool:
    return a.resolve() == (b if b.is_absolute() else _REPO_ROOT / b).resolve()


def resolve_output_paths(
    synthetic: bool, output_json: Path | None, output_md: Path | None
) -> tuple[Path, Path]:
    """Pick output paths; raise ValueError when the combination is unsafe.

    * Synthetic run: defaults to ``evals/results/ers_validation_synthetic.*``, and may never
      write to the committed real-results paths.
    * Real run: both paths must be given explicitly.
    """
    if synthetic:
        out_json = output_json or _REPO_ROOT / _SYNTHETIC_OUTPUT_JSON
        out_md = output_md or _REPO_ROOT / _SYNTHETIC_OUTPUT_MD
        for path, real in ((out_json, _REAL_RESULTS_JSON), (out_md, _REAL_RESULTS_MD)):
            if _same_path(path, real):
                raise ValueError(
                    f"Refusing to write synthetic-fixture results to the real results path {real}"
                )
        return out_json, out_md
    if output_json is None or output_md is None:
        raise ValueError(
            "Real mirrors detected: pass --output-json and --output-md explicitly to write "
            "real results (e.g. evals/results/ers_validation_results.json / .md)."
        )
    return output_json, output_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Smoke-level ERS ranking corroboration against ExploitDB / Metasploit catalogue "
            "entries. Synthetic fixtures by default."
        )
    )
    parser.add_argument(
        "--dataset", type=Path, default=_DEFAULT_DATASET, help="Path to dataset JSON"
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=_DEFAULT_CACHE_DIR,
        help="Mirror cache directory (default: synthetic fixtures). Must exist.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="JSON output path. Required for real mirrors; synthetic default "
        f"{_SYNTHETIC_OUTPUT_JSON.as_posix()}",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Markdown output path. Required for real mirrors; synthetic default "
        f"{_SYNTHETIC_OUTPUT_MD.as_posix()}",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    args = parser.parse_args(argv)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")

    if not args.cache_dir.exists():
        sys.stderr.write(f"Error: Cache directory not found at {args.cache_dir}\n")
        return 1

    results = run_ers_validation(dataset_path=args.dataset, cache_dir=args.cache_dir)
    try:
        out_json, out_md = resolve_output_paths(
            results["metadata"]["synthetic_mode"], args.output_json, args.output_md
        )
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2
    write_outputs(results, out_json, out_md)

    if not args.quiet:
        meta = results["metadata"]
        comp = results["comparison"]
        k = comp["top_slice_size"]
        print("=" * 72)
        if meta["banner"]:
            print(meta["banner"])
            print("-" * 72)
        print(f"Mode:                      {'Synthetic' if meta['synthetic_mode'] else 'Real'}")
        print(f"Evaluated CVEs:            {meta['total_cves']}")
        print(f"Random-baseline precision: {comp['random_baseline_precision_pct']}%")
        print(f"Top {k} precision balanced: {comp['balanced_precision_pct']}%")
        print(f"Top {k} precision no-EPSS:  {comp['no_epss_control_precision_pct']}%")
        print(f"Top {k} precision CVSS:     {comp['cvss_only_precision_pct']}%")
        print(f"EPSS marginal delta:       {comp['epss_marginal_precision_gain_pp']:+0.1f} pp")
        print("=" * 72)
        print(f"Markdown report written to: {out_md}")
        print(f"JSON results written to:    {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
