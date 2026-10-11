"""ERS empirical validation and exploit corroboration evaluation harness.

Evaluates SeekThreat's Exposure Risk Score (ERS) against independent public exploit
indicators (ExploitDB public exploits and Rapid7 Metasploit modules).

Follows CLAUDE.md and DECISIONS.md (D-008, D-027, D-038):
1. No network calls: uses local mirror caches or synthetic fixtures.
2. Evaluates ERS ranking precision, recall, and exploit corroboration across top tiers.
3. Comparative control: measures ranking efficacy with EPSS active vs EPSS zeroed out
   (pure technical severity CVSS + KEV), isolating the marginal predictive value of EPSS.
4. Transparently documents partial circularity (EPSS internally features public exploit data).
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
    build_engines,
    describe_mirrors,
)
from packages.schema.models.finding import Finding
from packages.schema.models.provenance import Source
from services.enrichment.ers import ERSWeights, calculate_ers

_DEFAULT_DATASET = Path("evals/golden/enrichment_baseline.json")
_DEFAULT_CACHE_DIR = Path("data/enrichment_cache")
_FIXTURES_CACHE_DIR = Path("tests/fixtures/enrichment")
_DEFAULT_OUTPUT_JSON = Path("evals/results/ers_validation_results.json")
_DEFAULT_OUTPUT_MD = Path("evals/results/ers_validation_results.md")

_EVAL_DETECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)

# Validation weight profiles:
# 1. Standard Balanced (Production default: D-008 / D-027)
# 2. Control: EPSS Zeroed Out (Technical severity CVSS + KEV only)
# 3. CVSS-Only Baseline (Pure CVSS severity)
# 4. Exploitation Heavy (Aggressive exploitation priority)
PROFILES: dict[str, ERSWeights] = {
    "balanced": ERSWeights(weight_cvss=0.40, weight_epss=0.35, weight_kev=0.25),
    "no_epss_control": ERSWeights(weight_cvss=0.60, weight_epss=0.00, weight_kev=0.40),
    "cvss_only": ERSWeights(weight_cvss=1.00, weight_epss=0.00, weight_kev=0.00),
    "exploitation_heavy": ERSWeights(weight_cvss=0.25, weight_epss=0.50, weight_kev=0.25),
}


def _has_exploit(fields: dict[str, Any]) -> bool:
    """True if verified positive in ExploitDB or Metasploit."""
    edb = fields.get("has_public_exploit")
    msf = fields.get("has_metasploit_module")
    edb_val = (
        bool(edb.value)
        if edb is not None and edb.provenance.source == Source.EXPLOITDB and edb.value is True
        else False
    )
    msf_val = (
        bool(msf.value)
        if msf is not None and msf.provenance.source == Source.METASPLOIT and msf.value is True
        else False
    )
    return edb_val or msf_val


def _has_metasploit(fields: dict[str, Any]) -> bool:
    msf = fields.get("has_metasploit_module")
    return (
        bool(msf.value)
        if msf is not None and msf.provenance.source == Source.METASPLOIT and msf.value is True
        else False
    )


def _has_exploitdb(fields: dict[str, Any]) -> bool:
    edb = fields.get("has_public_exploit")
    return (
        bool(edb.value)
        if edb is not None and edb.provenance.source == Source.EXPLOITDB and edb.value is True
        else False
    )


def evaluate_ranking(
    scored_items: list[dict[str, Any]],
    score_key: str,
    top_k: int,
) -> dict[str, Any]:
    """Calculate precision and recall for top_k items ranked by score_key."""
    sorted_items = sorted(scored_items, key=lambda x: x[score_key], reverse=True)
    total_exploited = sum(1 for x in scored_items if x["has_exploit"])
    top_slice = sorted_items[:top_k]
    top_exploited = sum(1 for x in top_slice if x["has_exploit"])

    precision = round(top_exploited / top_k * 100.0, 1) if top_k > 0 else 0.0
    recall = round(top_exploited / total_exploited * 100.0, 1) if total_exploited > 0 else 0.0

    return {
        "top_k": top_k,
        "total_exploited_dataset": total_exploited,
        "top_k_exploited_count": top_exploited,
        "precision_pct": precision,
        "recall_pct": recall,
        "min_score_in_top_k": round(top_slice[-1][score_key], 2) if top_slice else 0.0,
        "top_cves": [x["cve_id"] for x in top_slice],
    }


def run_ers_validation(
    dataset_path: Path,
    cache_dir: Path,
    nvd_override: Path | None = None,
) -> dict[str, Any]:
    """Run ERS empirical validation against independent exploit mirrors."""
    with open(dataset_path, encoding="utf-8") as f:
        raw_dataset = json.load(f)

    items = raw_dataset.get("items", [])
    if not items:
        raise ValueError(f"No items found in dataset at {dataset_path}")

    # Fallback to fixtures if cache_dir does not exist
    resolved_cache = (
        cache_dir
        if cache_dir.exists()
        else (_FIXTURES_CACHE_DIR if _FIXTURES_CACHE_DIR.exists() else cache_dir)
    )

    synthetic, mirrors = describe_mirrors(_mirror_paths(resolved_cache, nvd_override))
    _, multi_engine = build_engines(resolved_cache, nvd_override)

    scored_items: list[dict[str, Any]] = []

    for item in items:
        cve_id = item["cve_id"]
        finding = Finding(
            finding_id=f"eval-ers-{cve_id}",
            engagement_id="eng-ers-validation",
            asset_id="asset-eval-target",
            scanner="eval_harness",
            title=f"ERS Validation finding for {cve_id}",
            description="Finding for ERS empirical exploit validation",
            observation_ids=[f"obs-{cve_id}"],
            detected_at=_EVAL_DETECTED_AT,
            cve_ids=[cve_id],
        )

        fused = multi_engine.fuse(finding)

        # Compute ERS under all profiles
        profile_scores: dict[str, float] = {}
        for pname, weights in PROFILES.items():
            ers = calculate_ers(fused, weights=weights)
            profile_scores[f"score_{pname}"] = round(ers.value, 3)

        cvss_attr = fused.get("cvss_score")
        epss_attr = fused.get("epss_score")
        kev_attr = fused.get("in_kev")

        has_exp = _has_exploit(fused)
        has_msf = _has_metasploit(fused)
        has_edb = _has_exploitdb(fused)

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
                "has_exploit": has_exp,
                "has_metasploit": has_msf,
                "has_exploitdb": has_edb,
                **profile_scores,
            }
        )

    n_total = len(scored_items)
    n_exploited = sum(1 for x in scored_items if x["has_exploit"])

    # Evaluation slices: Top 10% (decile), Top 20% (quintile), Top 30%
    slice_sizes = [
        max(1, int(round(n_total * 0.10))),
        max(1, int(round(n_total * 0.20))),
        max(1, int(round(n_total * 0.30))),
    ]

    profile_evals: dict[str, dict[str, Any]] = {}
    for pname in PROFILES:
        profile_evals[pname] = {
            f"top_{s}": evaluate_ranking(scored_items, f"score_{pname}", s) for s in slice_sizes
        }

    # Comparison metrics between Balanced vs No-EPSS Control
    top_decile_size = slice_sizes[0]
    balanced_top = profile_evals["balanced"][f"top_{top_decile_size}"]
    control_top = profile_evals["no_epss_control"][f"top_{top_decile_size}"]
    cvss_top = profile_evals["cvss_only"][f"top_{top_decile_size}"]

    comparison = {
        "top_slice_size": top_decile_size,
        "balanced_precision_pct": balanced_top["precision_pct"],
        "no_epss_control_precision_pct": control_top["precision_pct"],
        "cvss_only_precision_pct": cvss_top["precision_pct"],
        "epss_marginal_precision_gain_pp": round(
            balanced_top["precision_pct"] - control_top["precision_pct"], 1
        ),
        "ers_vs_cvss_precision_gain_pp": round(
            balanced_top["precision_pct"] - cvss_top["precision_pct"], 1
        ),
    }

    results: dict[str, Any] = {
        "metadata": {
            "dataset_path": str(dataset_path).replace("\\", "/"),
            "cache_dir": str(resolved_cache).replace("\\", "/"),
            "synthetic_mode": synthetic,
            "total_cves": n_total,
            "total_exploited_cves": n_exploited,
            "overall_exploit_rate_pct": round(n_exploited / n_total * 100.0, 1) if n_total else 0,
            "mirrors": mirrors,
        },
        "profiles": profile_evals,
        "comparison": comparison,
        "items": sorted(scored_items, key=lambda x: x["score_balanced"], reverse=True),
    }

    if not synthetic:
        results["metadata"]["generated_at"] = datetime.now(UTC).isoformat()

    return results


def generate_markdown_report(results: dict[str, Any]) -> str:
    """Format validation results into a comprehensive GitHub Flavored Markdown report."""
    meta = results["metadata"]
    comp = results["comparison"]
    mode_str = "Synthetic Fixtures" if meta["synthetic_mode"] else "Real Feed Mirrors"
    lines: list[str] = [
        "# ERS Empirical Validation & Exploit Corroboration Report",
        "",
        "> **Evaluation Harness:** `evals/ers_validation.py` (DECISIONS.md D-027 & D-038)  ",
        f"> **Evaluation Dataset:** `{meta['dataset_path']}` ({meta['total_cves']} CVEs)  ",
        f"> **Mirror Cache:** `{meta['cache_dir']}` (Mode: {mode_str})  ",
        "",
        "## 1. Executive Summary & Corroboration Metrics",
        "",
        (
            "Exposure Risk Score (ERS) combines technical severity (CVSS: 40%), "
            "exploitation probability (FIRST EPSS: 35%), and confirmed active "
            "exploitation (CISA KEV: 25%) additively."
        ),
        "",
        (
            f"- **Dataset Exploit Prevalence:** **{meta['total_exploited_cves']} / "
            f"{meta['total_cves']} CVEs** ({meta['overall_exploit_rate_pct']}%) possess "
            "verified weaponized exploits in ExploitDB or Rapid7 Metasploit."
        ),
        (
            f"- **Top Decile Precision (Balanced ERS):** **{comp['balanced_precision_pct']}%** "
            "of top-ranked CVEs have verified public exploits."
        ),
        (
            "- **Control Comparison (No-EPSS Control):** "
            f"**{comp['no_epss_control_precision_pct']}%** precision when EPSS is zeroed out."
        ),
        (
            f"- **CVSS-Only Baseline Precision:** **{comp['cvss_only_precision_pct']}%** "
            "precision under pure CVSS base score ranking."
        ),
        (
            "- **EPSS Marginal Signal Gain:** "
            f"**{comp['epss_marginal_precision_gain_pp']:+0.1f} pp** over CVSS+KEV control."
        ),
        (
            f"- **Full ERS vs CVSS Gain:** **{comp['ers_vs_cvss_precision_gain_pp']:+0.1f} pp** "
            "over legacy CVSS prioritization."
        ),
        "",
        "## 2. Profile Ranking Performance (Precision & Recall Across Slices)",
        "",
        (
            "| Weight Profile | Weights (CVSS / EPSS / KEV) | Top Slice | "
            "Precision (%) | Recall (%) | Min ERS Score |"
        ),
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    profile_descriptions = {
        "balanced": ("Balanced (Production Default)", "0.40 / 0.35 / 0.25"),
        "no_epss_control": ("No-EPSS Control (Severity+KEV)", "0.60 / 0.00 / 0.40"),
        "cvss_only": ("CVSS-Only Baseline", "1.00 / 0.00 / 0.00"),
        "exploitation_heavy": ("Exploitation Heavy", "0.25 / 0.50 / 0.25"),
    }

    for pname, (label, w_str) in profile_descriptions.items():
        slices = results["profiles"].get(pname, {})
        for sname, sdata in slices.items():
            s_label = f"{sname.replace('_', ' ').title()} ({sdata['top_k']} CVEs)"
            lines.append(
                f"| **{label}** | {w_str} | {s_label} | "
                f"{sdata['precision_pct']}% | {sdata['recall_pct']}% | "
                f"{sdata['min_score_in_top_k']} |"
            )

    lines.extend(
        [
            "",
            "## 3. Top-Ranked Vulnerabilities Corroboration Table",
            "",
            (
                "| Rank | CVE ID | ERS (Balanced) | CVSS | EPSS (%) | In KEV | "
                "Public Exploit | Metasploit | Cohort |"
            ),
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )

    for i, item in enumerate(results["items"][:15], 1):
        cve = item["cve_id"]
        ers = item["score_balanced"]
        cvss = f"{item['cvss']:.1f}" if item["cvss"] is not None else "—"
        epss = f"{item['epss'] * 100.0:.1f}%" if item["epss"] is not None else "—"
        kev = "✅ Yes" if item["in_kev"] else "No"
        exp = "✅ EDB" if item["has_exploitdb"] else "—"
        msf = "✅ MSF" if item["has_metasploit"] else "—"
        cohort = item["cohort"]
        lines.append(
            f"| {i} | `{cve}` | **{ers:.2f}** | {cvss} | {epss} | {kev} | "
            f"{exp} | {msf} | {cohort} |"
        )

    lines.extend(
        [
            "",
            "## 4. Methodological Defense & Circularity Disclosure (D-038)",
            "",
            "### A. Partial Circularity Analysis",
            (
                "In academic viva defense, evaluators may question whether validating ERS "
                "against ExploitDB / Metasploit is circular:"
            ),
            (
                "1. **Direct Input Independence:** ExploitDB and Metasploit are **not** "
                "direct inputs to the ERS formula. ERS inputs are strictly CVSS Base Score, "
                "FIRST EPSS v4 probability, and CISA KEV membership."
            ),
            (
                "2. **Indirect Training Overlap (EPSS v4):** The FIRST EPSS machine learning "
                "model utilizes public exploit code availability (including ExploitDB records "
                "and GitHub PoCs) as features in its training pipeline. Therefore, corroborating "
                "ERS against ExploitDB involves partial feature overlap."
            ),
            "3. **Circularity Mitigation:**",
            (
                "   - **Independent Metasploit Corroboration:** Metasploit module presence "
                "indicates weaponized, high-reliability exploit tooling that requires manual "
                "engineering beyond raw PoC scripts."
            ),
            (
                "   - **Comparative Control Isolation:** By comparing Balanced ERS against the "
                "`no_epss_control` (EPSS zeroed out), we empirically isolate the precise "
                "predictive value added by EPSS versus technical severity alone."
            ),
            (
                "   - **Additive Non-Multiplicative Architecture:** ERS strictly avoids "
                "multiplying EPSS × CVSS (Project Hard Rule 1 & D-008). Each factor's "
                "provenance and contribution are recorded transparently in self-explaining "
                "`ScoreComponent` objects."
            ),
            "",
            "---",
            "_Generated by `evals/ers_validation.py`._",
            "",
        ]
    )

    return "\n".join(lines)


def write_outputs(results: dict[str, Any], output_json: Path, output_md: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(generate_markdown_report(results))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate ERS empirical validation against independent exploit mirrors."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=_DEFAULT_DATASET,
        help="Path to evaluation dataset JSON",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=_DEFAULT_CACHE_DIR,
        help="Path to mirror cache directory",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=_DEFAULT_OUTPUT_JSON,
        help="Path to output JSON results",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=_DEFAULT_OUTPUT_MD,
        help="Path to output Markdown report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output",
    )
    args = parser.parse_args(argv)

    results = run_ers_validation(
        dataset_path=args.dataset,
        cache_dir=args.cache_dir,
    )
    write_outputs(results, args.output_json, args.output_md)

    if not args.quiet:
        meta = results["metadata"]
        comp = results["comparison"]
        m_label = "Synthetic" if meta["synthetic_mode"] else "Real Mirrors"
        print("=" * 72)
        print("ERS Empirical Exploit Validation & Corroboration")
        print(f"Mode:                    {m_label}")
        print(f"Evaluated CVEs:          {meta['total_cves']}")
        print(
            f"Exploited CVEs:          {meta['total_exploited_cves']} "
            f"({meta['overall_exploit_rate_pct']}%)"
        )
        print("-" * 72)
        print(f"Top Decile Precision:    {comp['balanced_precision_pct']}% (Balanced ERS)")
        print(
            f"Control Precision:       {comp['no_epss_control_precision_pct']}% "
            "(No-EPSS Severity Control)"
        )
        print(f"CVSS-Only Precision:     {comp['cvss_only_precision_pct']}% (CVSS 1.0 Baseline)")
        print(f"EPSS Marginal Delta:     {comp['epss_marginal_precision_gain_pp']:+0.1f} pp")
        print(f"ERS vs CVSS Delta:       {comp['ers_vs_cvss_precision_gain_pp']:+0.1f} pp")
        print("=" * 72)
        print(f"Markdown report written to: {args.output_md}")
        print(f"JSON results written to:    {args.output_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
