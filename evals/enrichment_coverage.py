"""Enrichment coverage evaluation harness.

Compares SeekThreat multi-source fusion against an NVD-only baseline engine over the
CVE list in ``evals/golden/enrichment_baseline.json``. Complies with evals/README.md:
no network calls, and no number is written unless this script computed it.

What is measured
----------------
* **Headline coverage** counts only the intelligence fields ``cvss_score``, ``cwe_ids``,
  ``summary`` and ``epss_score``. A field is "filled" when it is present, non-empty and
  not a placeholder. Placeholders are identified by provenance alone
  (``Source.DERIVED`` or ``Confidence.LOW``), never by value: a real CVSS of 5.0 or a
  real EPSS of 0.001 exist and must count.
* **Signal fields** ``in_kev`` and ``exploit_availability`` are NOT in the headline. A
  loaded mirror answers every lookup with a definite True/False, so "has a definite
  value" just means "the mirror file exists". They are reported separately as
  "mirror loaded" plus the positive-hit rate.

Known limitation of the baseline
--------------------------------
The baseline engine parses only NVD CVSS, CWE and description (``NVDSource``). The real
NVD API 2.0 also carries CISA KEV fields (``cisaExploitAdd``, ``cisaActionDue``, ...)
which ``NVDSource`` does not parse, so the baseline's missing KEV signal is a property of
this harness, not of NVD. EPSS, KEV and exploit sources are simply not loaded in the
baseline; their absence there is definitional and is reported as "not loaded", not as 0%.

Synthetic vs real mirrors
-------------------------
The run is "synthetic" when any loaded mirror file is a JSON object with a truthy
``_synthetic`` key (the fixtures in ``tests/fixtures/enrichment/`` all are). In
non-synthetic mode each mirror's sha256, mtime and ``synced_at`` (from a
``<name>.meta.json`` sidecar, if present) are recorded, plus a generation timestamp.
Synthetic-mode output carries no wall-clock data so the committed results reproduce
byte-for-byte.
"""

from __future__ import annotations

# ruff: noqa: E402
import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path when script is invoked directly
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from packages.schema.models.finding import Finding
from packages.schema.models.provenance import Attributed, Confidence, Source
from services.enrichment.fusion import _CHAIN_ORDER, FusionEngine
from services.enrichment.sources.cisa_kev import CISAKevSource
from services.enrichment.sources.cve_org import CVEOrgSource
from services.enrichment.sources.epss import FirstEPSSSource
from services.enrichment.sources.secondary import (
    EUVDSource,
    ExploitDBSource,
    MetasploitSource,
    NVDSource,
    VulnrichmentSource,
)

HEADLINE_FIELDS = ("cvss_score", "cwe_ids", "summary", "epss_score")
SIGNAL_FIELDS = ("in_kev", "exploit_availability")

SYNTHETIC_BANNER = (
    "SYNTHETIC SMOKE TEST — harness validation on hand-authored fixtures. These are not "
    "measurements of the platform; no real-world coverage number exists yet."
)

# Mirror base names searched in the cache dir, in report order.
MIRROR_NAMES = (
    "nvd",
    "cve_org",
    "vulnrichment",
    "euvd",
    "epss_v4",
    "cisa_kev",
    "exploitdb",
    "metasploit",
)

_DEFAULT_DATASET = Path("evals/golden/enrichment_baseline.json")
_DEFAULT_CACHE_DIR = Path("tests/fixtures/enrichment")
_DEFAULT_OUTPUT_MD = Path("evals/results/enrichment_coverage_results.md")
_DEFAULT_OUTPUT_JSON = Path("evals/results/enrichment_coverage_results.json")

# Fixed timestamp for the synthetic findings the harness fuses. Fusion output used here
# does not depend on it; fixing it keeps the run free of wall-clock input.
_EVAL_DETECTED_AT = datetime(2026, 1, 1, tzinfo=UTC)


def _is_placeholder(attr: Attributed[Any]) -> bool:
    """A value is a placeholder when its provenance says so: DERIVED source or LOW confidence."""
    return attr.provenance.source == Source.DERIVED or attr.provenance.confidence == Confidence.LOW


def _is_filled(field_name: str, fields: dict[str, Attributed[Any]]) -> bool:
    """True when a headline field holds a present, non-empty, non-placeholder value."""
    if field_name not in HEADLINE_FIELDS:
        raise ValueError(f"{field_name!r} is not a headline coverage field")
    attr = fields.get(field_name)
    if attr is None or attr.value is None or _is_placeholder(attr):
        return False
    if isinstance(attr.value, list):
        return len(attr.value) > 0
    if isinstance(attr.value, str):
        return bool(attr.value.strip())
    return True


def _definite_bool(attr: Attributed[Any] | None, source: Source) -> bool | None:
    """The attributed boolean if it is a definite answer from ``source``, else None."""
    if attr is None or attr.provenance.source != source or _is_placeholder(attr):
        return None
    return attr.value if isinstance(attr.value, bool) else None


def _signal_state(field_name: str, fields: dict[str, Attributed[Any]]) -> str:
    """Classify a signal field as ``positive``, ``negative`` or ``unknown``."""
    if field_name == "in_kev":
        values = [_definite_bool(fields.get("in_kev"), Source.KEV)]
    elif field_name == "exploit_availability":
        values = [
            _definite_bool(fields.get("has_public_exploit"), Source.EXPLOITDB),
            _definite_bool(fields.get("has_metasploit_module"), Source.METASPLOIT),
        ]
    else:
        raise ValueError(f"{field_name!r} is not a signal field")
    if any(v is True for v in values):
        return "positive"
    if any(v is False for v in values):
        return "negative"
    return "unknown"


def _signal_mirror_loaded(field_name: str, engine: FusionEngine) -> bool:
    if field_name == "in_kev":
        return engine.cisa_kev.is_loaded
    edb = engine.exploitdb is not None and engine.exploitdb.is_loaded
    msf = engine.metasploit is not None and engine.metasploit.is_loaded
    return edb or msf


def _find_fixture_or_mirror(directory: Path, base_name: str) -> Path | None:
    """Find either <name>.json or <name>_sample.json in directory."""
    direct = directory / f"{base_name}.json"
    if direct.exists():
        return direct
    sample = directory / f"{base_name}_sample.json"
    if sample.exists():
        return sample
    return None


def _is_synthetic_file(path: Path) -> bool:
    """True when the file is a JSON object carrying a truthy ``_synthetic`` key."""
    if path.suffix.lower() != ".json":
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and bool(data.get("_synthetic"))


def _sidecar_synced_at(path: Path) -> str | None:
    """``synced_at`` from a ``<name>.meta.json`` sidecar next to the mirror, if present."""
    for candidate in (path.with_name(f"{path.stem}.meta.json"), Path(f"{path}.meta.json")):
        if candidate.exists():
            try:
                meta = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
            value = meta.get("synced_at") if isinstance(meta, dict) else None
            return str(value) if value is not None else None
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rel_posix(path: Path) -> str:
    """Repo-relative POSIX path when possible, so reports are identical across OSes."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def _mirror_paths(cache_dir: Path, nvd_override: Path | None) -> dict[str, Path | None]:
    paths = {name: _find_fixture_or_mirror(cache_dir, name) for name in MIRROR_NAMES}
    if nvd_override is not None:
        paths["nvd"] = nvd_override
    return paths


def describe_mirrors(paths: dict[str, Path | None]) -> tuple[bool, list[dict[str, Any]]]:
    """Return (synthetic, per-mirror descriptions) for the mirror files found."""
    present = {name: p for name, p in paths.items() if p is not None and p.exists()}
    flags = {name: _is_synthetic_file(p) for name, p in present.items()}
    synthetic = any(flags.values())

    described: list[dict[str, Any]] = []
    for name in MIRROR_NAMES:
        path = present.get(name)
        if path is None:
            described.append({"name": name, "path": None, "present": False})
            continue
        entry: dict[str, Any] = {
            "name": name,
            "path": _rel_posix(path),
            "present": True,
            "synthetic": flags[name],
        }
        if not synthetic:
            entry["sha256"] = _sha256(path)
            entry["mtime"] = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat()
            entry["synced_at"] = _sidecar_synced_at(path)
        described.append(entry)
    return synthetic, described


def build_engines(
    cache_dir: Path, nvd_override: Path | None = None
) -> tuple[FusionEngine, FusionEngine]:
    """Build the NVD-only baseline engine and the multi-source fusion engine."""
    paths = _mirror_paths(cache_dir, nvd_override)
    nvd_path = paths["nvd"]

    # Baseline: NVD only. Every other source is either unloaded or absent.
    baseline_engine = FusionEngine(
        cve_org=CVEOrgSource(cache_file=None),
        cisa_kev=CISAKevSource(cache_file=None),
        first_epss=FirstEPSSSource(cache_file=None),
        vulnrichment=None,
        nvd=NVDSource(cache_file=nvd_path),
        euvd=None,
        exploitdb=None,
        metasploit=None,
    )

    multi_engine = FusionEngine(
        cve_org=CVEOrgSource(cache_file=paths["cve_org"]),
        cisa_kev=CISAKevSource(cache_file=paths["cisa_kev"]),
        first_epss=FirstEPSSSource(cache_file=paths["epss_v4"]),
        vulnrichment=VulnrichmentSource(cache_file=paths["vulnrichment"]),
        nvd=NVDSource(cache_file=nvd_path),
        euvd=EUVDSource(cache_file=paths["euvd"]),
        exploitdb=ExploitDBSource(cache_file=paths["exploitdb"]),
        metasploit=MetasploitSource(cache_file=paths["metasploit"]),
    )

    return baseline_engine, multi_engine


def _pct(count: int, total: int) -> float:
    return round(count / total * 100.0, 1) if total else 0.0


def _signal_summary(field_name: str, engine: FusionEngine, states: list[str]) -> dict[str, Any]:
    n = len(states)
    positives = states.count("positive")
    negatives = states.count("negative")
    loaded = _signal_mirror_loaded(field_name, engine)
    return {
        "mirror_loaded": loaded,
        "positive_count": positives,
        "negative_count": negatives,
        "unknown_count": states.count("unknown"),
        "positive_rate_pct": _pct(positives, n) if loaded else None,
    }


def run_evaluation(
    dataset_path: Path,
    cache_dir: Path,
    nvd_override: Path | None = None,
) -> dict[str, Any]:
    """Run the evaluation over the dataset and compute coverage statistics."""
    with open(dataset_path, encoding="utf-8") as f:
        raw_dataset = json.load(f)

    items = raw_dataset.get("items", [])
    if not items:
        raise ValueError(f"No items found in dataset at {dataset_path}")

    synthetic, mirrors = describe_mirrors(_mirror_paths(cache_dir, nvd_override))
    baseline_engine, multi_engine = build_engines(cache_dir, nvd_override)
    engines = {"baseline": baseline_engine, "multi_source": multi_engine}

    n_items = len(items)
    filled = {e: {f: 0 for f in HEADLINE_FIELDS} for e in engines}
    signal_states: dict[str, dict[str, list[str]]] = {
        e: {f: [] for f in SIGNAL_FIELDS} for e in engines
    }
    cohort_counts: dict[str, dict[str, int]] = {}
    item_results: list[dict[str, Any]] = []

    for item in items:
        cve_id = item["cve_id"]
        cohort = item.get("cohort", "unclassified")
        cstats = cohort_counts.setdefault(cohort, {"count": 0, "baseline": 0, "multi_source": 0})
        cstats["count"] += 1

        finding = Finding(
            finding_id=f"eval-{cve_id}",
            engagement_id="eng-eval-baseline",
            asset_id="asset-eval-target",
            scanner="eval_harness",
            title=f"Evaluation finding for {cve_id}",
            description="Synthetic evaluation finding for enrichment coverage harness",
            observation_ids=[f"obs-{cve_id}"],
            detected_at=_EVAL_DETECTED_AT,
            cve_ids=[cve_id],
        )

        item_eval: dict[str, Any] = {"cve_id": cve_id, "cohort": cohort}
        for ename, engine in engines.items():
            fields = engine.fuse(finding)
            per_field: dict[str, Any] = {}
            for field in HEADLINE_FIELDS:
                is_filled = _is_filled(field, fields)
                per_field[field] = is_filled
                if is_filled:
                    filled[ename][field] += 1
                    cstats[ename] += 1
            for field in SIGNAL_FIELDS:
                state = _signal_state(field, fields)
                per_field[field] = state
                signal_states[ename][field].append(state)
            item_eval[ename] = per_field
        item_results.append(item_eval)

    total_instances = n_items * len(HEADLINE_FIELDS)
    base_total = sum(filled["baseline"].values())
    multi_total = sum(filled["multi_source"].values())
    base_pct = _pct(base_total, total_instances)
    multi_pct = _pct(multi_total, total_instances)

    per_field_out: dict[str, dict[str, Any]] = {}
    for field in HEADLINE_FIELDS:
        b_cnt = filled["baseline"][field]
        m_cnt = filled["multi_source"][field]
        per_field_out[field] = {
            "baseline_count": b_cnt,
            "baseline_pct": _pct(b_cnt, n_items),
            "multi_count": m_cnt,
            "multi_pct": _pct(m_cnt, n_items),
            "improvement_pp": round(_pct(m_cnt, n_items) - _pct(b_cnt, n_items), 1),
        }

    signals_out = {
        field: {
            ename: _signal_summary(field, engine, signal_states[ename][field])
            for ename, engine in engines.items()
        }
        for field in SIGNAL_FIELDS
    }

    cohort_summary: dict[str, dict[str, Any]] = {}
    for cname, cdata in cohort_counts.items():
        c_inst = cdata["count"] * len(HEADLINE_FIELDS)
        c_b = _pct(cdata["baseline"], c_inst)
        c_m = _pct(cdata["multi_source"], c_inst)
        cohort_summary[cname] = {
            "count": cdata["count"],
            "baseline_filled": cdata["baseline"],
            "multi_filled": cdata["multi_source"],
            "baseline_coverage_pct": c_b,
            "multi_coverage_pct": c_m,
            "improvement_pp": round(c_m - c_b, 1),
        }

    metadata: dict[str, Any] = {
        "banner": SYNTHETIC_BANNER if synthetic else None,
        "sample_mode": "synthetic_fixtures" if synthetic else "real_mirrors",
        "dataset_path": _rel_posix(dataset_path),
        "dataset_verification": raw_dataset.get("verification"),
        "cache_dir": _rel_posix(cache_dir),
        "fusion_chain_order": [s.value for s in _CHAIN_ORDER],
        "headline_fields": list(HEADLINE_FIELDS),
        "signal_fields": list(SIGNAL_FIELDS),
        "baseline_limitation": (
            "Baseline engine parses only NVD CVSS, CWE and description via NVDSource. "
            "NVD API 2.0 KEV fields (cisaExploitAdd etc.) are not parsed; EPSS, KEV and "
            "exploit sources are not loaded in the baseline."
        ),
        "mirrors": mirrors,
        "total_cves": n_items,
        "total_headline_instances": total_instances,
    }
    if not synthetic:
        metadata["generated_at"] = datetime.now(UTC).isoformat()

    return {
        "metadata": metadata,
        "summary": {
            "baseline_filled": base_total,
            "multi_filled": multi_total,
            "baseline_overall_coverage_pct": base_pct,
            "multi_overall_coverage_pct": multi_pct,
            "coverage_improvement_pp": round(multi_pct - base_pct, 1),
        },
        "per_field": per_field_out,
        "signals": signals_out,
        "cohorts": cohort_summary,
        "items": item_results,
    }


def _signed_pp(value: float) -> str:
    """Format a percentage-point delta with exactly one sign."""
    return f"+{value} pp" if value >= 0 else f"{value} pp"


def _signal_cell(summary: dict[str, Any], n: int) -> str:
    if not summary["mirror_loaded"]:
        return "not loaded"
    return f"loaded; positive {summary['positive_rate_pct']}% ({summary['positive_count']}/{n})"


def generate_markdown_report(results: dict[str, Any]) -> str:
    """Generate a human-readable Markdown report from evaluation results."""
    meta = results["metadata"]
    summary = results["summary"]
    n = meta["total_cves"]
    is_synthetic = meta["sample_mode"] == "synthetic_fixtures"

    md: list[str] = ["# Enrichment Coverage Evaluation Results", ""]
    if is_synthetic:
        md.extend([f"> **{meta['banner']}**", ""])

    md.extend(
        [
            f"**Mode:** {'Synthetic fixtures' if is_synthetic else 'Real mirrors'}  ",
            f"**Dataset:** `{meta['dataset_path']}` ({n} CVEs)  ",
        ]
    )
    if meta.get("dataset_verification"):
        md.append(f"**Dataset verification:** {meta['dataset_verification']}  ")
    md.append(f"**Source cache:** `{meta['cache_dir']}`  ")
    md.append(f"**Fusion chain order:** {' -> '.join(meta['fusion_chain_order'])} -> derived  ")
    if meta.get("generated_at"):
        md.append(f"**Generated at:** {meta['generated_at']}  ")

    md.extend(["", "## Mirror files", "", "| Mirror | Path | Synthetic |"])
    if not is_synthetic:
        md[-1] += " sha256 | mtime | synced_at |"
        md.append("|---|---|---|---|---|---|")
    else:
        md.append("|---|---|---|")
    for m in meta["mirrors"]:
        if not m["present"]:
            row = f"| `{m['name']}` | not present | - |"
            if not is_synthetic:
                row += " - | - | - |"
        else:
            row = f"| `{m['name']}` | `{m['path']}` | {'yes' if m['synthetic'] else 'no'} |"
            if not is_synthetic:
                row += f" `{m['sha256']}` | {m['mtime']} | {m['synced_at'] or '-'} |"
        md.append(row)

    md.extend(
        [
            "",
            "## Headline coverage (cvss_score, cwe_ids, summary, epss_score)",
            "",
            "| Metric | NVD-only baseline | Multi-source | Difference |",
            "|---|---|---|---|",
            f"| Overall | {summary['baseline_overall_coverage_pct']}% "
            f"({summary['baseline_filled']}/{meta['total_headline_instances']}) | "
            f"{summary['multi_overall_coverage_pct']}% "
            f"({summary['multi_filled']}/{meta['total_headline_instances']}) | "
            f"{_signed_pp(summary['coverage_improvement_pp'])} |",
            "",
            "| Field | NVD-only baseline | Multi-source | Difference |",
            "|---|---|---|---|",
        ]
    )
    for f_id, data in results["per_field"].items():
        md.append(
            f"| `{f_id}` | {data['baseline_pct']}% ({data['baseline_count']}/{n}) | "
            f"{data['multi_pct']}% ({data['multi_count']}/{n}) | "
            f"{_signed_pp(data['improvement_pp'])} |"
        )

    md.extend(
        [
            "",
            "## Signal fields (not in the headline)",
            "",
            "A loaded mirror answers every lookup with a definite True/False, so these are "
            "reported as whether the mirror was loaded and how many CVEs hit positive.",
            "",
            "| Field | NVD-only baseline | Multi-source |",
            "|---|---|---|",
        ]
    )
    for f_id, per_engine in results["signals"].items():
        md.append(
            f"| `{f_id}` | {_signal_cell(per_engine['baseline'], n)} | "
            f"{_signal_cell(per_engine['multi_source'], n)} |"
        )

    md.extend(
        [
            "",
            "## Cohorts (headline fields)",
            "",
            "| Cohort | CVEs | NVD-only baseline | Multi-source | Difference |",
            "|---|---|---|---|---|",
        ]
    )
    for c_id, c in results["cohorts"].items():
        md.append(
            f"| `{c_id}` | {c['count']} | {c['baseline_coverage_pct']}% | "
            f"{c['multi_coverage_pct']}% | {_signed_pp(c['improvement_pp'])} |"
        )

    md.extend(
        [
            "",
            "## Limitations",
            "",
            f"- {meta['baseline_limitation']}",
            "- Cohort labels come from the dataset and are unverified hypotheses; see "
            "`evals/golden/README.md`.",
        ]
    )
    if is_synthetic:
        md.append(
            "- Every mirror marked synthetic above is a hand-authored fixture covering a "
            "handful of CVEs. Coverage here reflects which CVEs the fixtures happen to "
            "contain, not the platform."
        )
    md.extend(["", "---", "_Generated by `evals/enrichment_coverage.py`._", ""])
    return "\n".join(md)


def write_outputs(results: dict[str, Any], output_json: Path, output_md: Path) -> None:
    """Write JSON and Markdown results with LF line endings."""
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    output_md.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as f:
        f.write(generate_markdown_report(results))


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for enrichment coverage eval."""
    parser = argparse.ArgumentParser(
        description="Measure SeekThreat enrichment coverage vs an NVD-only baseline."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=_DEFAULT_DATASET,
        help="Path to golden evaluation dataset JSON",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=_DEFAULT_CACHE_DIR,
        help="Path to local source mirror directory",
    )
    parser.add_argument(
        "--nvd-file",
        type=Path,
        default=None,
        help="Explicit path to NVD mirror file for baseline (optional)",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=_DEFAULT_OUTPUT_MD,
        help="Path to output Markdown results report",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=_DEFAULT_OUTPUT_JSON,
        help="Path to output JSON results",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress stdout summary output")
    args = parser.parse_args(argv)
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")

    if not args.dataset.exists():
        sys.stderr.write(f"Error: Dataset not found at {args.dataset}\n")
        return 1
    if not args.cache_dir.exists():
        sys.stderr.write(f"Error: Cache directory not found at {args.cache_dir}\n")
        return 1

    results = run_evaluation(
        dataset_path=args.dataset,
        cache_dir=args.cache_dir,
        nvd_override=args.nvd_file,
    )
    write_outputs(results, args.output_json, args.output_md)

    if not args.quiet:
        meta = results["metadata"]
        summary = results["summary"]
        n = meta["total_cves"]
        print("=" * 72)
        if meta["banner"]:
            print(meta["banner"])
            print("-" * 72)
        print(f"Evaluated CVEs:          {n}")
        print(f"Headline (NVD-only):     {summary['baseline_overall_coverage_pct']}%")
        print(f"Headline (multi-source): {summary['multi_overall_coverage_pct']}%")
        print(f"Difference:              {_signed_pp(summary['coverage_improvement_pp'])}")
        print("-" * 72)
        for fid, fs in results["per_field"].items():
            print(
                f"  {fid:<22} {fs['baseline_pct']:>5.1f}% -> {fs['multi_pct']:>5.1f}%  "
                f"({_signed_pp(fs['improvement_pp'])})"
            )
        print("Signals (not in headline):")
        for fid, per_engine in results["signals"].items():
            print(
                f"  {fid:<22} baseline: {_signal_cell(per_engine['baseline'], n)}; "
                f"multi: {_signal_cell(per_engine['multi_source'], n)}"
            )
        print("=" * 72)
        print(f"Markdown report written to: {args.output_md}")
        print(f"JSON results written to:    {args.output_json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
