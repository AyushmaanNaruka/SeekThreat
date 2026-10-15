"""Generate the eval CVE list using a documented, reproducible stratified selection rule.

This script reads the local CISA KEV mirror and the FIRST EPSS v4 mirror (no network
calls — Rule 5 of services/enrichment/README.md) and produces:

  evals/golden/eval_cve_list.txt          – one CVE ID per line, sorted
  evals/golden/eval_cve_selection_manifest.json – mirror sha256s, strata, seed

Selection rule (documented in evals/golden/README.md §Selection rule):
  Universe:  all CVE IDs present in the EPSS mirror.
  KEV set:   all CVE IDs in the CISA KEV catalog (loaded from the same mirrors).
  Seed:      SEED = 20261011

  Stratum 1 – kev_high_epss      (n=15): KEV ∩ EPSS ≥ 0.50
  Stratum 2 – kev_low_epss       (n=10): KEV ∩ EPSS < 0.50
  Stratum 3 – non_kev_high_epss  (n=10): non-KEV ∩ EPSS ≥ 0.70
  Stratum 4 – non_kev_mid_epss   (n=10): non-KEV ∩ 0.10 ≤ EPSS < 0.70
  Stratum 5 – non_kev_low_epss   (n= 5): non-KEV ∩ EPSS < 0.005  (control)

If a stratum has fewer CVEs available than requested, all available are taken.
The script is deterministic: given the same mirror sha256s and SEED, it produces
the same output. Re-running with updated mirrors will produce a different list;
commit the manifest alongside to identify the snapshot.

Usage:
    python evals/scripts/generate_eval_cve_list.py \\
        --mirrors-dir data/enrichment_cache \\
        [--out-list   evals/golden/eval_cve_list.txt] \\
        [--out-manifest evals/golden/eval_cve_selection_manifest.json] \\
        [--seed 20261011] \\
        [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SEED: int = 20261011

STRATA: list[dict] = [
    {"name": "kev_high_epss",     "in_kev": True,  "epss_min": 0.50,  "epss_max": None, "n": 15},
    {"name": "kev_low_epss",      "in_kev": True,  "epss_min": None,  "epss_max": 0.50, "n": 10},
    {"name": "non_kev_high_epss", "in_kev": False, "epss_min": 0.70,  "epss_max": None, "n": 10},
    {"name": "non_kev_mid_epss",  "in_kev": False, "epss_min": 0.10,  "epss_max": 0.70, "n": 10},
    {"name": "non_kev_low_epss",  "in_kev": False, "epss_min": None,  "epss_max": 0.005,"n":  5},
]

_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$", re.ASCII)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Mirror loading
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _meta_synced_at(path: Path) -> str | None:
    """Read synced_at from the accompanying .meta.json sidecar, if present."""
    for candidate in (
        path.with_name(f"{path.stem}.meta.json"),
        Path(f"{path}.meta.json"),
    ):
        if candidate.exists():
            try:
                meta = json.loads(candidate.read_text(encoding="utf-8"))
                v = meta.get("synced_at") if isinstance(meta, dict) else None
                return str(v) if v else None
            except (OSError, ValueError):
                return None
    return None


def load_kev_ids(mirrors_dir: Path) -> set[str]:
    """Return the set of CVE IDs that appear in the loaded CISA KEV mirror."""
    kev_path = mirrors_dir / "cisa_kev.json"
    if not kev_path.exists():
        print(f"[warn] KEV mirror not found at {kev_path}; KEV stratum will be empty", file=sys.stderr)
        return set()

    data = json.loads(kev_path.read_text(encoding="utf-8"))
    kev_ids: set[str] = set()
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                cid = v.get("cveID", "") if isinstance(v, dict) else ""
                if _CVE_RE.match(cid.strip().upper()):
                    kev_ids.add(cid.strip().upper())
    return kev_ids


def load_epss_scores(mirrors_dir: Path) -> dict[str, float]:
    """Return {cve_id: epss_score} from the FIRST EPSS v4 mirror."""
    epss_path = mirrors_dir / "epss_v4.json"
    if not epss_path.exists():
        print(f"[error] EPSS mirror not found at {epss_path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(epss_path.read_text(encoding="utf-8"))
    scores: dict[str, float] = {}

    if isinstance(data, dict) and "data" in data:
        for entry in data["data"]:
            if isinstance(entry, dict):
                cid = str(entry.get("cve", "")).strip().upper()
                try:
                    epss = float(entry["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
                if _CVE_RE.match(cid):
                    scores[cid] = epss
    elif isinstance(data, dict):
        # Flat dict {cve_id: {epss: ...}} or {cve_id: score}
        for cid, val in data.items():
            if not _CVE_RE.match(cid.strip().upper()):
                continue
            try:
                if isinstance(val, dict):
                    epss = float(val.get("epss", val.get("score", 0)))
                else:
                    epss = float(val)
            except (TypeError, ValueError):
                continue
            scores[cid.strip().upper()] = epss

    if not scores:
        print("[error] No EPSS scores parsed from mirror — check mirror format", file=sys.stderr)
        sys.exit(1)

    return scores


# ---------------------------------------------------------------------------
# Stratified sampling
# ---------------------------------------------------------------------------

@dataclass
class StratumResult:
    name: str
    requested_n: int
    available_n: int
    selected: list[str] = field(default_factory=list)


def stratified_sample(
    epss: dict[str, float],
    kev_ids: set[str],
    strata: list[dict],
    seed: int,
) -> tuple[list[str], list[StratumResult]]:
    """Perform stratified sampling. Returns (sorted_cve_list, stratum_results)."""
    rng = random.Random(seed)
    selected_all: set[str] = set()
    results: list[StratumResult] = []

    for spec in strata:
        in_kev_filter: bool = spec["in_kev"]
        epss_min: float | None = spec["epss_min"]
        epss_max: float | None = spec["epss_max"]
        target_n: int = spec["n"]

        pool = [
            cid for cid, score in epss.items()
            if (cid in kev_ids) == in_kev_filter
            and (epss_min is None or score >= epss_min)
            and (epss_max is None or score < epss_max)
            and cid not in selected_all
        ]
        pool.sort()  # deterministic sort before shuffle
        rng.shuffle(pool)

        chosen = pool[:target_n]
        selected_all.update(chosen)

        results.append(StratumResult(
            name=spec["name"],
            requested_n=target_n,
            available_n=len(pool),
            selected=sorted(chosen),
        ))

    return sorted(selected_all), results


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def build_manifest(
    mirrors_dir: Path,
    strata_results: list[StratumResult],
    seed: int,
    generated_at: str,
) -> dict:
    kev_path = mirrors_dir / "cisa_kev.json"
    epss_path = mirrors_dir / "epss_v4.json"

    def _mirror_info(p: Path) -> dict:
        if not p.exists():
            return {"path": str(p), "present": False}
        return {
            "path": p.name,
            "sha256": _sha256_file(p),
            "synced_at": _meta_synced_at(p),
            "size_bytes": p.stat().st_size,
        }

    return {
        "_generated_by": "evals/scripts/generate_eval_cve_list.py",
        "generated_at": generated_at,
        "seed": seed,
        "selection_rule": (
            "Stratified random sample from EPSS v4 mirror universe, "
            "split by KEV membership and EPSS score threshold bands."
        ),
        "mirrors": {
            "cisa_kev": _mirror_info(kev_path),
            "epss_v4": _mirror_info(epss_path),
        },
        "strata": [
            {
                "name": sr.name,
                "requested_n": sr.requested_n,
                "available_n": sr.available_n,
                "selected_n": len(sr.selected),
                "selected": sr.selected,
            }
            for sr in strata_results
        ],
        "total_selected": sum(len(sr.selected) for sr in strata_results),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the eval CVE list using a documented stratified selection rule.",
    )
    parser.add_argument(
        "--mirrors-dir",
        default=str(_REPO_ROOT / "data" / "enrichment_cache"),
        help="Directory containing local mirror files (default: data/enrichment_cache)",
    )
    parser.add_argument(
        "--out-list",
        default=str(_REPO_ROOT / "evals" / "golden" / "eval_cve_list.txt"),
        help="Output path for eval_cve_list.txt",
    )
    parser.add_argument(
        "--out-manifest",
        default=str(_REPO_ROOT / "evals" / "golden" / "eval_cve_selection_manifest.json"),
        help="Output path for eval_cve_selection_manifest.json",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help=f"Random seed (default: {SEED})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print selected CVEs without writing files",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output",
    )
    args = parser.parse_args(argv)

    mirrors_dir = Path(args.mirrors_dir)
    if not mirrors_dir.is_dir():
        print(f"[error] mirrors-dir does not exist: {mirrors_dir}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[info] Loading EPSS mirror from {mirrors_dir}/epss_v4.json ...")
    epss = load_epss_scores(mirrors_dir)
    if not args.quiet:
        print(f"[info] Loaded {len(epss):,} EPSS scores")

    if not args.quiet:
        print(f"[info] Loading KEV mirror from {mirrors_dir}/cisa_kev.json ...")
    kev_ids = load_kev_ids(mirrors_dir)
    if not args.quiet:
        print(f"[info] Loaded {len(kev_ids):,} KEV entries")

    cve_list, strata_results = stratified_sample(epss, kev_ids, STRATA, args.seed)

    generated_at = datetime.now(UTC).isoformat()
    manifest = build_manifest(mirrors_dir, strata_results, args.seed, generated_at)

    if not args.quiet:
        print(f"\n[info] Selection summary:")
        for sr in strata_results:
            print(f"  {sr.name:<26} requested={sr.requested_n:2d}  "
                  f"available={sr.available_n:6,d}  selected={len(sr.selected):2d}")
        print(f"  {'TOTAL':<26} {'':5s}                       selected={len(cve_list):2d}")

    if args.dry_run:
        print("\n[dry-run] CVEs selected:")
        for cid in cve_list:
            print(f"  {cid}")
        return 0

    out_list = Path(args.out_list)
    out_manifest = Path(args.out_manifest)
    out_list.parent.mkdir(parents=True, exist_ok=True)
    out_manifest.parent.mkdir(parents=True, exist_ok=True)

    out_list.write_text("\n".join(cve_list) + "\n", encoding="utf-8")
    out_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if not args.quiet:
        print(f"\n[info] Written: {out_list}")
        print(f"[info] Written: {out_manifest}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
