"""CLI entry point for the enrichment feed sync job.

Runs standalone — no API server or Celery broker required.

Usage:
    python -m services.enrichment.sync_feeds                      # every source
    python -m services.enrichment.sync_feeds --source kev
    python -m services.enrichment.sync_feeds --cve CVE-2021-44228 --cve CVE-2024-3400
    python -m services.enrichment.sync_feeds --cve-file cves.txt --source nvd
    python -m services.enrichment.sync_feeds --cache-dir /data/enrichment_cache

Full mirrors (KEV, EPSS, ExploitDB, Metasploit) need no input. The targeted sources
(CVE.org, Vulnrichment, EUVD, NVD) fetch only the CVE IDs given with ``--cve`` /
``--cve-file``; the scheduled Celery task supplies the IDs from ``enriched_findings``.

Each run writes one audit event with actor ``system:cli``.

Network is ONLY allowed in this job. EnrichmentService / FusionEngine must
never make outbound requests (Rule 5, services/enrichment/README.md).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
from services.enrichment.sources.sync import ALL_SOURCES, FeedSyncer, SyncReport

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("seekthreat.sync_feeds")

CLI_ACTOR = "system:cli"
VALID_SOURCES = {*ALL_SOURCES, "all"}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m services.enrichment.sync_feeds",
        description=(
            "Download intelligence feed mirrors into ENRICHMENT_CACHE_DIR. "
            "Network is allowed only in this job."
        ),
    )
    parser.add_argument(
        "--source",
        default="all",
        choices=sorted(VALID_SOURCES),
        help="Which feed to sync (default: all).",
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        help="CVE ID for the targeted sources (repeatable).",
    )
    parser.add_argument(
        "--cve-file",
        type=Path,
        default=None,
        help="File of CVE IDs, one per line, for the targeted sources.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help=(
            "Directory to write mirror files into. "
            "Defaults to ENRICHMENT_CACHE_DIR or data/enrichment_cache."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="HTTP connect/read timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--allow-shrink",
        action="store_true",
        help="Allow replacing a mirror with one under 50%% of its previous record count.",
    )
    return parser.parse_args(argv)


def _log_report(report: SyncReport) -> None:
    for result in report.results:
        if result.success:
            logger.info(
                "ok %s: %d records -> %s (%s)",
                result.key,
                result.records_synced,
                result.target_path,
                result.note or "full mirror",
            )
        else:
            logger.error("FAILED %s: %s", result.key, result.error)


def main(argv: list[str] | None = None) -> int:
    """Run the feed sync and return an exit code (0=every source ok, 1=any failure)."""
    args = _parse_args(argv)

    # Same resolution as the API/worker readers: ENRICHMENT_CACHE_DIR (env or .env),
    # else the shared default directory.
    cache_dir: Path = args.cache_dir or settings.enrichment_cache_dir

    cve_ids: list[str] = list(args.cve)
    if args.cve_file is not None:
        cve_ids.extend(
            line.strip()
            for line in args.cve_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )

    syncer = FeedSyncer(
        cache_dir=cache_dir,
        timeout_seconds=args.timeout,
        nvd_api_key=settings.nvd_api_key,
        allow_shrink=args.allow_shrink,
    )
    sources = None if args.source == "all" else [args.source]
    report = syncer.sync_all(cve_ids=cve_ids, sources=sources)
    _log_report(report)

    details = report.to_summary()
    log_audit_event(
        event="feed_sync.completed" if report.ok else "feed_sync.failed",
        actor=CLI_ACTOR,
        target=",".join(r.key for r in report.results) or "no feeds selected",
        engagement_id="n/a",
        scanner="feed_sync",
        status="success" if report.ok else "failed",
        details={**details, "cve_ids_requested": len(cve_ids)},
    )
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
