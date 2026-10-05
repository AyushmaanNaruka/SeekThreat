"""CLI entry point for the enrichment feed sync job.

Runs standalone — no API or Celery stack required.

Usage:
    python -m services.enrichment.sync_feeds
    python -m services.enrichment.sync_feeds --source kev
    python -m services.enrichment.sync_feeds --source epss
    python -m services.enrichment.sync_feeds --source cve_org
    python -m services.enrichment.sync_feeds --source all
    python -m services.enrichment.sync_feeds --cache-dir /data/enrichment_cache

Network is ONLY allowed in this job. EnrichmentService / FusionEngine must
never make outbound requests (Rule 5, services/enrichment/README.md).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from services.enrichment.sources.sync import FeedSyncer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("seekthreat.sync_feeds")

VALID_SOURCES = {
    "kev",
    "epss",
    "cve_org",
    "vulnrichment",
    "euvd",
    "exploitdb",
    "metasploit",
    "all",
}


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
        "--cache-dir",
        type=Path,
        default=None,
        help=(
            "Directory to write mirror files into. "
            "Defaults to ENRICHMENT_CACHE_DIR env var or data/enrichment_cache."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="HTTP request timeout in seconds (default: 60).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the feed sync and return an exit code (0=success, 1=any failure)."""
    args = _parse_args(argv)

    # Prefer CLI arg, then env var from settings, then FeedSyncer default.
    cache_dir: Path | None = args.cache_dir
    if cache_dir is None:
        try:
            from apps.api.core.config import settings

            cache_dir = settings.enrichment_cache_dir
        except Exception:
            pass  # Running outside the API app context — FeedSyncer uses its default.

    syncer = FeedSyncer(
        cache_dir=cache_dir,
        timeout_seconds=args.timeout,
    )

    if args.source == "all":
        results = syncer.sync_all(include_secondary=True)
    elif args.source == "kev":
        results = [syncer.sync_kev()]
    elif args.source == "epss":
        results = [syncer.sync_epss()]
    elif args.source == "cve_org":
        results = [syncer.sync_cve_org()]
    elif args.source == "vulnrichment":
        results = [syncer.sync_vulnrichment()]
    elif args.source == "euvd":
        results = [syncer.sync_euvd()]
    elif args.source == "exploitdb":
        results = [syncer.sync_exploitdb()]
    elif args.source == "metasploit":
        results = [syncer.sync_metasploit()]
    else:
        logger.error("Unknown source: %s", args.source)
        return 1

    any_failure = False
    for result in results:
        if result.success:
            logger.info(
                "✓ %s — %d records → %s",
                result.source.value,
                result.records_synced,
                result.target_path,
            )
        else:
            logger.error(
                "✗ %s — FAILED: %s",
                result.source.value,
                result.error,
            )
            any_failure = True

    return 1 if any_failure else 0


if __name__ == "__main__":
    sys.exit(main())
