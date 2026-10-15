"""Identify and rectify malformed CVE identifiers in legacy EnrichedFinding rows.

Background (DECISIONS.md D-040 & Task C-2):
Strict ASCII CVE regex validation was introduced in D-040. Legacy rows persisted
before D-040 might contain malformed CVE IDs (e.g., whitespace, lowercase, trailing null
bytes, or non-standard identifiers). When ``EnrichedFindingModel.to_schema()`` is
called on such rows, Pydantic raises a ValidationError.

This script scans ``EnrichedFindingModel`` rows in the database, normalizes salvageable
CVE IDs (stripping whitespace, uppercasing), drops completely invalid identifiers,
and updates the persisted JSON payload.

Usage:
    # Dry-run inspection (default):
    python scripts/cleanup_malformed_cve_ids.py

    # Apply changes to database:
    python scripts/cleanup_malformed_cve_ids.py --apply

    # Filter by specific engagement:
    python scripts/cleanup_malformed_cve_ids.py --apply --engagement-id eng-lab-01
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.api.db.models import EnrichedFindingModel
from apps.api.db.session import SessionLocal
from packages.schema.models.finding import CVE_ID_PATTERN

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cleanup_malformed_cve_ids")


def sanitize_cve_id(raw_cve: Any) -> str | None:
    """Normalize a CVE ID string, or return None if it is fundamentally malformed."""
    if not isinstance(raw_cve, str):
        return None
    cleaned = raw_cve.replace("\x00", "").strip().upper()
    if CVE_ID_PATTERN.fullmatch(cleaned):
        return cleaned
    return None


def cleanup_malformed_cve_ids(
    session: Session,
    *,
    apply: bool = False,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Scan and rectify malformed CVE IDs across EnrichedFindingModel rows.

    Returns summary metrics of scanned, modified, rectified, and dropped IDs.
    """
    stmt = select(EnrichedFindingModel)
    if engagement_id:
        stmt = stmt.where(EnrichedFindingModel.engagement_id == engagement_id)

    rows = session.scalars(stmt).all()
    total_scanned = len(rows)
    modified_rows = 0
    rectified_cve_count = 0
    dropped_cve_count = 0
    details: list[dict[str, Any]] = []

    for row in rows:
        finding_data = dict(row.finding_data or {})
        raw_cves = finding_data.get("cve_ids", [])
        if not isinstance(raw_cves, list):
            raw_cves = []

        cleaned_cves: list[str] = []
        row_changed = False
        seen: set[str] = set()

        for cve in raw_cves:
            sanitized = sanitize_cve_id(cve)
            if sanitized is not None:
                if sanitized not in seen:
                    seen.add(sanitized)
                    cleaned_cves.append(sanitized)
                if sanitized != cve:
                    rectified_cve_count += 1
                    row_changed = True
            else:
                dropped_cve_count += 1
                row_changed = True

        if row_changed:
            modified_rows += 1
            details.append({
                "engagement_id": row.engagement_id,
                "finding_id": row.finding_id,
                "before": raw_cves,
                "after": cleaned_cves,
            })
            if apply:
                finding_data["cve_ids"] = cleaned_cves
                row.finding_data = finding_data
                session.add(row)

    if apply and modified_rows > 0:
        session.commit()
        logger.info("Successfully committed updates for %d rows.", modified_rows)
    elif not apply and modified_rows > 0:
        logger.info("Dry-run complete. %d rows would be updated. Run with --apply to commit.", modified_rows)
    else:
        logger.info("Scan complete. All %d rows conform to valid CVE ID schemas.", total_scanned)

    return {
        "total_scanned": total_scanned,
        "modified_rows": modified_rows,
        "rectified_cve_count": rectified_cve_count,
        "dropped_cve_count": dropped_cve_count,
        "details": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean up malformed CVE IDs in EnrichedFinding rows.")
    parser.add_argument("--apply", action="store_true", help="Apply fixes to database (default is dry-run)")
    parser.add_argument("--engagement-id", type=str, help="Optional engagement ID filter")
    args = parser.parse_args()

    session = SessionLocal()
    try:
        results = cleanup_malformed_cve_ids(session, apply=args.apply, engagement_id=args.engagement_id)
        print(f"Total scanned: {results['total_scanned']}")
        print(f"Modified rows: {results['modified_rows']}")
        print(f"Rectified CVE IDs: {results['rectified_cve_count']}")
        print(f"Dropped malformed CVE IDs: {results['dropped_cve_count']}")
        for detail in results["details"]:
            print(f"  [{detail['engagement_id']} / {detail['finding_id']}]: {detail['before']} -> {detail['after']}")
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
