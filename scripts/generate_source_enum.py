"""Generate or verify packages/schema/sources.json from packages.schema.models.provenance.Source.

Single Source of Truth (Task C-3):
The backend Source enum defines the canonical intelligence & provenance sources.
This script serializes the enum to a shared JSON specification consumed by
frontend tests (apps/web/tests/findings.test.mjs), backend tests, and CI.

Usage:
    # Generate / update packages/schema/sources.json:
    python scripts/generate_source_enum.py

    # Verify sources.json is in sync with backend Source enum (used in CI):
    python scripts/generate_source_enum.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add repo root to sys.path so packages can be imported directly
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packages.schema.models.provenance import Source  # noqa: E402

OUTPUT_PATH = REPO_ROOT / "packages" / "schema" / "sources.json"


def generate_sources_payload() -> dict[str, object]:
    """Build the canonical sources dictionary from Source enum."""
    # Preserve enum definition order
    sources = [s.value for s in Source]
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "SeekThreat Intelligence and Provenance Sources",
        "description": (
            "Canonical list of intelligence and provenance sources derived from "
            "packages.schema.models.provenance.Source."
        ),
        "sources": sources,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify packages/schema/sources.json from backend Source enum."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that sources.json is up to date without modifying it (exit 1 if out of sync).",
    )
    args = parser.parse_args()

    payload = generate_sources_payload()
    formatted = json.dumps(payload, indent=2) + "\n"

    if args.check:
        if not OUTPUT_PATH.exists():
            print(
                f"ERROR: {OUTPUT_PATH} does not exist. Run without --check to generate.",
                file=sys.stderr,
            )
            return 1

        current_content = OUTPUT_PATH.read_text(encoding="utf-8")
        try:
            current_json = json.loads(current_content)
        except json.JSONDecodeError as exc:
            print(f"ERROR: {OUTPUT_PATH} contains invalid JSON: {exc}", file=sys.stderr)
            return 1

        if current_json.get("sources") != payload["sources"]:
            print(
                f"ERROR: {OUTPUT_PATH} is out of sync with Source enum!\n"
                f"Current sources in JSON: {current_json.get('sources')}\n"
                f"Expected sources from Enum: {payload['sources']}\n"
                f"Run `python scripts/generate_source_enum.py` to regenerate.",
                file=sys.stderr,
            )
            return 1

        print("OK: packages/schema/sources.json is up to date with backend Source enum.")
        return 0

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(formatted, encoding="utf-8")
    print(f"Wrote {len(payload['sources'])} sources to {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
