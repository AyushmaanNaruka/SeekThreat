#!/usr/bin/env bash
# Local version of the CI check. Run before pushing.
set -euo pipefail

BASE="${1:-main}"
CHANGED=$(git diff --name-only "$BASE"...HEAD)

VENDOR=0;   echo "$CHANGED" | grep -q '^vendor/'         && VENDOR=1
REGISTER=0; echo "$CHANGED" | grep -q '^THIRD_PARTY.md$' && REGISTER=1

if [ "$VENDOR" = "1" ] && [ "$REGISTER" = "0" ]; then
  echo "FAIL: vendor/ changed but THIRD_PARTY.md did not."
  echo "Add a register entry before pushing."
  exit 1
fi

echo "OK: third-party register is consistent."
