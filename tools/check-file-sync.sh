#!/usr/bin/env bash
# check-file-sync.sh — enforce that lunarblock/<f>.lua stays as a shim pointing
# to the canonical src/<f>.lua.
#
# Background: the project has two historically-duplicated layouts:
#   - src/<module>.lua    (canonical; what the rockspec points at)
#   - lunarblock/<module>.lua  (resolves require("lunarblock.<module>") without
#                               an installed rock because luajit's default
#                               package.path includes ./?.lua)
#
# Previously these were two independent copies that drifted (fee.lua in
# Apr 2026-04-09, consensus.lua in 2026-04-12). As of PARALLEL-BUGFIX-BLITZ-2
# every lunarblock/<f>.lua is an auto-generated shim that dofile()s
# ../src/<f>.lua. This script fails CI if any lunarblock/<f>.lua is NOT a shim
# — i.e. someone tried to edit it directly instead of editing src/<f>.lua.
#
# Usage:
#   tools/check-file-sync.sh          # run from repo root
#   bash tools/check-file-sync.sh
#
# Exit codes:
#   0  all shims are properly delegating to src/
#   1  one or more lunarblock/<f>.lua is not a shim or targets the wrong file
#   2  invocation error (wrong cwd, etc.)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -d lunarblock ] || [ ! -d src ]; then
  echo "check-file-sync: must run from lunarblock repo root (need lunarblock/ and src/)" >&2
  exit 2
fi

fail=0
for shim in lunarblock/*.lua; do
  b="$(basename "$shim")"
  canonical="src/$b"
  if [ ! -f "$canonical" ]; then
    echo "FAIL: $shim has no canonical counterpart at $canonical" >&2
    fail=1
    continue
  fi
  # A valid shim must contain a dofile call referencing ../src/<b>.
  if ! grep -q "dofile.*\.\./src/$b" "$shim"; then
    echo "FAIL: $shim is not a shim (expected dofile \"../src/$b\")." >&2
    echo "      Edit src/$b instead. If you need a genuinely different" >&2
    echo "      lunarblock/$b, regenerate the shim with:" >&2
    echo "        tools/regen-shims.sh" >&2
    fail=1
    continue
  fi
  # Shims should be small (<= 30 lines). Larger means drift.
  lines="$(wc -l <"$shim")"
  if [ "$lines" -gt 30 ]; then
    echo "FAIL: $shim has $lines lines (shim should be small). Drift suspected." >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "" >&2
  echo "check-file-sync: one or more lunarblock/*.lua files have drifted from" >&2
  echo "src/. To fix: copy changes into src/<f>.lua and regenerate shims with" >&2
  echo "  tools/regen-shims.sh" >&2
  exit 1
fi

echo "check-file-sync: OK (all $(ls lunarblock/*.lua | wc -l) shims delegate to src/)"
