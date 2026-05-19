#!/usr/bin/env bash
# S-035 Option 1 seed — Chain::save + Chain::load file-persistence
# round-trip. The chain.json on-disk format is what every node restarts
# from (snapshot-bootstrap is the alternative for new joiners; existing
# nodes load + replay chain.json).
#
# Covered:
#   - save writes a non-empty file
#   - load(path) reconstructs a Chain whose state matches the saved one
#     byte-for-byte (state_root, head_hash, height, accounts, stakes,
#     registry, A1 counters, R1 region)
#   - Atomic-write semantics: save→load→save→load idempotent
#   - load() of non-existent path returns an empty Chain (defensive —
#     a fresh node has no chain.json yet; relied on at first launch)
#
# 14 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_chain_save_load.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::save + Chain::load persistence round-trip ==="
OUT=$($DETERM test-chain-save-load 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-save-load all assertions"; then
  echo ""
  echo "  PASS: chain-save-load unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-save-load had assertion failures"
  exit 1
fi
