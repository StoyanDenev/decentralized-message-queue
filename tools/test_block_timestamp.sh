#!/usr/bin/env bash
# S-035 Option 1 seed — Block.timestamp hash-surface scope.
#
# The timestamp field is operator-supplied (no clock-monotonicity
# enforcement at the chain layer — that's validator concern). This
# test pins which hash surfaces timestamp DOES vs DOES NOT participate
# in:
#
#   - IN compute_hash (block identity changes with timestamp)
#   - IN signing_bytes (creator_block_sigs must NOT be replayable
#     across blocks with different timestamps)
#   - NOT in state_root (state_root binds ACCOUNT state, not block-
#     metadata — light-client proofs depend on this)
#   - NOT in compute_block_digest (the FA1 committee-signature path
#     commits to body, excludes consensus-time metadata)
#
# Documenting and pinning these boundaries — a regression that
# accidentally bound timestamp into state_root would break the
# light-client equivalence proofs.
#
# 6 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_block_timestamp.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block.timestamp hash-surface scope — IN compute_hash + signing_bytes; NOT in state_root + digest ==="
OUT=$($DETERM test-block-timestamp 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-timestamp all assertions"; then
  echo ""
  echo "  PASS: block-timestamp unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-timestamp had assertion failures"
  exit 1
fi
