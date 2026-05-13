#!/usr/bin/env bash
# v2.4 composable transactions — apply-path regression test.
#
# Exercises the COMPOSABLE_BATCH apply semantics:
#   1. Successful batch: multiple inner TRANSFERs apply atomically,
#      both senders' balances and nonces update correctly.
#   2. Failing batch: one inner TRANSFER has insufficient balance;
#      whole batch rolls back atomically — earlier inner mutations
#      are undone even though they would have succeeded individually.
#      Outer fee + outer nonce are still consumed (block-space billing).
#
# In-process via `unchained test-composable-batch` CLI — no network,
# no RPC. Tests the protocol-level apply path directly against a
# freshly-constructed Chain with three accounts (alice, bob, carol).
#
# Run from repo root: bash tools/test_composable_batch.sh
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe

echo "=== v2.4 composable_batch apply semantics ==="
OUT=$($UNCHAINED test-composable-batch 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: composable_batch all assertions"; then
  echo ""
  echo "  PASS: v2.4 composable_batch apply path"
  exit 0
else
  echo ""
  echo "  FAIL: composable_batch had assertion failures"
  exit 1
fi
