#!/usr/bin/env bash
# A4 / S-048 increment A4.5 (BoundedReorgDesign.md A4.5): the reorg-during-save
# CRASH-CONSISTENCY of the chain-blocks-v1 store.
#
# A head reorg clamps persisted_count_ below the on-disk manifest height, so the
# next save_incremental REWRITES the tail block file in place — no longer
# append-only. This test proves (1) the DANGER is real (a crash between the tail
# rewrite and the manifest update bricks load() on a head_hash mismatch) and
# (2) the shrink-manifest-first ordering makes EVERY crash window reload a
# consistent chain. It drives the real save_incremental through the chain::
# testonly crash seam, throwing at each atomic file boundary.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. DANGER PROOF — manifest{h3,head=OLD} beside a tail rewritten to the winner
#      bricks load() with a head_hash mismatch (the window A4.5 eliminates);
#   2-4. FIX PROOF — crash before/after the shrink manifest and after the tail
#      rewrite each reloads a consistent chain (OLD@h3 / floor@h2 / floor@h2);
#   5. FULL COMPLETION — a disarmed reorg save reloads the winner at h3;
#   6. RECOVERY — a save retried after a mid-reorg-save crash completes the reorg.
#
# Run from repo root: bash tools/test_chain_reorg_save_crash.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== chain-reorg-save-crash: reorg-during-save crash-consistency (A4.5) ==="
OUT=$($DETERM test-chain-reorg-save-crash 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-reorg-save-crash all assertions"; then
  echo ""
  echo "  PASS: chain-reorg-save-crash unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-reorg-save-crash had assertion failures"
  exit 1
fi
