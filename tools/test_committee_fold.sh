#!/usr/bin/env bash
# D3.3b (ShardTipMergeDesign.md §9.3): the EXTENDED-only epoch-rotation committee
# fold-in inside Chain::apply_transactions (Site A). Where D3.3a drives the `cc:`
# container directly, this proves the FOLD itself — the chain-layer step that
# populates the ring at each epoch boundary on an EXTENDED chain.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. the fold fires exactly at the boundary block (index = E*epoch_blocks-1),
#      freezing epoch E — not before;
#   2. it freezes the correct eligible pool (domain-sorted) + the boundary
#      block's cumulative_rand as epoch_rand;
#   3. SINGLE (shard_count==1) never folds — the byte-neutral gate;
#   4. epoch_blocks==0 disables the fold even on EXTENDED;
#   5. the frozen cc: leaf binds into state_root AND a Chain::load replay
#      re-folds it identically (no S-033 divergence on EXTENDED reload);
#   6. A4 revert_head across the boundary rolls the checkpoint back (the H-1
#      __ensure_committee_checkpoints lambda) and a re-append re-folds the
#      identical checkpoint + state_root (reorg idempotence).
#
# Run from repo root: bash tools/test_committee_fold.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== committee-fold: EXTENDED epoch-rotation fold-in (D3.3b) ==="
OUT=$($DETERM test-committee-fold 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: committee-fold all assertions"; then
  echo ""
  echo "  PASS: committee-fold unit test"
  exit 0
else
  echo ""
  echo "  FAIL: committee-fold had assertion failures"
  exit 1
fi
