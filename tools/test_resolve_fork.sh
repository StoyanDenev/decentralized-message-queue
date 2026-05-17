#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Chain::resolve_fork
# (S-029 closure: fork-choice rule for the BFT-mode fast-finalize path).
#
# When two K-of-K-signed blocks are observed at the same height (only
# possible in BFT mode where the gather-quorum is ceil(2K/3) rather
# than K, so signature subsets can differ), resolve_fork picks the
# canonical tip deterministically. The rule:
#
#   1. Heaviest sig set wins (max non-zero creator_block_sigs)
#   2. Tie → fewer abort_events wins
#   3. Tie → smallest block_hash (deterministic across peers)
#
# A regression would either:
#   * silently let the wrong block win (safety violation: peers
#     diverge on canonical tip), OR
#   * make resolution non-deterministic across nodes (peers pick
#     different winners → fork)
# Both break FA1.
#
# 10 assertions covering:
#
#   Sig-count branch (2): heavier sigs wins (3 > 2);
#     arg order doesn't matter (symmetric).
#
#   Abort-count tie-break (2): same sigs → fewer aborts wins;
#     symmetric on arg order.
#
#   Hash tie-break (2): tied sigs + aborts → smallest block_hash
#     wins (lexicographic); tie-break is symmetric across arg
#     order.
#
#   Edge cases (4):
#     - Identical blocks → returns first arg (deterministic)
#     - Zero-sigs on both → still resolves without crash
#     - Sentinel-zero sigs (BFT mode) don't count toward weight
#     - Abort tie-break beats hash tie-break (priority order)
#
# Run from repo root: bash tools/test_resolve_fork.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::resolve_fork — S-029 BFT-mode fork-choice rule ==="
OUT=$($DETERM test-resolve-fork 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: resolve-fork all assertions"; then
  echo ""
  echo "  PASS: resolve-fork unit test"
  exit 0
else
  echo ""
  echo "  FAIL: resolve-fork had assertion failures"
  exit 1
fi
