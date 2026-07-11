#!/usr/bin/env bash
# A4 / S-048 increment 1 (BoundedReorgDesign.md A4.1): the Chain depth-1
# head-reorg PRIMITIVE, Chain::revert_head().
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. revert_head() restores the EXACT pre-head state (height, head_hash,
#      balances, nonce, stake all byte-identical to before the head applied);
#   2. depth-1 bound — a second revert with no intervening apply is refused;
#   3. after a revert, a DIFFERENT block applies cleanly at the head height
#      (the reorg-replacement path);
#   4. genesis is the finality floor — revert_head at height 1 is refused;
#   5. has_revertible_head() tracks the retained snapshot.
#
# Run from repo root: bash tools/test_chain_revert_head.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== chain-revert-head: depth-1 revert primitive (A4.1) ==="
OUT=$($DETERM test-chain-revert-head 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-revert-head all assertions"; then
  echo ""
  echo "  PASS: chain-revert-head unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-revert-head had assertion failures"
  exit 1
fi
