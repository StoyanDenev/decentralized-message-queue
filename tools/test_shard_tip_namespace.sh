#!/usr/bin/env bash
# D3.2 (ShardTipMergeDesign.md §9): the `t:` on-chain SHARD_TIP distress-record
# ring — state-root binding + bounded ring + snapshot round-trip (the snapshot
# inheritance the S-036 closure depends on), and the empty-set byte-neutrality
# that keeps a non-EXTENDED / healthy chain's state_root unchanged.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. empty ring ⇒ zero t: leaves ⇒ two fresh chains share a state_root
#      (the non-EXTENDED byte-neutrality invariant);
#   2. a t: record actually changes state_root (bound, not inert);
#   3. determinism — identical record sets inserted in different orders give
#      the identical state_root;
#   4. bounded ring — per source shard, only the last revert_threshold_blocks
#      records survive; the lowest heights are pruned; other shards untouched;
#   5. snapshot round-trip — a restored (snapshot-bootstrapped) chain inherits
#      the t: ring exactly + reproduces the same state_root;
#   6. an empty ring is omitted from serialize_state (no snapshot bloat).
#
# Run from repo root: bash tools/test_shard_tip_namespace.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== shard-tip-namespace: t: state ring + snapshot inheritance (D3.2) ==="
OUT=$($DETERM test-shard-tip-namespace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: shard-tip-namespace all assertions"; then
  echo ""
  echo "  PASS: shard-tip-namespace unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shard-tip-namespace had assertion failures"
  exit 1
fi
