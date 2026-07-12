#!/usr/bin/env bash
# D3.3a (ShardTipMergeDesign.md §9): the `cc:` epoch committee-checkpoint ring —
# the circularity-breaker substrate for the S-036 closure (a frozen eligible set
# per epoch so a past shard committee is reconstructible with ZERO history replay).
# State-root binding + bounded ring + snapshot inheritance + empty-set
# byte-neutrality. Populated only in EXTENDED mode (D3.3b); here the container is
# driven directly.
#
# Asserts (in-process, no cluster — FAST-eligible):
#   1. empty ring ⇒ zero cc: leaves ⇒ two fresh chains share a state_root
#      (the non-EXTENDED byte-neutrality invariant);
#   2. a cc: checkpoint changes state_root (bound, not inert);
#   3. member-order-independent (add_committee_checkpoint canonicalizes to
#      domain-sorted → deterministic leaf hash);
#   4. bounded ring — only the most recent kCommitteeCheckpointRing epochs survive;
#   5. snapshot round-trip — a restored chain inherits the ring (epoch_rand +
#      members exact) + reproduces the same state_root;
#   6. an empty ring is omitted from serialize_state.
#
# Run from repo root: bash tools/test_committee_checkpoint.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== committee-checkpoint: cc: epoch committee-checkpoint ring (D3.3a) ==="
OUT=$($DETERM test-committee-checkpoint 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: committee-checkpoint all assertions"; then
  echo ""
  echo "  PASS: committee-checkpoint unit test"
  exit 0
else
  echo ""
  echo "  FAIL: committee-checkpoint had assertion failures"
  exit 1
fi
