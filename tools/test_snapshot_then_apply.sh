#!/usr/bin/env bash
# S-035 Option 1 seed — snapshot+restore chain remains OPERATIONAL.
# Post-restore appends produce identical state to a fresh full replay
# from genesis.
#
# This is the property snapshot/replay equivalence rests on beyond
# the round-trip semantics covered by test-snapshot-roundtrip (which
# only checks the read-side state post-restore, NOT that further
# apply works correctly).
#
# Strategy:
#   - Chain A (control): fresh genesis → 5 blocks with mixed txs
#   - Chain B (target):  fresh genesis → 3 blocks (same as A's 1..3)
#                      → serialize_state → restore_from_snapshot
#                      → apply A's blocks 4 + 5
#   - Assert A.state_root == B.state_root at every height post-restore
#   - Assert A.balance == B.balance for every account
#   - Assert A.next_nonce == B.next_nonce
#   - Assert A.accumulated_subsidy == B.accumulated_subsidy
#   - Assert A1 invariant on B throughout
#
# 21 assertions across the restore-apply boundary.
#
# Run from repo root: bash tools/test_snapshot_then_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== snapshot-then-apply (restore + apply == fresh full replay) ==="
OUT=$($DETERM test-snapshot-then-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-then-apply all assertions"; then
  echo ""
  echo "  PASS: snapshot-then-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-then-apply had assertion failures"
  exit 1
fi
