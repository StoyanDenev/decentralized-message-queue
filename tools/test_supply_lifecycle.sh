#!/usr/bin/env bash
# S-035 Option 1 seed — end-to-end A1 unitary-supply invariant test
# across a mixed-tx lifecycle. The per-tx-type apply tests
# (chain-apply-block, abort-event-apply, equivocation-apply,
# unstake-deregister-apply, subsidy-distribution, cross-shard-*) each
# verify the invariant after a single operation type. This test
# exercises a realistic interleaving:
#
#   genesis (initial supply 1700) →
#   block 1: empty + subsidy 50 mint (live = 1750) →
#   block 2: intra-shard TRANSFER 100/fee=1 + subsidy 50
#            (live = 1800; TRANSFER value-conserving + 50 mint) →
#   block 3: STAKE 50 + subsidy 50
#            (value moves balance ↔ stake; subsidy +50) →
#   block 4: Phase-1 AbortEvent (alice) + subsidy 50
#            (slash -SUSPENSION_SLASH, mint +50) →
#   block 5: DEREGISTER (sets unlock_height = height + delay) →
#   block N..: empty blocks advancing past unlock_height →
#   block X: UNSTAKE 200 (stake → balance, no net change).
#
# The A1 invariant `expected_total == live_total_supply` must hold
# after EVERY apply commit. The five counters
# (genesis_total, accumulated_subsidy, accumulated_inbound,
#  accumulated_slashed, accumulated_outbound) account for every
# entry/exit of value to/from this shard's supply.
#
# Mathematical identity verified at end:
#   genesis_total + accumulated_subsidy + accumulated_inbound
#   - accumulated_slashed - accumulated_outbound == live_total_supply
#
# 11 assertions covering: baseline, post-subsidy, post-TRANSFER,
# post-STAKE, post-slash, post-DEREGISTER, post-advance-loop,
# post-UNSTAKE, final invariant + 3 counter-state assertions, + the
# A1 identity formula.
#
# Run from repo root: bash tools/test_supply_lifecycle.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A1 unitary-supply invariant — end-to-end mixed-tx lifecycle ==="
OUT=$($DETERM test-supply-lifecycle 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: supply-lifecycle all assertions"; then
  echo ""
  echo "  PASS: supply-lifecycle unit test"
  exit 0
else
  echo ""
  echo "  FAIL: supply-lifecycle had assertion failures"
  exit 1
fi
