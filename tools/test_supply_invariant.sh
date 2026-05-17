#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Chain's A1
# (unitary supply) read API + the expected_total formula.
#
# A1 invariant requires:
#
#   live_total_supply() == expected_total()
#
# where expected_total =
#   genesis_total
#   + accumulated_subsidy
#   + accumulated_inbound
#   - accumulated_slashed
#   - accumulated_outbound
#
# This invariant is checked post-apply on every block (the
# in-loop assertion). This unit test locks the read-side API
# behavior on a default Chain (all counters zero, supply zero,
# invariant trivially holds) and the formula's arithmetic shape
# — defending against a future regression that flips a sign or
# reorders fields.
#
# Apply-path tests (where counters mutate through real txs) are
# exercised by the network-level tools/test_a1_unitary_*.sh
# integration tests; this unit test pins the read-side contract
# in <1s without spinning up a chain.
#
# 16 assertions:
#
#   Default Chain zero state (5):
#     - genesis_total / accumulated_subsidy / _slashed / _inbound /
#       _outbound all 0
#
#   Formula on zero state (2):
#     - expected_total = 0
#     - 0 + 0 + 0 - 0 - 0 = 0 (formula shape)
#
#   Live supply default (1):
#     - live_total_supply == 0 on default Chain (empty accounts +
#       stakes)
#
#   A1 invariant holds trivially (1):
#     - expected_total == live_total_supply on default Chain
#
#   Determinism (2):
#     - expected_total + live_total_supply both pure functions
#       of Chain state (no global state, no timing)
#
#   Setter independence (5):
#     - set_block_subsidy doesn't populate accounts (live still 0)
#     - set_block_subsidy doesn't tick accumulated_subsidy
#     - set_subsidy_pool_initial doesn't auto-tick counters
#     - set_subsidy_pool_initial doesn't increment
#       accumulated_subsidy
#     - expected_total unchanged by tunable-config setters
#       (min_stake / suspension_slash / unstake_delay /
#       merge_threshold_blocks) — formula depends only on the 5
#       named counters
#
# Run from repo root: bash tools/test_supply_invariant.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A1 unitary supply invariant — Chain read API + expected_total formula ==="
OUT=$($DETERM test-supply-invariant 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: supply-invariant all assertions"; then
  echo ""
  echo "  PASS: supply-invariant unit test"
  exit 0
else
  echo ""
  echo "  FAIL: supply-invariant had assertion failures"
  exit 1
fi
