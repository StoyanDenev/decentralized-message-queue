#!/usr/bin/env bash
# S-035 Option 1 seed — comprehensive stake-state-machine invariants.
# STAKE / UNSTAKE / DEREGISTER / slash interact non-trivially around
# the `unlock_height` sentinel (UINT64_MAX = never unlockable) +
# `locked` balance. This test exercises the full state machine in a
# structured way that the per-tx-apply tests don't compose:
#
#   Genesis:       locked = initial_stake,   unlock_height = UINT64_MAX
#   STAKE:         locked += amount,         unlock_height unchanged
#   slash:         locked -= SUSPENSION_SLASH (bounded), unlock unchanged
#   DEREGISTER:    locked unchanged,         unlock_height = inactive_from + unstake_delay
#   UNSTAKE pre:   locked unchanged,         balance unchanged (fee refunded)
#   UNSTAKE post:  locked -= amount,         balance += amount
#
# 12 assertions across seven scenarios cover the full lifecycle plus
# A1 conservation (STAKE moves value but doesn't change total supply;
# the full STAKE → UNSTAKE round-trip conserves supply).
#
# Run from repo root: bash tools/test_stake_accounting.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== stake state-machine invariants (STAKE/UNSTAKE/DEREGISTER/slash interaction) ==="
OUT=$($DETERM test-stake-accounting 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: stake-accounting all assertions"; then
  echo ""
  echo "  PASS: stake-accounting unit test"
  exit 0
else
  echo ""
  echo "  FAIL: stake-accounting had assertion failures"
  exit 1
fi
