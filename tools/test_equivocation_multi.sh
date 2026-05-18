#!/usr/bin/env bash
# S-035 Option 1 seed — multi-equivocation edge cases beyond
# test-equivocation-apply.
#
# Covers:
#   - Two distinct equivocators in same block (both forfeit, both
#     deregistered; A1 counts each forfeit)
#   - Same equivocator twice in same block (first forfeits stake;
#     second no-op on stake — stake already 0; accumulated_slashed
#     only counts the first forfeit)
#   - Equivocator with NO stake (DOMAIN_INCLUSION mode or post-UNSTAKE):
#     no forfeit possible, but registry IS deactivated (the
#     deregistration mechanism, not the stake mechanism, removes them)
#   - Pre-deactivated equivocator: inactive_from OVERRIDDEN to
#     b.index+1 (more recent override wins, prevents re-registration
#     during grace window via attack)
#   - Determinism: two chains see same multi-equivocation → same root
#
# ~14 assertions across five scenarios.
#
# Run from repo root: bash tools/test_equivocation_multi.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== multi-equivocation edge cases (dual mechanism: forfeit + deregister) ==="
OUT=$($DETERM test-equivocation-multi 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: equivocation-multi all assertions"; then
  echo ""
  echo "  PASS: equivocation-multi unit test"
  exit 0
else
  echo ""
  echo "  FAIL: equivocation-multi had assertion failures"
  exit 1
fi
