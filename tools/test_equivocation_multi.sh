#!/usr/bin/env bash
# Multi-equivocation edge cases beyond test-equivocation-apply, under the
# 2026-09-16 rule (DECISION-LOG D4): an EquivocationEvent moves NO L1 state.
#
# Covers:
#   - Two distinct equivocators in the same block (neither stake nor
#     registry entry moves; accumulated_slashed stays 0)
#   - Same equivocator twice in the same block (two records; nothing moves)
#   - Equivocator with NO stake, at a ZERO stake floor (registry entry NOT
#     deactivated; a consequence keyed on min_stake == 0 — mutant M8 — goes RED)
#   - Equivocator inside its DEREGISTER unlock window: the DEREGISTER's
#     inactive_from is NOT overridden and the pending-unlock stake is NOT
#     touched — the inverted "anti-dodge" scenario; mutant M6 (a consequence
#     that fires only inside the window) goes RED here and nowhere else
#   - Determinism: two chains see the same multi-equivocation → same root
#
# ~16 assertions across five scenarios.
#
# Run from repo root: bash tools/test_equivocation_multi.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== multi-equivocation edge cases (D4: evidence records move no L1 state) ==="
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
