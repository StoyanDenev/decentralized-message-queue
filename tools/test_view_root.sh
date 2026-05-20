#!/usr/bin/env bash
# v2.7 F2 foundation regression — compute_view_root + reconcile_union +
# reconcile_intersection (per docs/proofs/F2-SPEC.md §Q1).
#
# Three primitives the consensus-layer F2 closure of S-030 D2 needs:
#   1. compute_view_root — Phase-1 commit binding (member can't equivocate
#      on their view between commit and reveal). Same Merkle-over-sorted-
#      set structure as compute_tx_root.
#   2. reconcile_union — canonical-list builder for equivocation_events +
#      abort_events. Censorship-resistance: one observer suffices.
#   3. reconcile_intersection — canonical-list builder for inbound_receipts.
#      Conservative-credit: one missing observation suppresses the credit.
#
# Defends against drift in the foundation primitives that the upcoming
# v2.7 F2 producer + validator implementations will build on. Without
# these primitives working byte-for-byte the same on every node, the
# reconciled canonical lists diverge across nodes → safety break.
#
# 22 assertions across 17 scenarios.
#
# Run from repo root: bash tools/test_view_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.7 F2 foundation: compute_view_root + reconcile_union + reconcile_intersection ==="
OUT=$($DETERM test-view-root 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: view-root all assertions"; then
  echo ""
  echo "  PASS: view-root unit test"
  exit 0
else
  echo ""
  echo "  FAIL: view-root had assertion failures"
  exit 1
fi
