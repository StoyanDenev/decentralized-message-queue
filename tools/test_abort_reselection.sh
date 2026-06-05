#!/usr/bin/env bash
# v2.1 / S-035 Option 1 seed — in-process unit test for the post-abort
# committee re-selection contract.
#
# Runs `determ test-abort-reselection` which exercises
# crypto::select_after_abort_m — the fallback committee re-selection
# invoked on every abort / BFT-escalation retry. test-committee-selection
# already pins the happy-path determinism/size/distinctness on one
# fixture; this fills in the safety-critical CONTRACT:
#
#   - Pinned-first-index: result[0] == (indices[0] + offset) % N where
#     offset = hash_mod(abort_hash, N) — the S5 anti-cartel-navigation
#     defense (the lead proposer is shifted by a deterministic,
#     abort-hash-derived amount so a cartel cannot pre-plan the
#     post-abort committee). Verified on BOTH the rejection branch
#     (2K ≤ N) and the partial Fisher-Yates branch (2K > N).
#   - abort_hash sensitivity: a different abort hash rotates the
#     committee; the same abort hash re-selects identically.
#   - In-range + distinct invariants across both branches and the
#     K=N full-committee edge case.
#   - Chained-fallback sequence: a run of aborts folded through
#     chain_abort_hash drives successive re-selections — each
#     deterministic / distinct / in-range, the whole sequence
#     reproducible across replays.
#
# These underpin FA5 (BFT safety) and the S5 anti-cartel-navigation
# claim: a regression would either fork the post-abort committee across
# nodes (safety failure) or make the fallback sequence predictable.
#
# Assertions covered (11 total):
#   1-2. Pinned-first-index on rejection + partial-FY branches.
#   3-4. abort_hash sensitivity + purity.
#   5-7. In-range + distinct on both branches + K=N edge case.
#   8.   Committee-size preservation across K in {1,2,3,7}.
#   9-11. Chained-fallback sequence: distinct/in-range, advancing,
#         reproducible.
#
# Run from repo root: bash tools/test_abort_reselection.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.1 post-abort committee re-selection contract ==="
OUT=$($DETERM test-abort-reselection 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: abort-reselection all assertions"; then
  echo ""
  echo "  PASS: v2.1 abort-reselection unit test"
  exit 0
else
  echo ""
  echo "  FAIL: abort-reselection had assertion failures"
  exit 1
fi
