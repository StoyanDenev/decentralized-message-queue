#!/usr/bin/env bash
# v2.1 / S-035 Option 1 seed — in-process unit test for the
# committee-selection primitives.
#
# Runs `determ test-committee-selection` which exercises:
#   - crypto::select_m_creators (S-020 hybrid: rejection sampling
#     when 2K ≤ N, partial Fisher-Yates shuffle when 2K > N)
#   - crypto::select_after_abort_m (deterministic abort-shifted
#     re-selection — abort_hash-driven index rotation)
#   - crypto::epoch_committee_seed (shard-salted per-epoch seed)
#
# These are the foundation of FA1 (safety), FA2 (censorship), FA5
# (BFT safety), and FA8 (regional sharding) — every committee at
# every round is derived through these functions, so a regression
# in any of them would have cascading consequences across the
# protocol's safety claims.
#
# Assertions covered (13 total):
#   1. Determinism: same (rand, N, K) → same indices.
#   2. Seed-sensitivity: different seed → different indices.
#   3. Without-replacement: K distinct indices.
#   4. In-range: all indices in [0, N).
#   5. Rejection-sampling branch exercised (2K ≤ N: K=3, N=20).
#   6. Partial-Fisher-Yates branch exercised (2K > N: K=8, N=10).
#   7. Edge case K=N: returns every index 0..N-1.
#   8. Edge case K=1: returns one in-range index.
#   9-11. select_after_abort_m determinism + size + distinctness.
#   12-13. epoch_committee_seed determinism + shard-salt sensitivity.
#
# Run from repo root: bash tools/test_committee_selection.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.1 committee-selection primitives ==="
OUT=$($DETERM test-committee-selection 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: committee-selection all assertions"; then
  echo ""
  echo "  PASS: v2.1 committee-selection unit test"
  exit 0
else
  echo ""
  echo "  FAIL: committee-selection had assertion failures"
  exit 1
fi
