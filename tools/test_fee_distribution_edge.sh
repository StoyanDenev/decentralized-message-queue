#!/usr/bin/env bash
# S-035 Option 1 seed — fee + subsidy distribution edge cases.
# Tests boundary conditions beyond test-subsidy-distribution:
#   - many creators with prime dust (subsidy 100 / 3 creators)
#   - large fee + subsidy combine into single distribution pool
#   - zero-fee, zero-subsidy: no-op (no creator credit)
#   - zero-fee tx with non-zero subsidy: subsidy still mints
#   - exact-divide subsidy (no dust)
#   - subsidy < creator count: each gets 0 + dust to creator[0]
#   - A1 invariant across all distribution scenarios
#
# Critical: creators are sorted alphabetically in make_genesis_block,
# so creator[0] (the dust recipient) is deterministic across nodes.
# This test confirms that contract.
#
# Note: `b.creators` in the test fixtures is set explicitly to
# {"alice", "bob", "carol"} (3 creators) since these tests focus on
# the distribution math regardless of committee selection.
#
# 12 assertions across seven scenarios.
#
# Run from repo root: bash tools/test_fee_distribution_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== fee + subsidy distribution edge cases (dust, divisibility, A1) ==="
OUT=$($DETERM test-fee-distribution-edge 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fee-distribution-edge all assertions"; then
  echo ""
  echo "  PASS: fee-distribution-edge unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fee-distribution-edge had assertion failures"
  exit 1
fi
