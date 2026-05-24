#!/usr/bin/env bash
# S-035 Option 1: per-tx fee handling at the apply layer. Companion to
# test-fee-distribution-edge, which exercises the per-creator split
# side (dust, divisibility, A1 over distribution). THIS test exercises
# the per-tx FEE INPUT side — the shape that feeds the fee pool:
#   - Scenario 1: Zero-fee TRANSFER (fee=0 is legal; no creator credit
#     beyond subsidy)
#   - Scenario 2: Maximum fee within balance (drains sender to 1 unit;
#     entire fee_pool flows to sole creator)
#   - Scenario 3: Fee + amount > balance → rejected at cost gate
#     (chain.cpp:744)
#   - Scenario 4: Fee == balance, amount=0 → boundary admit
#     (cost == balance is NOT strictly greater)
#   - Scenario 5a: fee = UINT64_MAX, small amount → natural reject
#     (cost overflows beyond balance without wrap)
#   - Scenario 5b: cost wraps to 0 via UINT64_MAX-1 fee → applies
#     debit-by-zero, then S-007 overflow at per-creator distribution
#     → append THROWS + A9 atomic-apply rollback restores state
#   - Scenario 6: 3 TRANSFER txs fee=10 each + 3 creators → exact
#     divide 30/3 = 10 per creator (no dust)
#   - Scenario 7: Empty block + non-zero subsidy → fee_pool=0 doesn't
#     suppress the distribution branch; subsidy alone flows to
#     creators; accumulated_subsidy unchanged by absent fee_pool
#
# 19 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_fee_edge_cases.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== fee edge cases (zero-fee, max-fee, fee>balance, overflow, distribution) ==="
OUT=$($DETERM test-fee-edge-cases 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fee-edge-cases all assertions"; then
  echo ""
  echo "  PASS: fee-edge-cases unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fee-edge-cases had assertion failures"
  exit 1
fi
