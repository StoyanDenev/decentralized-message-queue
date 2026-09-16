#!/usr/bin/env bash
# S-035 Option 1 seed — multi-event-type composition in a single block.
#
# Each event type has isolated apply tests:
#   - test-chain-apply-block: TRANSFER / STAKE / UNSTAKE / DEREGISTER
#   - test-abort-event-apply: AbortEvent → suspension record, no stake (D13)
#   - test-equivocation-apply: EquivocationEvent → evidence record, no state (D4)
#   - test-subsidy-distribution: per-creator subsidy mint
#   - test-cross-shard-receipt-apply / outbound-apply: receipts
#   - test-merge-event-apply: MERGE_BEGIN/END
#
# This test exercises the COMPOSITION — a single block carrying
#   - TRANSFER tx (balance shift)
#   - AbortEvent (Phase-1: a suspension RECORD; moves no stake — D13 2026-09-16)
#   - EquivocationEvent (an evidence record; moves nothing — D4 2026-09-16)
#   - subsidy mint (per non-empty creators set)
#   - inbound receipt (cross-shard credit)
# applied simultaneously, and verifies that:
#   - each effect lands independently
#   - A1 invariant holds across the whole composition
#   - live supply moves by the expected delta (subsidy + inbound -
#     slashed - any outbound)
#   - disjoint-actor events compose identically across chains
#   - same-actor abort + equivocation stack correctly (drain stake to 0)
#
# Pins the "events compose correctly" property — a regression in
# apply ordering or shared-state mutation would manifest here.
#
# 17 assertions across 3 scenarios.
#
# Run from repo root: bash tools/test_block_event_composition.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== block event composition — TRANSFER + abort + equiv + subsidy + receipt all together ==="
OUT=$($DETERM test-block-event-composition 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-event-composition all assertions"; then
  echo ""
  echo "  PASS: block-event-composition unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-event-composition had assertion failures"
  exit 1
fi
