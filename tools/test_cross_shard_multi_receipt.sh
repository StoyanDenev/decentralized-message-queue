#!/usr/bin/env bash
# S-035 Option 1 seed — mixed cross-shard inbound + outbound in a single
# block, multi-receipt edge cases, and dedup across BLOCKS.
#
# The single-direction tests already cover:
#   - test-cross-shard-receipt-apply: inbound-only (credit + dedup +
#     accumulated_inbound + predicate)
#   - test-cross-shard-outbound-apply: outbound-only (debit, fee return,
#     accumulated_outbound, single-shard fallback)
#
# This test fills the gap where BOTH directions move simultaneously:
#   - Mixed inbound + outbound in same block — both A1 counters advance,
#     invariant holds
#   - Two receipts to SAME destination in one block — cumulative credit
#   - Two receipts to DISTINCT destinations in one block — independent
#   - Dedup across BLOCKS in presence of additional mixed-direction
#     traffic (verifies dedup-set isolation from other counters)
#   - A1 invariant held at H=1 (inbound-only), H=2 (outbound-only),
#     H=3 (mixed multi-receipt + outbound)
#   - Determinism: parallel chains apply same sequence → same root
#
# 19 assertions across six scenarios.
#
# Run from repo root: bash tools/test_cross_shard_multi_receipt.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== cross-shard mixed inbound+outbound + multi-receipt + dedup ==="
OUT=$($DETERM test-cross-shard-multi-receipt 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: cross-shard-multi-receipt all assertions"; then
  echo ""
  echo "  PASS: cross-shard-multi-receipt unit test"
  exit 0
else
  echo ""
  echo "  FAIL: cross-shard-multi-receipt had assertion failures"
  exit 1
fi
