#!/usr/bin/env bash
# S-035 Option 1 seed — cross-shard atomicity at the chain-pair level.
#
# test-cross-shard-outbound-apply covers source-side debit on a single
# Chain; test-cross-shard-receipt-apply covers destination-side credit
# on a single Chain. This test verifies they COMPOSE at the cross-shard
# atomicity contract by modeling BOTH sides simultaneously:
#
#   - Source shard S0: TRANSFER to address routed to S1 →
#     S0.accumulated_outbound += amount
#   - Destination shard S1: inbound receipt credits that address →
#     S1.accumulated_inbound += amount
#   - Cross-shard A1 atomicity: src.accumulated_outbound ==
#     dst.accumulated_inbound (the cross-pair conservation)
#   - Per-shard A1 invariant on each chain (each shard's expected ==
#     live)
#   - Net supply across the pair conserved (src loses what dst gains)
#   - Determinism (replay produces same state_roots)
#
# Defends against drift where the two sides' counters could move by
# different amounts (silent value loss or creation across the shard
# boundary — the catastrophic cross-shard failure mode).
#
# 10 assertions across the dual-chain flow.
#
# Run from repo root: bash tools/test_cross_shard_atomicity.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== cross-shard atomicity — chain-pair model with A1 conservation across S0+S1 ==="
OUT=$($DETERM test-cross-shard-atomicity 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: cross-shard-atomicity all assertions"; then
  echo ""
  echo "  PASS: cross-shard-atomicity unit test"
  exit 0
else
  echo ""
  echo "  FAIL: cross-shard-atomicity had assertion failures"
  exit 1
fi
