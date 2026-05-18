#!/usr/bin/env bash
# S-035 Option 1 seed — TRANSFER corner cases not covered by the
# happy-path tests test-chain-apply-block / test-multi-tx-block.
#
# Covers:
#   - Self-transfer (alice → alice) — apply-order semantics where
#     sender.balance -= cost then accounts_[to=alice].balance += amount
#     net out to -fee, with fee returning via creator → 0 net
#   - Zero amount + zero fee — pure no-op except nonce++
#   - Zero amount + non-zero fee — fee paid + returned via creator → 0 net
#   - Missing sender (operator[] creates 0-balance entry; cost > balance
#     → silent skip, NO nonce bump — defends against forged tx attacks)
#   - Insufficient balance (amount > balance, fee = 0)
#   - Edge case: balance covers fee alone but not amount + fee (single-
#     check semantics — no partial debit)
#   - Boundary: balance == amount + fee exactly → SUCCEEDS (strict `<`)
#   - Determinism across edge-case mix
#
# 28 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_tx_edge_cases.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== TRANSFER corner cases — self / zero / missing-sender / boundary ==="
OUT=$($DETERM test-tx-edge-cases 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-edge-cases all assertions"; then
  echo ""
  echo "  PASS: tx-edge-cases unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-edge-cases had assertion failures"
  exit 1
fi
