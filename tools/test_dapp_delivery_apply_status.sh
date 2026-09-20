#!/usr/bin/env bash
# S-063 / D18a — DApp delivery layer apply reporting and value gating regression test.
#
# Asserts:
#   1. make_dapp_call_frame emits "status": "APPLIED" and includes "amount"
#      and "fee" iff applied == true; emits "status": "SKIPPED" and OMITS
#      "amount" and "fee" iff applied == false.
#   2. Chain::is_tx_applied tracks exact apply success/failure per tx across
#      underfunded, funded, and depth-1 reorg (revert_head) scenarios.
#   3. Node::rpc_dapp_messages delivers "status": "APPLIED" (with amount/fee)
#      for funded txs, and "status": "SKIPPED" (without amount/fee) for underfunded txs.
#
# Run from repo root: bash tools/test_dapp_delivery_apply_status.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh

echo "=== S-063 DApp delivery apply status / value gating ==="
OUT=$($DETERM test-dapp-delivery-apply-status 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp-delivery-apply-status all assertions"; then
  echo ""
  echo "  PASS: S-063 DApp delivery apply reporting / value gating"
  exit 0
else
  echo ""
  echo "  FAIL: dapp-delivery-apply-status had assertion failures"
  exit 1
fi
