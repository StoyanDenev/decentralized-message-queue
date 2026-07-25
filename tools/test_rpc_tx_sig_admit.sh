#!/usr/bin/env bash
# RpcIngressGateAudit §3 MEM-tx-sig-admit — the mempool signature-admission gate.
#
# verify_tx_signature_locked runs in production on BOTH ingress paths —
# rpc_submit_tx (node.cpp:4453, hard throw) and on_tx (gossip, node.cpp:2819,
# silent drop) — but no negative test pinned either. This is the ingress analog
# of the closed VAL-tx-sender-sig:685 (block-validator path); removing it lets
# any peer / RPC client inject forged-sender txs into shared mempool (production
# stall + cap exhaustion).
#
# In-process Node harness (mirrors test-scheduler-external): a single M=K=1 node
# "node0", genesis-registered + funded, on a fresh node per leg. Covered:
#   - CONTROL: a validly-signed tx is ADMITTED (queued, mempool == 1)
#   - RPC ingress: a forged-sender tx is REJECTED (throws) — not admitted
#   - gossip ingress: a forged-sender tx is SILENTLY DROPPED by on_tx
# Each ingress call site falsifies INDEPENDENTLY (see the register).
#
# Run from repo root: bash tools/test_rpc_tx_sig_admit.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== MEM-tx-sig-admit — mempool signature-admission on both ingress paths ==="
OUT=$($DETERM test-rpc-tx-sig-admit 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-rpc-tx-sig-admit"; then
  echo ""
  echo "  PASS: rpc-tx-sig-admit unit test"
  exit 0
else
  echo ""
  echo "  FAIL: rpc-tx-sig-admit had assertion failures"
  exit 1
fi
