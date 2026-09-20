#!/usr/bin/env bash
# S-097 (finding F-2; docs/SECURITY.md) — BlockValidator pre-check in rpc_submit_tx.
#
# Definitively rejects structurally invalid transactions at RPC ingress (oversized
# payload, unauthorized anonymous type, malformed stake payload) rather than
# acknowledging `queued` and silently evicting them later during block assembly.
#
# In-process Node harness:
#   - CONTROL 1: validly-signed TRANSFER is ADMITTED (status: queued, mempool == 1)
#   - CONTROL 2: future-nonce TRANSFER is ADMITTED (status: queued, mempool == 2)
#   - NEGATIVE 1: oversized TRANSFER payload (> 128 bytes) is REJECTED at RPC ingress
#   - NEGATIVE 2: anonymous STAKE tx is REJECTED at RPC ingress
#   - NEGATIVE 3: STAKE with malformed payload size is REJECTED at RPC ingress
#
# Run from repo root: bash tools/test_rpc_validator_precheck.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-097: rpc_submit_tx BlockValidator precheck ==="
OUT=$($DETERM test-rpc-validator-precheck 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-rpc-validator-precheck"; then
  echo ""
  echo "  PASS: test-rpc-validator-precheck unit test"
  exit 0
else
  echo ""
  echo "  FAIL: test-rpc-validator-precheck had assertion failures"
  exit 1
fi
