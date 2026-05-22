#!/usr/bin/env bash
# S-035 Option 1 seed — BlockValidator V1..V20 gate-by-gate reject-path
# coverage. Widens test-block-validator-basic with explicit assertions
# per numbered gate (V1 prev_hash, V2 creators_registered, V3 creator_
# selection size + off-committee, V4 creator_tx_commitments size/sig,
# V13 inbound_receipts on SINGLE chain, V14 timestamp ±30s window,
# BFT-mode without bft_enabled). Pins V0 genesis short-circuit +
# negative determinism over identical reject-path inputs.
#
# Reference: src/node/validator.cpp BlockValidator::validate gate
# sequence; src/main.cpp cmd_test_block_validator_extensive handler.
#
# Run from repo root: bash tools/test_block_validator_extensive.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== BlockValidator V1..V20 gate-by-gate reject-path coverage ==="
OUT=$($DETERM test-block-validator-extensive 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-validator-extensive all assertions"; then
  echo ""
  echo "  PASS: test_block_validator_extensive"
  exit 0
else
  echo ""
  echo "  FAIL: block-validator-extensive had assertion failures"
  exit 1
fi
