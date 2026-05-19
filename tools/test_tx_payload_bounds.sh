#!/usr/bin/env bash
# S-035 Option 1 seed — per-tx-type payload-size apply gates.
#
# Each tx type has its own payload-shape contract; the validator
# enforces these at admission, but the apply path also defensively
# checks them as a "silent skip" safety net for txs that slip through.
# This test pins the boundary behavior on the apply side:
#
#   - REGISTER:
#     - payload < 32 bytes → silent skip (no nonce bump, no registrant)
#     - payload == 32 bytes → accepted (legacy/no-region form)
#     - payload > 32 bytes with mismatched region_len header → skip
#     - payload > 32 bytes with matched region_len → accepted, region set
#   - STAKE / UNSTAKE:
#     - payload.size() != 8 → silent skip (no fee charge, no nonce bump)
#     - payload.size() == 8 → accepted, amount decoded LE
#   - TRANSFER:
#     - empty payload → accepted (payload is OPTIONAL per A4 memo design)
#   - A1 invariant under all skip paths
#   - Determinism: same malformed payload → same state_root
#
# Defends against payload-format regressions that could either crash
# the apply path or silently corrupt state.
#
# 16 assertions across 11 scenarios.
#
# Run from repo root: bash tools/test_tx_payload_bounds.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== per-tx-type payload bounds — REGISTER < 32 skip, STAKE/UNSTAKE != 8 skip, boundary cases ==="
OUT=$($DETERM test-tx-payload-bounds 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: tx-payload-bounds all assertions"; then
  echo ""
  echo "  PASS: tx-payload-bounds unit test"
  exit 0
else
  echo ""
  echo "  FAIL: tx-payload-bounds had assertion failures"
  exit 1
fi
