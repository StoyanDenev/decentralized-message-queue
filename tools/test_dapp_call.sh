#!/usr/bin/env bash
# v2.19 Theme 7 Phase 7.2 — DAPP_CALL apply-path regression test.
#
# Exercises the DApp message-delivery semantics:
#   1. Successful DAPP_CALL with payment: alice → dappowner with
#      amount=5, topic="chat". Verifies debit/credit + nonce.
#   2. DAPP_CALL with amount=0: pure message, no transfer.
#   3. DAPP_CALL to nonexistent DApp: apply silently no-ops
#      (defensive; validator would have rejected first).
#   4. DAPP_CALL with unregistered topic: no-op rollback.
#   5. DAPP_CALL with empty topic: allowed, applies normally.
#   6. DAPP_CALL during DApp's deactivation grace period: still
#      applies (DApp can wind down without instant cutoff).
#
# In-process via `unchained test-dapp-call` CLI — no network, no RPC.
# Tests the protocol-level apply path directly.
#
# Run from repo root: bash tools/test_dapp_call.sh
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe

echo "=== v2.19 DAPP_CALL apply semantics ==="
OUT=$($UNCHAINED test-dapp-call 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp_call all assertions"; then
  echo ""
  echo "  PASS: v2.19 DAPP_CALL apply path"
  exit 0
else
  echo ""
  echo "  FAIL: dapp_call had assertion failures"
  exit 1
fi
