#!/usr/bin/env bash
# v2.18 Theme 7 — DAPP_REGISTER apply-path regression test.
#
# Exercises the DApp registration lifecycle:
#   1. create: alice registers a DApp with service_pubkey, endpoint_url,
#      topics, metadata. Verifies entry shape and state_root binding.
#   2. update: re-register with new endpoint_url + topic. Verifies
#      registered_at is preserved across updates.
#   3. deactivate: op=1 sets inactive_from = current_height + GRACE.
#
# In-process via `determ test-dapp-register` CLI — no network, no RPC.
# Tests the protocol-level apply path directly against a freshly-
# constructed Chain with alice as a REGISTER'd Determ identity.
#
# Run from repo root: bash tools/test_dapp_register.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe

echo "=== v2.18 DAPP_REGISTER apply semantics ==="
OUT=$($DETERM test-dapp-register 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dapp_register all assertions"; then
  echo ""
  echo "  PASS: v2.18 DAPP_REGISTER apply path"
  exit 0
else
  echo ""
  echo "  FAIL: dapp_register had assertion failures"
  exit 1
fi
