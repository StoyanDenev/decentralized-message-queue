#!/usr/bin/env bash
# S-035 Option 1 seed — anon-address routing INTEGRATION.
#
# Each layer is already pinned:
#   - test-anon-address: parse / normalize / canonical hex
#   - test-shard-routing: shard_id_for_address determinism + uniformity
#
# This test verifies the three layers compose CORRECTLY:
#
#   1. make_anon_address(pubkey) produces a canonical 0x + 64-hex form
#   2. parse_anon_pubkey(addr) recovers the pubkey (round-trip)
#   3. Case-variant inputs route to the SAME shard (S-028 closure):
#      0xABC... and 0xabc... must be indistinguishable end-to-end —
#      if the normalize layer drifts from the routing layer, the same
#      logical address would land on different shards depending on case
#   4. Distinct pubkeys → distinct addresses (defeats key-collision
#      attacks where two keys would share an address/balance)
#   5. TRANSFER to anon-address that routes locally credits locally
#   6. TRANSFER to anon-address that routes cross-shard generates an
#      outbound debit and does NOT credit locally (recipient receives
#      via inbound receipt on the destination shard)
#   7. Determinism across the integrated path
#
# 15 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_anon_routing.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== anon-address routing integration — parse + shard + apply compose ==="
OUT=$($DETERM test-anon-routing 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: anon-routing all assertions"; then
  echo ""
  echo "  PASS: anon-routing unit test"
  exit 0
else
  echo ""
  echo "  FAIL: anon-routing had assertion failures"
  exit 1
fi
