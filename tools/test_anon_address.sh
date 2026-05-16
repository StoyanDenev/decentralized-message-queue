#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the anon-address
# helpers (S-028 surface): is_anon_address, normalize_anon_address,
# parse_anon_pubkey, make_anon_address.
#
# Faster unit-level counterpart to tools/test_anon_address_case.sh
# (which exercises the same surface end-to-end through 3-node RPC —
# 1+ minute to spin up vs ~1 second for the unit test). Both stay in
# the suite: the integration test catches RPC-layer regressions
# (rpc_balance / rpc_send / rpc_submit_tx normalization at input);
# the unit test catches regressions in the address helpers themselves.
#
# Assertions covered (12 total):
#   1-3. is_anon_address accepts canonical lowercase, uppercase,
#        mixed-case "0x + 64 hex" forms (S-028 closure).
#   4-7. is_anon_address rejects: missing 0x prefix, wrong length,
#        non-hex char, registered-domain name (no 0x).
#   8.   normalize_anon_address lowercases hex while preserving the
#        "0x" prefix.
#   9.   normalize_anon_address leaves registered domain names
#        unchanged.
#  10.   make_anon_address ↔ parse_anon_pubkey round-trip
#        (byte-identical pubkey across the conversion).
#  11.   parse_anon_pubkey is case-insensitive: uppercase address
#        yields the same pubkey as lowercase (S-028 case-tolerance).
#  12.   make_anon_address always emits lowercase canonical form
#        (the storage-key invariant).
#
# Run from repo root: bash tools/test_anon_address.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Anon-address helpers (S-028 unit-level) ==="
OUT=$($DETERM test-anon-address 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: anon-address all assertions"; then
  echo ""
  echo "  PASS: anon-address unit test"
  exit 0
else
  echo ""
  echo "  FAIL: anon-address had assertion failures"
  exit 1
fi
