#!/usr/bin/env bash
# S-035 Option 1 seed — anon-address balance-fragmentation hazard at the
# APPLY layer.
#
# The anon-address PRIMITIVES are already pinned:
#   - test-anon-address              is_anon_address / normalize / parse
#   - test-anon-address-derivation   make_anon_address byte-identity
#   - test-anon-routing              make/parse + case-variant same-shard
#   - test-account-create-on-credit  TRANSFER / receipt auto-create
#
# None of them drive the S-028 fragmentation THREAT through Chain::append.
# This test executes the exact hazard described in prose by
# proofs/S028AnonAddressNormalization.md §5.3 (Threat T3):
#
#   1. Two case-variant spellings of the SAME pubkey, applied WITHOUT
#      normalization, land in two distinct accounts_ entries — balances
#      are SPLIT and a canonical query under-reports (the loss).
#   2. The SAME two credits, normalized at ingress, consolidate into ONE
#      canonical entry — balances sum to the full total (the fix).
#   3. The split is bound into the a:-namespace state_root (fragmented vs
#      consolidated commitments differ) — not just a read-side artifact.
#   4. A1 unitary supply holds in BOTH worlds (misattribution, not
#      mint/burn).
#   5. Anon-vs-domain account-map distinctness + canonical-key stability
#      under a repeat credit.
#
# 14 assertions across the fragmentation / consolidation / determinism
# scenarios.
#
# Run from repo root: bash tools/test_anon_address_fragmentation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== anon-address fragmentation — S-028 T3 hazard at the apply layer ==="
OUT=$($DETERM test-anon-address-fragmentation 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: anon-address-fragmentation all assertions"; then
  echo ""
  echo "  PASS: anon-address-fragmentation unit test"
  exit 0
else
  echo ""
  echo "  FAIL: anon-address-fragmentation had assertion failures"
  exit 1
fi
