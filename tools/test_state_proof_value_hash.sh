#!/usr/bin/env bash
# Light-client VALUE-ENCODING contract for Chain::state_proof. The sibling
# `test-state-proof-namespaces` proves a leaf's (key, value_hash) pair is a
# MEMBER of the committed Merkle root — the "membership" half of the light-
# client argument. It never asserts what the leaf's value_hash MEANS. A
# trustless reader that wants to learn alice's balance (not just "alice has
# some proven leaf") must independently recompute the expected value_hash
# from raw fields using the SAME encoding the producer used in
# src/chain/chain.cpp::build_state_leaves, then confirm it equals the
# proof's value_hash. This test pins exactly that contract for the four
# simple namespaces a:/s:/k:/c: — the "meaning" half of the argument.
#
#   - a:  accounts_   value_hash = SHA256( u64(balance) || u64(next_nonce) )
#   - s:  stakes_     value_hash = SHA256( u64(locked)  || u64(unlock_height) )
#   - k:  constants   value_hash = SHA256( u64(min_stake) )
#   - c:  counters    value_hash = SHA256( u64(genesis_total) )  (key "k:c:...")
#
# If build_state_leaves ever changed a namespace's field order, width, or
# hashing without updating the documented light-client encoding, this test
# fails — protecting every external verifier that reconstructs value_hash
# off-node.
#
# 11 assertions:
#
#   Per-namespace recompute + verify (8):
#     - a:/s:/k:/c: each: proof's value_hash equals the independently-
#       recomputed encoding AND that recomputed value_hash re-verifies
#       under state_root (plus a:-field-order sensitivity + s:-fixture sanity)
#
#   Cross-namespace value distinctness (1):
#     - a:/s:/k:/c: recomputed value_hashes pairwise distinct
#
#   Tamper rejection + determinism (2):
#     - value_hash from a wrong balance fails merkle_verify
#     - 2 recomputations of the a: encoding byte-identical
#
# Run from repo root: bash tools/test_state_proof_value_hash.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== state_proof per-namespace value-hash encoding contract ==="
OUT=$($DETERM test-state-proof-value-hash 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-proof-value-hash all assertions"; then
  echo ""
  echo "  PASS: state-proof-value-hash unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-proof-value-hash had assertion failures"
  exit 1
fi
