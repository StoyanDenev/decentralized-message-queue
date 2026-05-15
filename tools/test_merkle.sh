#!/usr/bin/env bash
# v2.1 / S-035 Option 1 seed — in-process unit test for the Merkle
# primitives that the v2.2 light-client surface depends on.
#
# Runs `determ test-merkle` which exercises crypto::merkle_root +
# merkle_proof + merkle_verify + merkle_leaf_hash + merkle_inner_hash
# over freshly-constructed in-memory leaf sets. No network, no chain,
# no node — just the primitive code paths that compute_state_root and
# state_proof RPC build on.
#
# Assertions covered (12 total):
#   1. Empty leaf set → all-zero root (no-committed-state convention).
#   2. Single-leaf root equals leaf_hash (degenerate case).
#   3. Single-leaf proof is empty array.
#   4. Single-leaf merkle_verify OK.
#   5. Determinism: same inputs → same root.
#   6. Round-trip merkle_proof+verify for all 8 leaves of a balanced
#      (power-of-2) tree.
#   7. Round-trip on an unbalanced (7-leaf) tree — exercises the
#      last-leaf-duplication padding.
#   8. merkle_verify rejects a tampered value_hash.
#   9. merkle_verify rejects a tampered sibling-hash.
#  10. merkle_verify rejects a wrong target_index.
#  11. leaf_hash and inner_hash domain-separated (defeats second-
#      preimage attacks where a leaf hashes identically to an inner
#      node).
#  12. Sort-invariance: merkle_root sorts leaves internally so
#      pre-sorted input and shuffled input yield the same root.
#
# This is the first dedicated unit-test seed for S-035 Option 1
# (gtest/Catch2 seed). The in-process subcommand pattern is the same
# as test_atomic_scope.sh / test_composable_batch.sh /
# test_s018_json_validation.sh — a small but real foundation for
# eventually growing into the comprehensive Option 1 framework
# without depending on the multi-node bash harness.
#
# Run from repo root: bash tools/test_merkle.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.1 Merkle primitives ==="
OUT=$($DETERM test-merkle 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merkle all assertions"; then
  echo ""
  echo "  PASS: v2.1 Merkle primitives unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merkle had assertion failures"
  exit 1
fi
