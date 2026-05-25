#!/usr/bin/env bash
# S-038 / v2.1 Merkle tree structural pins — lock in the sorted-leaves
# balanced binary Merkle tree shape (NOT a sparse Merkle tree / NOT a
# Patricia trie). The state-commitment in S-033 + the v2.2 light-client
# inclusion proofs depend on this exact shape; a silent regression that
# swapped it would still pass the existing test-merkle / test-merkle-
# proof-tampering round-trips because those only exercise root → proof
# → verify on the same implementation.
#
# Verifies:
#   (1) Empty leaf set returns the all-zero Hash{} sentinel.
#   (2) Single-leaf tree: root == merkle_leaf_hash(L0).
#   (3) Two-leaf tree: root == merkle_inner_hash(LH0, LH1) in sorted-
#       by-key order.
#   (4) Three-leaf odd-count tree: last-leaf duplication at the bottom
#       row (Bitcoin-style padding documented in merkle.hpp).
#   (5) Four-leaf balanced tree: depth-2 shape, no padding.
#   (6) Determinism: independently-built identical content → identical
#       root (no hidden process-local state).
#   (7) Sort-on-build: descending-key leaf order → SAME root as
#       ascending — merkle_root sorts internally (caller doesn't pre-
#       sort).
#   (8) Domain separation: single-leaf root (0x00 leaf prefix) is byte-
#       distinct from same-content two-leaf root (0x01 inner prefix
#       over duplicated leaf).
#
# Companion to:
#   - test-merkle (positive primitives + round-trip)
#   - test-merkle-proof-tampering (exhaustive negative paths)
#   - test-state-root-determinism (chain-level state-root determinism
#     that builds on this tree)
#   - include/determ/crypto/merkle.hpp lines 9-21 (documented shape)
#   - src/crypto/merkle.cpp (the S-038 implementation under test)
#
# 8 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_merkle_tree_balanced.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Merkle tree structural pins — sorted-leaves balanced binary tree ==="
OUT=$($DETERM test-merkle-tree-balanced 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merkle-tree-balanced all assertions"; then
  echo ""
  echo "  PASS: merkle-tree-balanced unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merkle-tree-balanced had assertion failures"
  exit 1
fi
