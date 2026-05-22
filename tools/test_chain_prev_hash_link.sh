#!/usr/bin/env bash
# S-035 Option 1 seed — prev_hash chain-link contract.
#
# Block.prev_hash is the chain-anchor primitive: every non-genesis
# block carries prev_hash == prior.compute_hash(). This test pins
# that contract end-to-end:
#
#   * Happy path: 5-block chain, every block's prev_hash equals the
#     prior block's compute_hash().
#   * Genesis special case: prev_hash is all-zero (no predecessor).
#   * Apply-time rejection: both Chain::append (chain.cpp:55) and
#     BlockValidator::check_prev_hash (validator.cpp:43) reject
#     wrong / all-zero prev_hash on non-genesis blocks.
#   * Reload preserves links: Chain::save + Chain::load round-trip
#     keeps every per-block prev_hash link intact (and the S-021
#     wrapped-head_hash gate enforces it once globally).
#   * Tampering cascades: mutating ANY field that contributes to
#     compute_hash (timestamp here) changes that block's
#     compute_hash, so the NEXT block's stored prev_hash no longer
#     matches — defeats silent in-chain swap attempts.
#   * Empty-prev-hash at height 1 is rejected (zero is not a
#     wildcard for non-genesis blocks).
#   * Reorg-aware: extending the chain doesn't retroactively
#     rewrite prior prev_hashes (append-only contract).
#
# ~22 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_chain_prev_hash_link.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== prev_hash chain-link contract — happy path + cascade-detection + reload ==="
OUT=$($DETERM test-chain-prev-hash-link 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-prev-hash-link all assertions"; then
  echo ""
  echo "  PASS: test_chain_prev_hash_link"
  exit 0
else
  echo ""
  echo "  FAIL: chain-prev-hash-link had assertion failures"
  exit 1
fi
