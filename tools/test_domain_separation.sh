#!/usr/bin/env bash
# S-035 Option 1 seed — in-process cross-cutting test for domain
# separation across every commitment hash in the protocol.
#
# Protocol uses many SHA-256-based commitments for distinct
# semantic purposes:
#
#   * compute_block_digest    (Phase-2 K-of-K signature target)
#   * make_contrib_commitment (Phase-1 sig target)
#   * make_abort_claim_message (abort certificate sig target)
#   * compute_delay_seed      (Phase-1 inputs commitment)
#   * compute_block_rand      (Phase-2 randomness output)
#   * compute_tx_root         (committee tx union commitment)
#   * compute_genesis_hash    (chain identity)
#   * Transaction::compute_hash (tx identity)
#   * Block::compute_hash     (block identity / chain-anchor)
#
# Every pair of these MUST produce distinct outputs even when fed
# similar inputs. A cross-domain collision would enable cross-
# protocol replay attacks where an attacker uses a sig made for
# one commitment in another context.
#
# Each function has its own dedicated test exercising input
# sensitivity (test-block-rand, test-block-digest, test-block-hash,
# test-consensus-msgs, test-tx-root, test-genesis, test-transaction,
# test-state-root, test-random-state). This test fills the
# cross-cutting gap: explicit non-collision invariant on a common
# input.
#
# 20 assertions in two blocks:
#
#   Pairwise non-collision (16):
#     - make_contrib_commitment vs make_abort_claim_message
#     - make_abort_claim round-1 vs round-2 (within-domain)
#     - compute_delay_seed vs compute_block_rand (Phase-1 vs 2)
#     - compute_block_digest vs Block::compute_hash (S-030 D2 fence)
#     - Transaction::compute_hash vs Block::compute_hash
#     - compute_tx_root vs the tx_hash it commits
#     - compute_genesis_hash vs every other commitment (7 pairs)
#     - compute_block_digest vs compute_delay_seed
#     - compute_block_digest vs make_contrib_commitment
#     - compute_block_rand vs compute_block_digest
#
#   S-033/S-038 state_root exclusion fence (3):
#     - state_root mutation leaves compute_block_digest unchanged
#       (proves the EXCLUSION half of the S-030 D2 contract)
#     - state_root mutation DOES change compute_hash (proves
#       the INCLUSION half — chain-anchor binds state)
#     - digest != hash even with state_root populated (domain
#       distinction holds across the mutation)
#
#   Determinism sanity (1):
#     - Same input through same function twice → same output
#       (cross-checks that non-collision comes from distinct
#       inputs, not from internal state)
#
# Run from repo root: bash tools/test_domain_separation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Domain separation across every protocol commitment hash ==="
OUT=$($DETERM test-domain-separation 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: domain-separation all assertions"; then
  echo ""
  echo "  PASS: domain-separation unit test"
  exit 0
else
  echo ""
  echo "  FAIL: domain-separation had assertion failures"
  exit 1
fi
