#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `make_block_sig`,
# the Phase-2 BlockSigMsg producer helper in producer.hpp.
#
# Complements test-consensus-msgs (which covers `make_contrib` +
# `make_abort_claim`) with the third K-of-K consensus message
# production helper. Phase-2 K-of-K signing: each committee
# member signs compute_block_digest's output, and K gathered
# signatures finalize the block.
#
# A regression in make_block_sig would either silently fork the
# signing path (wrong sig message → no peer can verify) or produce
# a sig that verifies against the wrong content.
#
# 15 assertions in nine blocks:
#
#   Data-field preservation (4):
#     - block_index, signer, delay_output, dh_secret all
#       preserved as passed.
#
#   Central sign/verify contract (2):
#     - Signature verifies under the signer's pubkey over the
#       block_digest input.
#     - Tampered block_digest fails verification (defends against
#       post-collection digest swap).
#
#   Cross-signer distinctness + key-binding (2):
#     - Distinct signers produce distinct sigs over the same
#       digest (K-of-K threshold is K *distinct* sigs).
#     - Signer A's sig does NOT verify under signer B's pubkey.
#
#   RFC 8032 determinism (1):
#     - Same key + same digest → same signature (the
#       deterministic-Ed25519 invariant; defends against any
#       future regression that introduces nondeterministic
#       libsodium variants).
#
#   Sig-domain documentation (6):
#     - block_index doesn't affect sig (digest already encodes it
#       via compute_block_digest).
#     - signer string doesn't affect sig (metadata, not in sig
#       domain).
#     - delay_output + dh_secret don't affect sig (carried for
#       Phase-2 reveal, not in sig domain).
#     - But all three field-distinct-per-message invariants
#       preserved so the wire format carries them distinctly.
#
# Run from repo root: bash tools/test_make_block_sig.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== make_block_sig — Phase-2 K-of-K BlockSigMsg producer ==="
OUT=$($DETERM test-make-block-sig 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: make-block-sig all assertions"; then
  echo ""
  echo "  PASS: make-block-sig unit test"
  exit 0
else
  echo ""
  echo "  FAIL: make-block-sig had assertion failures"
  exit 1
fi
