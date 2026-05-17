#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the three consensus
# message types (ContribMsg / BlockSigMsg / AbortClaimMsg) and their
# commitment-hash helpers (make_contrib_commitment +
# make_abort_claim_message).
#
# These three messages drive the K-of-K consensus protocol:
#
#   * ContribMsg (Phase 1): each committee member signs
#     (block_index, prev_hash, sorted tx_hashes, dh_input). Sigs
#     gather to K → Phase 1 complete.
#
#   * BlockSigMsg (Phase 2): each member reveals their dh_secret +
#     signs compute_block_digest. K sigs → block finalized.
#
#   * AbortClaimMsg (abort path): when a member's local timer fires
#     with fewer than M valid messages, they sign + broadcast an
#     abort claim naming the first missing creator. M-1 matching
#     claims form a quorum certificate (AbortEvent).
#
# A regression in any of:
#   - the commitment-hash helpers (make_contrib_commitment,
#     make_abort_claim_message)
#   - the message-type JSON round-trips
#   - the sign/verify integration
# would either silently break interoperability (a non-trivial
# K-of-K subset can't gather sigs) or open a replay attack surface
# (a commit hash collides across heights / rounds).
#
# 28 assertions covering:
#
#   make_contrib_commitment (6): determinism + sensitivity for every
#     input field (block_index, prev_hash, tx_hashes value,
#     tx_hashes ORDER, dh_input). The ORDER assertion is critical —
#     the contract says "sorted ascending" and a member with the
#     wrong order produces a commit that doesn't match peers.
#
#   make_abort_claim_message (5): determinism + sensitivity for
#     block_index, round (defeats cross-phase replay), prev_hash,
#     missing_creator.
#
#   Domain separation (1): contrib commit and abort claim hash
#     differ for the same anchor inputs (no cross-domain collision).
#
#   ContribMsg / BlockSigMsg / AbortClaimMsg JSON round-trip (15):
#     every field of each struct preserved through to_json + from_json.
#
#   Sign/verify integration (1): make_contrib produces a sig that
#     verifies under the signer's pubkey via the real Ed25519
#     primitives.
#
# Run from repo root: bash tools/test_consensus_msgs.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== ContribMsg + BlockSigMsg + AbortClaimMsg + commitment-hash helpers ==="
OUT=$($DETERM test-consensus-msgs 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: consensus-msgs all assertions"; then
  echo ""
  echo "  PASS: consensus-msgs unit test"
  exit 0
else
  echo ""
  echo "  FAIL: consensus-msgs had assertion failures"
  exit 1
fi
