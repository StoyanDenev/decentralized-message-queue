#!/usr/bin/env bash
# D2-inc7a / inc7b — in-process unit test for the WIRE PAYLOAD frames of the
# five Block-carrying MsgTypes (BLOCK, BEACON_HEADER, SHARD_TIP,
# CROSS_SHARD_RECEIPT_BUNDLE, CHAIN_RESPONSE) and of CONTRIB
# (src/net/binary_codec.cpp).
#
# These six were the last consensus-critical payloads still travelling as
# length-prefixed JSON INSIDE the binary envelope. All five Block-carrying
# types delegate to the ONE canonical Block container
# (chain::Block::encode_frame / decode_frame, D2-inc5, gated by
# tools/test_block_binary_codec.sh) instead of deriving a second block layout
# per message type — the S-044 shared-codec discipline, and the reason inc5
# landed first. CONTRIB gets an always-present field layout whose decode
# returns ContribMsg::to_json(), so its three emission gates keep living at
# their single owning site (src/node/producer.cpp).
#
# THE THEOREM (PF-1) is the wire-level analogue of the Block container's
# BF-1. For every payload DOM P that a BUILDER produces:
#
#     decode_binary(encode_binary({type, P})).payload  ==  P
#
# That is what makes the swap provably behavior-preserving at the message
# layer: GossipNet::handle_message, the dispatcher and every Node handler read
# the payload as a DOM, so a decoder that rebuilds the builder's DOM exactly
# is invisible to all of them — which is why this increment edits ZERO handler
# code. The oracle (Block::to_json / ContribMsg::to_json) is not deleted by
# D2, so the gate stays live rather than becoming self-referential.
#
# Signature transparency: every signature these payloads carry binds a binary
# field hash (signing_bytes / compute_block_digest / make_contrib_commitment),
# never a serialization — so no verification outcome can change. Only the
# container does.
#
# Assertions:
#
#   PF-1  builder-DOM equivalence for all six types, on a Block exercising
#         every section (transactions, all six creator_view_* collections,
#         abort + equivocation events, both receipt lists, initial_state,
#         shard_tip_records and a witness) and a ContribMsg with all four
#         view lists. Includes the EMPTY CHAIN_RESPONSE ("nothing more"),
#         which is a real and load-bearing sync shape.
#   PF-2  canonical fixed point: encode(decode(x)) == x byte-for-byte, per
#         type. This is what makes the CROSS_SHARD_RECEIPT_BUNDLE relay
#         (on_cross_shard_receipt_bundle re-broadcasts the DECODED Message)
#         reproduce the inbound bytes exactly.
#   PF-3  gate mirror, in BOTH directions:
#           a) a DEFAULT CONTRIB must not resurrect any of the nine gated
#              keys (always-present must not leak a value);
#           b) a non-empty view LIST under all-zero roots KEEPS the six-key
#              bundle in both containers — ContribMsg's gate is value-derived,
#              so nothing is discarded;
#           c) the opposite mirror through the envelope: BLOCK drops a view
#              list under all-zero roots exactly as to_json drops it (BF-10).
#              Preserving data the JSON path discards is not "more faithful" —
#              those bytes are neither signed nor hashed, so a relayer could
#              append them and trigger a validator rejection of an otherwise
#              valid block.
#   PF-4  HOSTILE BYTES across all six frames: every single-byte corruption
#         of a valid frame, 0xFFFF stamps over the header region, valid
#         frames with adversarial tails, and pure-garbage bodies under each
#         type's envelope header. Contract: every input either decodes or
#         throws std::exception. Reaching the end of the sweep IS the
#         assertion — a crash, a hang or an out-of-bounds read kills the run.
#         These decoders sit on the PRE-AUTH wire, so "well-formed input
#         round-trips" is not the property that matters.
#   PF-5  COUNT-LIE: a declared count must be proven against the bytes that
#         actually remain BEFORE any reserve or loop (the WIRE-1 lesson — a
#         cap that runs after the work is not a cap). Covered for
#         CHAIN_RESPONSE's block count and CONTRIB's tx_hashes, each paired
#         with the control frame it was built from so it cannot pass
#         vacuously. Plus has_more's two-encodings-only rule.
#   PF-6  SHARD_TIP POISON-WITNESS — the one deliberate accept-rule change
#         here. Only BEACON producers fold shard_tip_records and attach
#         shard_tip_witnesses, so a legitimate SHARD_TIP tip is always a LEAF;
#         a poisoned tip would ride into the beacon's witness buffer and make
#         the folded beacon block unparseable fleet-wide (a beacon-liveness
#         attack). Node::on_shard_tip guard 4b already rejects exactly that
#         shape, so decoding the tip with allow_witnesses=false is strictly
#         accept-NARROWING to an already-rejected set, moved to the pre-auth
#         decode boundary so the multi-MB depth-2 parse never happens. Guard
#         4b stays in place for the _for_test / direct-call paths.
#         The falsify target is the MAP: flipping SHARD_TIP to
#         allow_witnesses=true reddens PF-6a/PF-6b while PF-6c (the SAME
#         records+witness block decoding as a BEACON_HEADER) stays green —
#         which is what proves this is a per-type map and not a blanket
#         reject.
#
# Companion gates, deliberately elsewhere:
#   * both-directions EXACT-LENGTH sweep (pad + truncate + control, per type)
#     lives in test-binary-codec leg 4d, whose `cases.size() == 17` pin is the
#     completeness statement — a new fixed frame without a row reds it;
#   * the Block container's own theorem lives in test-block-binary-codec
#     (BF-0 pins kMinBlockFrame = 297, which this codec's CHAIN_RESPONSE
#     min-element bound cites);
#   * the independent light-client mirror lives in
#     tools/test_light_decode_wire.sh (a second decoder written from the
#     published layout, so a passing run is cross-implementation conformance).
#
# Run from repo root: bash tools/test_wire_payload_frames.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Wire payload frames (BLOCK / BEACON_HEADER / SHARD_TIP / BUNDLE / CHAIN_RESPONSE / CONTRIB, D2-inc7a+7b) ==="
OUT=$($DETERM test-wire-payload-frames 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: wire-payload-frames all assertions"; then
  echo ""
  echo "  PASS: wire-payload-frames unit test"
  exit 0
else
  echo ""
  echo "  FAIL: wire-payload-frames had assertion failures"
  exit 1
fi
