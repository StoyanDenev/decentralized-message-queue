#!/usr/bin/env bash
# D2-inc5 — in-process unit test for the canonical binary Block container
# (`chain::Block::encode_frame` / `decode_frame`, src/chain/block.cpp).
#
# This codec ships ALONGSIDE Block::to_json / from_json and no call site uses
# it yet — the p2p wire (BLOCK / CHAIN_RESPONSE / BEACON_HEADER / SHARD_TIP /
# CROSS_SHARD_RECEIPT_BUNDLE) and chain storage switch over in later D2
# increments. Until then this gate is the ONLY thing standing between the
# codec and a silent defect, so it is written to be adversarial rather than
# merely demonstrative.
#
# THE THEOREM (BF-1) is INFORMATION EQUIVALENCE with the JSON container, not
# field-for-field round-trip:
#
#     decode_frame(encode_frame(b))  ==json==  from_json(to_json(b))
#
# That is the property which makes the later container swap provably
# behavior-preserving: whatever a node would believe after a JSON round trip,
# it believes after a binary one. Field-for-field would be the WRONG theorem —
# to_json deliberately DISCARDS information in two places and the frame
# mirrors that discard on purpose:
#
#   * the six-key creator_view_* bundle when every root is zero (and likewise
#     the shard-tip pair), and
#   * source_shard_id when eligible_count == 0.
#
# Carrying those faithfully sounds strictly better but is not. None of them is
# covered by signing_bytes or compute_block_digest, so a relayer can append
# them to a valid block without breaking its hash or signatures. to_json
# normalizes that injection away; a faithful binary frame would carry it and
# let the validator reject an otherwise-valid block — a remotely-triggerable
# rejection, i.e. a censorship / liveness vector under the fork-free doctrine.
# Mirroring keeps the two paths from ever disagreeing on accept/reject for the
# same block. (Owner decision, 2026-08-01; BF-10 and BF-11 pin it.)
#
# 14 assertions:
#
#   BF-0  the empty frame is exactly 297 bytes. Pins kMinBlockFrame, from
#         which the witness Layer-1 cap is derived — if that constant drifts
#         ABOVE the true minimum the cap rejects legitimate one-witness
#         frames. Exactly the bug this leg caught in development (the u32
#         length prefix was counted twice).
#   BF-1  information equivalence, on a block exercising all 37 fields.
#   BF-2  encode(decode(x)) == x byte-for-byte — one canonical encoding per
#         value, which is the whole point of D2.
#   BF-3  signing_bytes and compute_hash byte-identical across the round trip
#         (the container touches no consensus hash).
#   BF-4  an all-default block round-trips WITHOUT resurrecting any of the
#         nine gated to_json keys — always-present must not leak a value.
#   BF-5  a trailing byte is rejected 'trailing bytes after last section'.
#   BF-6  EVERY proper prefix of a valid frame is rejected (~2.8k truncations,
#         zero silently accepted).
#   BF-7  a count of 65535 backed by 10 bytes is rejected before any reserve.
#   BF-8  witness depth: one level decodes, a NESTED witness is rejected
#         'must be a leaf block'. Enforced INLINE in the decoder so exactly
#         one site produces the string.
#   BF-10 a non-empty view LIST under all-zero roots is dropped by BOTH
#         containers.
#   BF-11 source_shard_id under eligible_count == 0 is dropped by BOTH.
#   BF-12 HOSTILE BYTES: 12,248 adversarial inputs - every single-byte
#         corruption of a valid frame, 0xFFFF stamps over the header region,
#         3000 pure-garbage buffers, and 500 valid-frames-with-hostile-tails.
#         Contract: every input either decodes or throws std::exception.
#         Reaching the end of the sweep IS the assertion - a crash, a hang or
#         an out-of-bounds read kills the run. Runs in ~0.6s.
#
#         Why this leg exists: at stage 2 this decoder sits on the PRE-AUTH
#         wire, so "well-formed input round-trips" is not the property that
#         matters. BF-6 only truncates a VALID frame, which is a narrow class -
#         every field boundary stays where the encoder put it. BF-12 corrupts
#         counts and length prefixes IN PLACE, which is what desynchronises a
#         parse and is how a decoder gets walked off its buffer. It was added
#         after the mutant pass showed that an encoder emitting one section
#         FEWER than the decoder reads does not reject cleanly - it fail-fasts
#         the process. Mutant-only, but an attacker supplies that shape free.
#
# RESIDUAL, stated rather than implied: BF-7 is STRUCTURAL, not measured. A
# mutant moving the cap after the reserve keeps it green — VERIFIED, not
# assumed: the mutant was built and run, and BF-7 stayed PASS. That is
# tolerable only because the u16 count width bounds the damage by
# construction — the largest possible over-reserve is 65535 x 64 B ~ 4 MB,
# which is also the wire cap for a BLOCK, so check placement is a performance
# question and not the unbounded WIRE-1 amplification class (16 MB -> 831 MB,
# 51.9x). Had the counts been u32 this leg would HAVE to count allocations.
# Revisit if any count width is ever widened.
#
# Run from repo root: bash tools/test_block_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block binary container (chain::Block::encode_frame / decode_frame, D2-inc5) ==="
OUT=$($DETERM test-block-binary-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-binary-codec all assertions"; then
  echo ""
  echo "  PASS: block-binary-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-binary-codec had assertion failures"
  exit 1
fi
