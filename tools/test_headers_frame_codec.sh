#!/usr/bin/env bash
# D2 inc7c — in-process unit test for the HEADERS_RESPONSE wire frame
# (src/net/binary_codec.cpp encode_headers_response_frame /
# decode_headers_response_frame).
#
# HEADERS_RESPONSE was one of the last two wire payloads still travelling as
# length-prefixed JSON inside the binary envelope. It is now a fixed frame:
#
#     [from u64 LE][height u64 LE][count u16 LE]        count <= 256 (kHeadersPageMax)
#     count x DHF1 record:
#         [magic 'DHF1'][block_hash 32][frame_len u32 LE][Block frame]
#
# where the Block frame is the canonical chain::Block::encode_frame with the
# four heavy collections (transactions / cross_shard_receipts /
# inbound_receipts / initial_state) EMPTY — exactly what Node::rpc_headers
# strips — and block_hash is the served compute_hash() (carried data, not a
# claim the decoder can recompute from a stripped header). The payload DOM is
# the rpc_headers envelope {headers, from, count, height}, so `determ headers
# --peer` and every downstream verifier see the same DOM as the RPC path.
#
# Assertions:
#   HF-1  the theorem: decode(encode(DOM)) == the rpc_headers DOM, over a page
#         holding a folded beacon header (records + witness), a genesis-shaped
#         header and a leaf header; the empty page is the 22-byte frame; every
#         decoded header has NO heavy key and the served block_hash verbatim;
#         from/count/height are rebuilt (count is carried ONCE).
#   HF-2  canonical fixed point: encode(decode(x)) == x; determinism.
#   HF-3  fail-closed arms — each a mutant target:
#           a) EVERY proper prefix rejected (no unbounded field read);
#           b) a trailing byte rejected (exact consumption);
#           c) a record whose tag is not DHF1 ('DHF2' included) rejected;
#           d) the page cap at its exact boundary: 256 records decode, 257 are
#              rejected BEFORE any record is parsed;
#           e) count-lie: a count backed by too few bytes rejected before any
#              allocation;
#           f) frame_len bound: a length past the buffer, one byte short and
#              one byte long all rejected;
#           g) a record carrying a transaction / receipt / initial_state is
#              rejected (one encoding per header), with the stripped control.
#   HF-4  HOSTILE BYTES: single-byte corruptions, 0xFFFF stamps, adversarial
#         tails and garbage bodies — every input decodes or throws.
#   HF-5  VECTOR PIN: a minimal page equals the hand-assembled layout and its
#         SHA-256 is pinned.
#   HF-6  encoder refusals: count/array mismatch, a heavy key, a missing
#         block_hash, 257 headers, a non-array headers field — refused, never
#         clamped.
#
# Companions: test_wire_payload_frames.sh (the frame under the shared
# PF-1/PF-2/PF-4 theorem with the other seven), test_binary_codec.sh (the
# 19/19 exact-length sweep + the binary-only legs), and the independent
# light-client mirror in tools/test_light_decode_wire.sh.
#
# Run from repo root: bash tools/test_headers_frame_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== HEADERS_RESPONSE frame codec (DHF1 header records, D2 inc7c) ==="
OUT=$($DETERM test-headers-frame-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: headers-frame-codec all assertions"; then
  echo ""
  echo "  PASS: headers-frame-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: headers-frame-codec had assertion failures"
  exit 1
fi
