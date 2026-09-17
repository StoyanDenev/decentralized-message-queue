#!/usr/bin/env bash
# D2 inc7c — in-process unit test for the SNAPSHOT_RESPONSE wire frame
# (src/net/binary_codec.cpp encode_snapshot_response_frame /
# decode_snapshot_response_frame).
#
# SNAPSHOT_RESPONSE was the last wire payload still travelling as
# length-prefixed JSON inside the binary envelope. It is now the canonical
# DSN1 snapshot record (Chain::encode_state) VERBATIM — one snapshot layout on
# the wire and at rest. The payload DOM is Chain::serialize_state's view: the
# encoder rebuilds the Chain from the DOM (restore_from_snapshot) and the
# decoder IS Chain::decode_state, so bad magic, a version other than 1,
# truncation, count lies, trailing bytes, a head_hash / block_index claim
# that does not match the tail and an S-033 state_root mismatch all reject at
# the pre-auth decode boundary.
#
# Assertions:
#   SR-1  the theorem: decode(encode(DOM)) == the serialize_state DOM, over a
#         chain touching EVERY snapshot namespace (every conditionally-emitted
#         key present on both sides), a consistent chain with a real
#         state_root, and the empty chain.
#   SR-2  canonical fixed point; the wire payload of a served snapshot ==
#         the chain's at-rest DSN1 bytes (also for a partial header_count);
#         the DSN1 magic + version lead the payload.
#   SR-3  fail-closed arms:
#           a) 'DSN2' magic and version 2 rejected;
#           b) EVERY proper prefix rejected;
#           c) a trailing byte rejected;
#           d) an accounts count of 2^32-1 rejected before any entry is read;
#           e) the tail-header cap at its exact boundary: 256 headers decode,
#              257 (backed by zero bytes, no frame at all) are rejected by the
#              cap BEFORE any header is parsed; 4,000,000 rejected by the byte
#              proof;
#           f) head_hash / block_index claim tampers rejected; a tampered
#              account balance rejected by the S-033 state_root gate;
#           g) the pre-inc7c lp-JSON shape (a VALID JSON snapshot) rejected at
#              the DSN1 magic, never parsed;
#           h) single-byte corruption sweep: every input decodes or throws.
#   SR-4  VECTOR PIN: the empty chain's frame is 270 bytes and its SHA-256 is
#         pinned.
#   SR-5  encoder refusals (257 tail headers refused, not clamped; a
#         non-snapshot DOM refused) and the A1 boundary: the unitary-balance
#         revalidate is the NODE's adoption policy, not a codec rule — an
#         A1-inconsistent snapshot still round-trips through the wire.
#
# Companions: test_snapshot_binary_codec.sh (the DSN1 container's own
# theorem, SB-1..SB-5), test_wire_payload_frames.sh, test_binary_codec.sh,
# and the independent light-client mirror in tools/test_light_decode_wire.sh.
#
# Run from repo root: bash tools/test_snapshot_response_frame_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== SNAPSHOT_RESPONSE frame codec (the DSN1 record on the wire, D2 inc7c) ==="
OUT=$($DETERM test-snapshot-response-frame-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: snapshot-response-frame-codec all assertions"; then
  echo ""
  echo "  PASS: snapshot-response-frame-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-response-frame-codec had assertion failures"
  exit 1
fi
