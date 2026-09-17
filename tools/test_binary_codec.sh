#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the wire-format codec
# (D2 binary-only wire: the 0xB1 binary envelope is the single format;
# the legacy JSON envelope v0 + the format-detecting dispatch died with
# the D2 strip) and the S-022 per-MsgType body-size cap table.
#
# The wire format is the trust boundary between peers. A regression
# here would either:
#
#   * silently break cross-peer interoperability (encode/decode
#     asymmetry across MsgType variants),
#   * re-admit a deleted wire format (the D2 negative gate), or
#   * widen an attack surface (a new MsgType added to the enum
#     slipping past the S-022 default-tight 1 MB cap into the 4 MB
#     or 16 MB bucket without explicit categorisation).
#
# This test exercises the codec directly + locks in the cap table
# byte-for-byte against include/determ/net/messages.hpp.
#
#   Binary round-trip (D2 wire):
#     1.   HELLO via the fixed binary frame — type + domain + port +
#        role/shard_id/wire_version preserved through round-trip.
#     1b.  Malformed HELLO frames fail closed: truncated fixed fields
#        ('truncated HELLO frame') and trailing bytes
#        ('HELLO frame trailing bytes').
#     2.   STATUS_REQUEST (consensus-chatter category).
#     3.   TRANSACTION through the fixed tx frame (full required
#        field set; scalar fields preserved).
#     4.   STATUS_RESPONSE via serialize_binary + deserialize;
#        is_binary_envelope detects the magic byte.
#     5.   D2 NEGATIVE GATE: a well-formed LEGACY JSON envelope body
#        ('{' 0x7B) is rejected with the SPECIFIC string
#        'not a binary envelope' — a mutant re-admitting a JSON wire
#        parse goes RED here.
#     6.   encode_binary / decode_binary free-function direct
#        round-trip for CONTRIB; 6b reserved-byte fail-closed.
#
#   Malformed input rejection:
#     7. Garbage bytes (no binary magic).
#     8. Truncated envelope header (< 4 bytes).
#
#   S-022 per-MsgType cap table golden vectors:
#     16 MB tier: SNAPSHOT_RESPONSE, CHAIN_RESPONSE.
#     4 MB tier:  BLOCK, BEACON_HEADER, SHARD_TIP,
#        CROSS_SHARD_RECEIPT_BUNDLE, HEADERS_RESPONSE.
#     1 MB tier:  everything else, plus the default branch — any
#        future MsgType falls through to 1 MB ("default-tight").
#
#   Hostile-wire ordering gates (round-12 audit wf_c277c6d1; vectors
#   rebuilt as binary envelopes by the D2 strip):
#     WIRE-1. An OVERSIZE BINARY envelope is rejected BEFORE its
#        payload is decoded (pre-decode per-type cap). The vector is
#        well-formed at any size, so only the cap can reject it.
#     BINARY-ONLY (D2 inc7c — the length-prefixed JSON fallback and its
#        WIRE-2 structural ceiling are DELETED; every one of the 19
#        types is a fixed frame). Legs:
#          * an lp-JSON SNAPSHOT_RESPONSE carrying a VALID JSON snapshot
#            is REJECTED at the DSN1 magic (never parsed), and the same
#            snapshot round-trips as the DSN1 frame;
#          * an lp-JSON HEADERS_RESPONSE carrying a VALID envelope is
#            REJECTED, and the same envelope round-trips as the frame;
#          * an UNKNOWN MsgType byte (200) is REJECTED by name on decode
#            ('unknown MsgType 200 ... no length-prefixed JSON fallback')
#            and refused on encode ('no encoder for MsgType 200');
#          * a SNAPSHOT_RESPONSE body that is only a 2 GB json_len prefix
#            is rejected at the DSN1 magic after 8 bytes.
#        A mutant restoring the fallback reddens these; the 4d exact-length
#        sweep's `cases.size() == 19` pin is the completeness statement.
#
#   (WIRE-3 — a malformed frame CLOSES the peer — lives in
#    `determ test-net-virtual`, since it needs a real Peer over a
#    Connection rather than the codec in isolation.)
#
# Run from repo root: bash tools/test_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Wire-format codec (D2 binary-only) + S-022 per-MsgType cap table ==="
OUT=$($DETERM test-binary-codec 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: binary-codec all assertions"; then
  echo ""
  echo "  PASS: binary-codec unit test"
  exit 0
else
  echo ""
  echo "  FAIL: binary-codec had assertion failures"
  exit 1
fi
