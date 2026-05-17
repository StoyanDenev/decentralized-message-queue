#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the wire-format codec
# (A3 / S8 closure: JSON envelope v0 + binary envelope v1 + the format-
# detecting deserializer) and the S-022 per-MsgType body-size cap table.
#
# The wire format is the trust boundary between peers. A regression
# here would either:
#
#   * silently break cross-peer interoperability (encode/decode
#     asymmetry across MsgType variants), or
#   * widen an attack surface (a new MsgType added to the enum
#     slipping past the S-022 default-tight 1 MB cap into the 4 MB
#     or 16 MB bucket without explicit categorisation).
#
# This test exercises the codec directly + locks in the cap table
# byte-for-byte against include/determ/net/messages.hpp.
#
# 35 assertions in four blocks:
#
#   JSON envelope (v0) round-trip (8):
#     1-4. HELLO — including the pre-negotiation always-JSON
#        contract; type + domain + port fields preserved through
#        round-trip.
#     5.   STATUS_REQUEST (consensus-chatter category).
#     6-7. TRANSACTION with non-trivial payload — type + payload
#        byte-for-byte equality.
#
#   Binary envelope (v1) round-trip + format detection (5):
#     8-10. STATUS_RESPONSE — non-empty body, is_binary_envelope
#        detects the magic byte, decode round-trip preserves type.
#     11.  is_binary_envelope returns FALSE for JSON-encoded bytes
#        (the format-detection contract).
#     12-13. encode_binary / decode_binary free-function direct
#        round-trip for CONTRIB (consensus-chatter category).
#
#   Malformed input rejection (2):
#     14. Garbage bytes (no JSON, no binary magic).
#     15. Truncated valid JSON (envelope missing closing brace).
#
#   S-022 per-MsgType cap table golden vectors (20):
#     16-17. 16 MB tier: SNAPSHOT_RESPONSE, CHAIN_RESPONSE.
#     18-22. 4 MB tier:  BLOCK, BEACON_HEADER, SHARD_TIP,
#        CROSS_SHARD_RECEIPT_BUNDLE, HEADERS_RESPONSE.
#     23-34. 1 MB tier:  HELLO, CONTRIB, BLOCK_SIG, ABORT_CLAIM,
#        ABORT_EVENT, EQUIVOCATION_EVIDENCE, TRANSACTION,
#        STATUS_REQUEST, STATUS_RESPONSE, GET_CHAIN,
#        SNAPSHOT_REQUEST, HEADERS_REQUEST.
#     35.  Default branch — any future MsgType beyond the
#        enumerated set falls through to 1 MB. The defensive
#        "default-tight" invariant prevents a new MsgType added
#        without explicit categorisation from slipping past the
#        S-022 fence into the 16 MB tier.
#
# Run from repo root: bash tools/test_binary_codec.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Wire-format codec (A3 / S8) + S-022 per-MsgType cap table ==="
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
