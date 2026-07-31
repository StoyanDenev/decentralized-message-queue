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
# 48 assertions. The four blocks below enumerate the original 35; the
# hostile-wire block added after them is described at the end.
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
#   Hostile-wire ordering gates (round-12 audit wf_c277c6d1):
#     WIRE-1. An OVERSIZE BINARY envelope is rejected BEFORE its
#        payload is decoded (pre-decode per-type cap). The vector is
#        well-formed at any size, so only the cap can reject it.
#     WIRE-2. The structural ceiling (kMaxJsonDepth / kMaxJsonNodes)
#        bounds the DOM before the parser allocates. A byte cap bounds
#        the INPUT, not the DOM built from it — 16 MB of '[' was
#        measured at ~831 MB peak heap (51.9x). Five legs:
#          * a VALID, BALANCED JSON envelope past the depth ceiling is
#            rejected pre-parse (a setup leg asserts it really is valid
#            JSON, so the rejection cannot be a parse error);
#          * the DEEPEST LEGITIMATE envelope (CHAIN_RESPONSE, depth 8)
#            still deserializes — the anti-over-tightening leg;
#          * structural bytes past an ESCAPED quote are data, not
#            structure — pins the scan's string-state tracking against
#            a false reject;
#          * a FLAT (depth-2) envelope past the node ceiling is
#            rejected — the shape the depth ceiling cannot see;
#          * a BINARY envelope CLAIMING SNAPSHOT_RESPONSE cannot use
#            that type's 16 MB cap to bypass the ceiling. The type at
#            offset 2 is attacker-chosen, so WIRE-1 alone does not
#            close this; the setup leg asserts the frame is UNDER its
#            WIRE-1 cap, proving WIRE-1 is not what rejects it.
#
#   (WIRE-3 — a malformed frame CLOSES the peer — lives in
#    `determ test-net-virtual`, since it needs a real Peer over a
#    Connection rather than the codec in isolation.)
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
