#!/usr/bin/env bash
# A3 / S8 wire-version negotiation + S-022 framing/cap layering contract —
# pin the network-layer invariants that SURROUND the binary codec but are
# distinct from the codec round-trip (test-binary-codec /
# test-binary-codec-roundtrip-exhaustive own that) and the HELLO encode /
# field-binding (test-hello-handshake-determinism owns that). The surfaces
# here are the ones a peer gets wrong on the wire under adversarial load.
#
# Coverage axes (3 groups, ~22 assertions):
#   (A) Negotiation arithmetic: the live min(ours,theirs) rule from
#       src/net/gossip.cpp's on_hello handler (and the contract in
#       src/net/binary_codec.cpp) — clamp-to-our-max (never negotiate UP
#       to an unknown codec), pass-through-when-lower (legacy compat),
#       exact-match, idempotence (re-applying min() is a fixed point),
#       symmetry (both endpoints reach the SAME version without an ack —
#       no split-brain codec), monotonicity (a more-capable peer never
#       yields a worse codec), and the missing-field default to
#       kWireVersionLegacy (pre-A3 peers omit wire_version). The rule is
#       mirrored as a local lambda so a drift in the gossip-side contract
#       trips the unit suite rather than a 3-node cluster bring-up.
#   (B) Framing-vs-cap layering (S-022): every per-type max_message_bytes
#       <= kMaxFrameBytes (16 MB framing ceiling) so the tight type-aware
#       cap is always reachable and never shadowed by the frame layer; the
#       three tiers are strictly ordered (1 < 4 < 16 MB); the largest tier
#       equals the framing ceiling exactly; the enumerated MsgType set
#       partitions into exactly the documented tiers (2 in 16 MB, 5 in
#       4 MB, the rest in the 1 MB default); and an unmapped future MsgType
#       fails CLOSED at the 1 MB floor, never the 16 MB ceiling.
#   (C) Discriminator-byte preservation: every non-HELLO MsgType encodes
#       its type byte at binary-envelope offset 2 and decode_binary
#       recovers the exact same MsgType — the discriminator IS the
#       receive-side dispatch key, so it must survive independent of the
#       payload (two MsgTypes with identical payloads still dispatch right).
#
# Companion to:
#   - test-binary-codec, test-binary-codec-roundtrip-exhaustive (codec
#     round-trip + tamper-rejection + cap-value golden vectors)
#   - test-hello-handshake-determinism (HELLO encode/field-binding +
#     HELLO-always-JSON carve-out)
#   - test-protocol-version-pinning (PROTOCOL.md §16 version contract)
#
# Run from repo root: bash tools/test_wire_negotiation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A3/S8 wire-version negotiation + S-022 framing/cap layering ==="
OUT=$($DETERM test-wire-negotiation 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: wire-negotiation all assertions"; then
  echo ""
  echo "  PASS: wire-negotiation unit test"
  exit 0
else
  echo ""
  echo "  FAIL: wire-negotiation had assertion failures"
  exit 1
fi
