#!/usr/bin/env bash
# S-022 framing/cap layering + discriminator contract for the D2 binary-only
# wire — pin the network-layer invariants that SURROUND the binary codec but
# are distinct from the codec round-trip (test-binary-codec /
# test-binary-codec-roundtrip-exhaustive own that) and the HELLO encode /
# field-binding (test-hello-handshake-determinism owns that).
#
# D2 NOTE: this gate was tools/test_wire_negotiation.sh until the JSON wire
# envelope + the per-pair v0/v1 negotiation were deleted pre-genesis
# (DECISION-LOG 2026-07-28). Its section (A) — the min(ours,theirs)
# negotiation arithmetic — died with that surface; the surviving sections
# gate the BINARY wire's load-bearing invariants (sequence-before-harden:
# gate the survivor).
#
# Coverage axes (2 groups):
#   (B) Framing-vs-cap layering (S-022): every per-type max_message_bytes
#       <= kMaxFrameBytes (16 MB framing ceiling) so the tight type-aware
#       cap is always reachable and never shadowed by the frame layer; the
#       three tiers are strictly ordered (1 < 4 < 16 MB); the largest tier
#       equals the framing ceiling exactly; the enumerated MsgType set
#       partitions into exactly the documented tiers (2 in 16 MB, 5 in
#       4 MB, the rest in the 1 MB default); and an unmapped future MsgType
#       fails CLOSED at the 1 MB floor, never the 16 MB ceiling.
#   (C) Discriminator-byte preservation: EVERY MsgType — HELLO included,
#       since D2 gave it a fixed binary frame — encodes its type byte at
#       binary-envelope offset 2 and decode_binary recovers the exact same
#       MsgType — the discriminator IS the receive-side dispatch key, so it
#       must survive independent of the payload (two MsgTypes with
#       identical payloads still dispatch right).
#
# Companion to:
#   - test-binary-codec, test-binary-codec-roundtrip-exhaustive (codec
#     round-trip + tamper-rejection + cap-value golden vectors)
#   - test-hello-handshake-determinism (HELLO encode/field-binding +
#     the D2 HELLO-is-binary contract)
#   - test-protocol-version-pinning (PROTOCOL.md §16 version contract)
#
# Run from repo root: bash tools/test_wire_caps_discriminator.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-022 framing/cap layering + discriminator (D2 binary-only wire) ==="
OUT=$($DETERM test-wire-caps-discriminator 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: wire-caps-discriminator all assertions"; then
  echo ""
  echo "  PASS: wire-caps-discriminator unit test"
  exit 0
else
  echo ""
  echo "  FAIL: wire-caps-discriminator had assertion failures"
  exit 1
fi
