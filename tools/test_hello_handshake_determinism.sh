#!/usr/bin/env bash
# HELLO message encode/decode determinism + handshake-state contract — pin
# every byte-level invariant the HELLO handshake relies on. HELLO is the
# FIRST wire message in any Determ peer connection — it exchanges
# domain / port / role / shard_id / wire_version. D2: it travels as the
# FIXED BINARY HELLO FRAME (binary_codec.cpp) like every other message —
# the JSON pre-negotiation carve-out died with the JSON envelope. Two
# byte-divergent encodings of "the same" HELLO would have downstream
# consequences for fingerprint-based DDoS layers and any peer-id hashing
# scheme that consumed the wire bytes.
#
# Coverage axes (7 scenarios):
#   (1) Replay determinism: encoding the same HelloMsg 3 times in a
#       row yields 3 byte-identical outputs (no hidden state mutation).
#   (2) Round-trip identity: encode → deserialize → re-encode produces
#       byte-identical output for both all-fields-populated HELLO and
#       a minimal HELLO (defaults only — role=SINGLE, shard_id=0,
#       wire_version=kWireVersionBinary).
#   (3) Cross-instance byte-identity: two distinct HelloMsg objects with
#       identical field values produce byte-identical frames (proves
#       serialization depends ONLY on field values, not object identity).
#   (4) Field-binding completeness: mutating each HELLO field
#       (domain / port / role / shard_id / wire_version) changes the
#       encoded output — the "no silently-dropped field" contract.
#   (5) HELLO-is-binary contract (D2 flip): encode_binary(HELLO)
#       SUCCEEDS with type byte 0; the serialized body IS a binary
#       envelope (is_binary_envelope true).
#   (6) Boundary values: wire_version=0, wire_version=kWireVersionBinary,
#       empty domain, 200-char domain,
#       port=0 / port=65535 — all round-trip cleanly.
#   (7) Insertion-order independence: two HelloMsg with identical fields
#       inserted in opposite orders produce byte-identical binary frames
#       (fixed field layout), and decode → re-encode is a byte fixed point.
#
# Companion to:
#   - test-protocol-version-pinning §8/§9 (HELLO wire_version field +
#     the D2 encode_binary(HELLO) success path as part of PROTOCOL.md §16)
#   - test-state-root-determinism, test-tx-signing-determinism,
#     test-merge-event-determinism, test-config-determinism (the
#     broader in-process determinism suite)
#
# Run from repo root: bash tools/test_hello_handshake_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== HELLO encode/decode determinism + handshake-state contract ==="
OUT=$($DETERM test-hello-handshake-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: hello-handshake-determinism all assertions"; then
  echo ""
  echo "  PASS: hello-handshake-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: hello-handshake-determinism had assertion failures"
  exit 1
fi
