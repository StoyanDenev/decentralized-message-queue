#!/usr/bin/env bash
# HELLO message encode/decode determinism + handshake-state contract — pin
# every byte-level invariant the HELLO handshake relies on. HELLO is the
# FIRST wire message in any Determ peer connection — it exchanges
# domain / port / role / shard_id / wire_version BEFORE any codec
# negotiation is complete, so it MUST be transmitted as JSON
# unconditionally. Two byte-divergent encodings of "the same" HELLO
# would have downstream consequences for fingerprint-based DDoS layers
# and any peer-id hashing scheme that consumed the wire bytes.
#
# Coverage axes (7 scenarios, ~18 assertions):
#   (1) Replay determinism: encoding the same HelloMsg 3 times in a
#       row yields 3 byte-identical outputs (no hidden state mutation).
#   (2) Round-trip identity: encode → deserialize → re-encode produces
#       byte-identical output for both all-fields-populated HELLO and
#       a minimal HELLO (defaults only — role=SINGLE, shard_id=0,
#       wire_version=kWireVersionMax).
#   (3) Cross-instance byte-identity: two distinct HelloMsg objects with
#       identical field values produce byte-identical JSON (proves
#       serialization depends ONLY on field values, not object identity).
#   (4) Field-binding completeness: mutating each HELLO field
#       (domain / port / role / shard_id / wire_version) changes the
#       encoded output — the "no silently-dropped field" contract.
#   (5) HELLO-always-JSON contract: encode_binary(HELLO) THROWS per
#       binary_codec.cpp's HELLO carve-out; is_binary_envelope returns
#       false for the JSON HELLO body (starts with '{', not 0xB1 magic).
#   (6) Boundary values: wire_version=0 (kWireVersionLegacy),
#       wire_version=kWireVersionMax, empty domain, 200-char domain,
#       port=0 / port=65535 — all round-trip cleanly.
#   (7) Canonical encoding: two HelloMsg with identical fields inserted
#       in opposite orders produce byte-identical JSON (alphabetical
#       key ordering on dump, insertion-order independent).
#
# Companion to:
#   - test-protocol-version-pinning §8/§9 (HELLO wire_version field +
#     encode_binary(HELLO) reject path as part of PROTOCOL.md §16)
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
