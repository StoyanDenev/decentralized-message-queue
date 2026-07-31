#!/usr/bin/env bash
# PROTOCOL.md §16 protocol-version contract pinning.
#
# Determ v1 has FOUR distinct version surfaces, each with its own
# backward-compat policy (PROTOCOL.md §16.2). This test pins the
# CURRENT contract for every surface so the next reviewer who
# touches a version field has to update this test deliberately
# rather than by accident.
#
# Covered surfaces:
#
#   1. MsgType enum integers — the gossip envelope's `type` byte.
#      HELLO=0, BLOCK=1, BLOCK_SIG=3, CONTRIB=4 anchor the most-
#      critical assignments. Reordering would mis-route every
#      peer-to-peer message.
#
#   2. The wire-version constant (D2 binary-only wire):
#         kWireVersionBinary = 1    (the single shipped format)
#      The v0 JSON envelope and the negotiation constants were
#      deleted pre-genesis; HELLO advertises this value as the
#      additive post-genesis upgrade escape hatch.
#
#   3. Binary envelope magic + version (0xB1 0x01 — the first two
#      body bytes of every message). is_binary_envelope
#      gates the binary-only deserializer; decode_binary
#      rejects unsupported versions with diagnostic.
#
#   4. Snapshot version field (S-018 / chain.cpp::
#      restore_from_snapshot). snap.version==1 accepted; missing
#      or future (=2) rejected.
#
#   5. Chain envelope schema (S-021 — chain.json wraps
#      {head_hash, blocks} but has NO version field; the schema
#      is shape-identified, with legacy array-form chain.json as
#      backward-compat fallback). Pinning "no version field"
#      defends against a future PR that accidentally adds one and
#      breaks pre-versioned parsers in the wild.
#
#   6. Genesis schema (GenesisConfig::from_json — also NO version
#      field; forward-compat via field-level .value() defaults and
#      skip-mix-when-default invariants in compute_genesis_hash).
#      Unknown keys must be tolerated.
#
#   7. Block JSON (Block::from_json — also NO version field;
#      schema is identified by required-field set, with S-018
#      field-name diagnostics on missing required fields).
#
#   8. HELLO `wire_version` field — make_hello defaults to
#      kWireVersionBinary + accepts override + round-trips intact
#      through the binary HELLO frame (advertisement only).
#
#   9. HELLO-is-binary contract (D2 flip of the old always-JSON
#      carve-out): encode_binary(HELLO) SUCCEEDS with type byte 0 —
#      the binary-only wire has no JSON HELLO exception.
#
#  10. MsgType numbering integrity — highest assigned value is 18
#      (HEADERS_RESPONSE); S-022 default-branch cap (1 MB) covers
#      any future variant added without explicit categorization.
#
# Defends against migration drift where a regression would either
# silently accept arbitrary version numbers (silent format fork)
# or break v1 parsers — the two scenarios behind every chain-fork
# incident in production blockchains.
#
# ~22 assertions across 10 scenarios.
#
# Run from repo root: bash tools/test_protocol_version_pinning.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== PROTOCOL.md §16 version-contract pinning — MsgType / wire-version / binary magic / snapshot version / chain envelope / genesis / block / HELLO ==="
OUT=$($DETERM test-protocol-version-pinning 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: protocol-version-pinning all assertions"; then
  echo ""
  echo "  PASS: protocol-version-pinning unit test"
  exit 0
else
  echo ""
  echo "  FAIL: protocol-version-pinning had assertion failures"
  exit 1
fi
