#!/usr/bin/env bash
# v2.10 Phase A: pin RFC 9591 type-layout assumptions against the FROST
# API in `include/determ/crypto/frost.hpp`.
#
# RFC 9591 §3 fixes the on-the-wire widths for Ed25519 (Scalar 32,
# Point 32, Signature 64) and our typedefs alias std::array of the
# corresponding widths so the Phase-A adapter in
# `src/crypto/frost.cpp::frost_verify` can do byte-for-byte field
# adaptation between FROST and the in-house Ed25519 (PubKey, Signature)
# aliases without copying field semantics. This test pins those
# invariants — any future change that altered the sizes (e.g. adding a
# tag byte, switching to a curve with a different scalar field) would
# silently break interop with peer nodes.
#
# It also pins the default zero-init contract that the DKG-output /
# Sign-output structs (KeygenRound1Output, LocalShare, CommitmentMap,
# SignRound1Output) rely on for deterministic zero-state construction
# before the round1 / round2 / sign1 / sign2 / aggregate primitives
# populate their fields in Phase B / Phase D.
#
# 17 assertions across compile-time sizes, byte-parity, zero-init,
# comparison semantics, Identifier bounds, and struct default-init.
#
# Run from repo root: bash tools/test_frost_types.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.10 Phase A: FROST type-layout pins (RFC 9591 §3) ==="
OUT=$($DETERM test-frost-types 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: frost-types all assertions"; then
  echo ""
  echo "  PASS: frost-types unit test"
  exit 0
else
  echo ""
  echo "  FAIL: frost-types had assertion failures"
  exit 1
fi
