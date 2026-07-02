#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.9b — the RFC 9497 OPRF(P-256, SHA-256) protocol layer in
# src/crypto/p256/p256.c (modes OPRF 0x00 + VOPRF 0x01, single-element): the
# DeriveKeyPair / Blind / BlindEvaluate / Finalize flow and the VOPRF DLEQ
# proof (ComputeComposites + GenerateProof/VerifyProof).
#
# STRUCTURAL / NEGATIVE leg, 4 assertions: (1) derive_key deterministic +
# mode-separated (the mode byte enters via the HashToScalar DST); (2) the
# §3.3.1 identity blind/evaluate/finalize == the server-side direct Evaluate;
# (3) VOPRF prove->verify accepts, and tampered c / s / eval element /
# wrong-mode context each reject; (4) a DLEQ proof under the wrong key
# rejects, and zero / >= n blinds are rejected.
#
# NOTE: the BYTE-exactness gate is the 4 RFC 9497 A.3.1/A.3.2 appendix
# vectors run through BOTH §3.13 halves (tools/vectors/p256_oprf.json +
# `determ test-c99-vectors`); this wrapper pins the protocol properties
# those accept-side vectors cannot express.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 RFC 9497 OPRF(P-256, SHA-256) protocol layer (§3.9b) ==="
OUT=$($DETERM test-p256-oprf-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: p256-oprf-c99 protocol self-consistency + DLEQ reject paths held"; then
  echo ""
  echo "  PASS: test_p256_oprf_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_p256_oprf_c99 (assertion failure or missing summary marker)"
  exit 1
fi
