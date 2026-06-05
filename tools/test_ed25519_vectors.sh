#!/usr/bin/env bash
# v2.10 Phase-0 / CRYPTO-C99-SPEC §Q7 "validate before you vendor".
#
# Pins the daemon's Ed25519 signature backend against the CANONICAL RFC 8032
# §7.1 known-answer vectors (TEST 1, TEST 2, TEST 3, TEST SHA(abc)). Today the
# backend is OpenSSL EVP_PKEY_ED25519 (the only shipped signature impl); per the
# V210ImplementationRoadmap P0 decision it will be replaced with a libsodium-free
# C99 ref10 implementation. RFC 8032 Ed25519 signing is DETERMINISTIC, so the
# signature bytes are themselves a KAT — this test is the independent oracle the
# ref10 backend MUST reproduce byte-for-byte (the §Q9 cross-validation gate).
#
# 24 assertions across 4 vectors x 6 checks (pubkey-from-seed matches the
# published RFC 8032 public key, signature verifies, signing is deterministic,
# tampered-sig-reject, wrong-pubkey-reject, all-zero-sig-reject). Signatures are
# not embedded as literals: Ed25519 (RFC 8032) is deterministic, so verify +
# reproducibility pin the exact canonical bytes without error-prone transcription.
#
# Run from repo root: bash tools/test_ed25519_vectors.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Ed25519 RFC 8032 §7.1 known-answer vectors (C99 ref10 cross-val oracle) ==="
OUT=$($DETERM test-ed25519-vectors 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ed25519-vectors all RFC 8032 KATs matched"; then
  echo ""
  echo "  PASS: ed25519-vectors unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ed25519-vectors had assertion failures"
  exit 1
fi
