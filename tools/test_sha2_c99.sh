#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.1 — the first vendored primitive of the
# libsodium-free C99 crypto stack: SHA-256 / SHA-512 (FIPS 180-4) in portable C99
# at src/crypto/sha2/. SHA-2 is the foundation the rest of the stack builds on
# (RFC 8032 Ed25519 + RFC 9591 FROST H1..H5 are SHA-512-based), so it unblocks
# the v2.10 work.
#
# Covers the C99 SHA-2 hash/MAC/KDF family (SHA-256/512 + HMAC + HKDF [§3.1] +
# PBKDF2 [§3.8b]), 18 assertions: (1) byte-equal cross-validation of C99 SHA-256 +
# SHA-512 against the OpenSSL backend over EVERY message length 0..300 (single-
# block, multi-block, both padding edges — the §Q9 gate, no transcribed digest),
# (2) NIST FIPS 180-4 KATs for SHA-256/512 of "abc" and "", (3) a 1 MiB message,
# (4) HMAC-SHA-256/512 vs OpenSSL HMAC() over a (key,msg)-length grid incl. the
# key>block hashing path, (5) HKDF-SHA-256 vs the RFC 5869 Test Case 1 + 3 KATs,
# (6) PBKDF2-HMAC-SHA-256 vs OpenSSL PKCS5_PBKDF2_HMAC over a grid + a KAT. The
# module is additive — not wired into any call site yet.
#
# Run from repo root: bash tools/test_sha2_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 SHA-2 (FIPS 180-4) vs OpenSSL backend + NIST KATs ==="
OUT=$($DETERM test-sha2-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: sha2-c99 all cross-validation + NIST/RFC KATs matched"; then
  echo ""
  echo "  PASS: sha2-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: sha2-c99 had assertion failures"
  exit 1
fi
