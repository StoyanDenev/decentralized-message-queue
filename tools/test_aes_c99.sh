#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.5 — the complete C99 AES-256-GCM AEAD at
# src/crypto/aes/ (AES-256 block FIPS-197 + GHASH over GF(2^128) + the GCM mode,
# NIST SP 800-38D). This is the AEAD the wallet keyfile envelope (S-004) uses.
#
# NOTE: GHASH here is branchless/constant-time, but the AES S-box is table-based
# and NOT constant-time (see aes.h). This is an additive validated module; it must
# be CT-hardened (constant-time S-box / AES-NI / BearSSL per the spec) before
# replacing OpenSSL at a secret-key call site.
#
# 6 assertions: (1) AES-256 encrypt vs the FIPS-197 Appendix C.3 KAT; (2) AES-256
# block byte-equal vs OpenSSL EVP_aes_256_ecb over 256 fuzzed pairs; (3) the full
# AES-256-GCM (ciphertext AND tag) byte-equal vs OpenSSL EVP_aes_256_gcm over a
# (plaintext,aad)-length grid -- the §Q9 gate; (4) GCM decrypt round-trip + tamper
# rejection (tag + ciphertext). Additive -- not wired into any call site yet.
#
# Run from repo root: bash tools/test_aes_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 AES-256 (FIPS-197) vs OpenSSL EVP_aes_256_ecb + the FIPS-197 KAT ==="
OUT=$($DETERM test-aes-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: aes-c99 all cross-validation + KATs matched"; then
  echo ""
  echo "  PASS: aes-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: aes-c99 had assertion failures"
  exit 1
fi
