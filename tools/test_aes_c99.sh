#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.5 — the complete C99 AES-256-GCM AEAD at
# src/crypto/aes/ (AES-256 block FIPS-197 + GHASH over GF(2^128) + the GCM mode,
# NIST SP 800-38D). This is the AEAD the wallet keyfile envelope (S-004) uses.
#
# CONSTANT-TIME: GHASH is branchless, and the AES S-box is computed arithmetically
# (a branchless GF(2^8) inverse via a fixed x^254 addition chain + the affine map),
# so there is no key-dependent table lookup -> no cache-timing channel. §3.5 is now
# complete (byte-correctness + CT); this remains an additive validated module not
# yet wired into the S-004 call site.
#
# 9 assertions: (0) the constant-time S-box exhaustively equals the canonical
# FIPS-197 table over all 256 inputs; (1) AES-256 encrypt vs the FIPS-197 Appendix
# C.3 KAT; (2) AES-256 block byte-equal vs OpenSSL EVP_aes_256_ecb over 256 fuzzed
# pairs; (3) the full AES-256-GCM (ciphertext AND tag) byte-equal vs OpenSSL
# EVP_aes_256_gcm over a (plaintext,aad)-length grid -- the §Q9 gate; (4) GCM
# decrypt round-trip + tamper rejection (tag + ciphertext).
#
# Run from repo root: bash tools/test_aes_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# Minix §6 OpenSSL split: this oracle subcommand lives in the standalone
# determ-cryptotest binary (the daemon links zero OpenSSL).
if [ -z "${DETERM_CRYPTOTEST:-}" ]; then
  echo "  FAIL: determ-cryptotest binary not found (build the determ-cryptotest target or set DETERM_CRYPTOTEST_BIN)"
  exit 1
fi

echo "=== C99 AES-256 (FIPS-197) vs OpenSSL EVP_aes_256_ecb + the FIPS-197 KAT ==="
OUT=$($DETERM_CRYPTOTEST test-aes-c99 2>&1)
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
