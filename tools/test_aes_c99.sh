#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.5 — the C99 AES-256 block cipher (FIPS-197) at
# src/crypto/aes/, the cipher underlying AES-256-GCM (the AEAD the wallet keyfile
# envelope, S-004, uses). GHASH + the GCM mode land next.
#
# NOTE: this AES uses a table-based S-box and is NOT constant-time (see aes.h). It
# is an additive validated module; it must be CT-hardened (constant-time S-box /
# AES-NI / BearSSL per the spec) before replacing OpenSSL at a secret-key call site.
#
# 2 assertions: (1) AES-256 encrypt vs the FIPS-197 Appendix C.3 known-answer
# vector; (2) byte-equal cross-validation against OpenSSL EVP_aes_256_ecb over 256
# fuzzed (key, block) pairs (the §Q9 gate). Additive -- not wired into any call site.
#
# Run from repo root: bash tools/test_aes_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 AES-256 (FIPS-197) vs OpenSSL EVP_aes_256_ecb + the FIPS-197 KAT ==="
OUT=$($DETERM test-aes-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: aes-c99 all cross-validation + FIPS-197 KAT matched"; then
  echo ""
  echo "  PASS: aes-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: aes-c99 had assertion failures"
  exit 1
fi
