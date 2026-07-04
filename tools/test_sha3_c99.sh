#!/usr/bin/env bash
# PQ prerequisite — the libsodium-free C99 SHA-3 / SHAKE (NIST FIPS 202,
# Keccak-f[1600]) at src/crypto/sha3/. The XOF (SHAKE128/256) is the
# eXtendable-Output Function the ML-DSA / Dilithium (FIPS 204) signature track
# expands its public matrix + samples secrets with; SLH-DSA (FIPS 205) uses it
# throughout. Ships the XOF first, KAT-verified, so those schemes build on a
# validated sponge. Keccak is data-independent (naturally constant-time).
#
# Assertions: (1) SHA3-256/512 byte-equal vs OpenSSL EVP_sha3_256/512 over a
# fuzzed length grid crossing the sponge rate boundaries (the §Q9 gate — full
# absorb / pad10*1 / permute); (2) SHAKE128/256 byte-equal vs OpenSSL
# EVP_shake128/256 (DigestFinalXOF) over fuzzed lengths × output sizes including
# output longer than the rate (forces a squeeze-permute); (3) FIPS 202 KATs
# (empty + "abc"); (4) incremental absorb/squeeze == one-shot; (5) rate-boundary
# byte-by-byte absorb == one-shot. Additive — the first consumer is the ML-DSA
# increment. See also tools/verify_sha3_vectors.py (hashlib-oracle corpus).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 SHA-3/SHAKE (FIPS 202) vs OpenSSL EVP_sha3/shake + FIPS 202 KATs ==="
OUT=$($DETERM test-sha3-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: sha3-c99 unit test"; then
  echo ""
  echo "  PASS: sha3-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: sha3-c99 had assertion failures"
  exit 1
fi
