#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.8c — the from-scratch C99 NIST P-256 (the FIPS-profile
# curve; src/crypto/p256/p256.c: Montgomery field arithmetic, Renes-Costello-
# Batina complete addition, constant-time double-and-add-always ladder) vs the
# OpenSSL EC oracle.
#
# 6 assertions, ORDER LOAD-BEARING: (1) the in-source curve constants
# p/n/b/Gx/Gy are asserted byte-equal against OpenSSL's EC_GROUP (+ a == -3
# mod p) BEFORE any arithmetic is trusted — that gate is what converts the
# hand-transcribed constants into mechanically-verified ones; (2) [k]G
# byte-equal vs OpenSSL over a 12-scalar grid incl. k=1,2 (the §Q9 gate);
# (3) ECDH both-direction symmetry + OpenSSL parity; (4) scalar-mult
# commutativity on a non-generator base; (5) off-curve / bad-prefix / X>=p
# all rejected (and point_mul refuses a bad point); (6) scalar 0 and n
# rejected, [n-1]G == -G (X matches G, Y + Gy == p byte-verified).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# Minix §6 OpenSSL split: this oracle subcommand lives in the standalone
# determ-cryptotest binary (the daemon links zero OpenSSL).
if [ -z "${DETERM_CRYPTOTEST:-}" ]; then
  echo "  FAIL: determ-cryptotest binary not found (build the determ-cryptotest target or set DETERM_CRYPTOTEST_BIN)"
  exit 1
fi

echo "=== C99 NIST P-256 vs OpenSSL EC (§3.8c) ==="
OUT=$($DETERM_CRYPTOTEST test-p256-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: p256-c99 constants + scalar-mult byte-equal vs OpenSSL; reject gates held"; then
  echo ""
  echo "  PASS: test_p256_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_p256_c99 (assertion failure or missing summary marker)"
  exit 1
fi
