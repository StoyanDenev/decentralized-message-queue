#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.9b groundwork — the P-256 scalar-field (mod n) arithmetic
# and the RFC 9380 hash-to-curve suite P256_XMD:SHA-256_SSWU_RO_ (simplified
# SSWU, Z = -10, no isogeny) in src/crypto/p256/p256.c.
#
# 9 assertions: (1) scalar_mul_mod_n == OpenSSL BN_mod_mul over a 10-pair
# grid; (2) scalar_inv_mod_n == BN_mod_inverse AND a*a^-1 == 1 through our own
# mul; (3) zero / >= n rejected on both entry points; (4) expand_message_xmd
# deterministic + outlen domain-separation (len_in_bytes is bound into b0, so
# a 32B output must NOT be the 96B output's prefix) + bounds rejects;
# (5) hash_to_curve always on-curve + deterministic over a 16-msg grid;
# (6) DST-sensitivity; (7) point_add == OpenSSL EC_POINT_add +
# the [a]G+[b]G == [(a+b) mod n]G identity + P+(-P) -> -1; (8) hash_to_scalar
# < n / deterministic / DST-sensitive (the RFC 9497 HashToScalar shape). NOTE: structural gates only here — the RFC 9380
# appendix BYTE vectors live in tools/vectors/p256_h2c.json and are enforced
# by both §3.13 gate halves (test_c99_vector_files.sh + determ
# test-c99-vectors); a wrong SSWU constant passes structure but fails there.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 P-256 mod-n + hash-to-curve (§3.9b groundwork) ==="
OUT=$($DETERM test-p256-h2c-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: p256-h2c-c99 mod-n ops == OpenSSL BIGNUM; hash-to-curve structural contract held"; then
  echo ""
  echo "  PASS: test_p256_h2c_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_p256_h2c_c99 (assertion failure or missing summary marker)"
  exit 1
fi
