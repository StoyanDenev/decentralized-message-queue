#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 3 — the C99 finite-field SCALAR field mod q, the
# subgroup order q=(p-1)/2 of G_q ⊂ Z_p* (p the RFC 3526 MODP-3072 safe prime). This is
# the exponent/challenge field the §3.20 Bulletproofs IPA / range proof operate in:
# determ_ff_scalar_add/mul/inv/reduce + determ_ff_hash_to_scalar (Fiat-Shamir challenge
# map). Same portable 32-bit-limb CIOS Montgomery bignum as the group ops, one context
# per modulus (p for elements, q for scalars). NOT constant-time (owner-gated).
#
# 5 assertions: (1) add commutative + small sum; (2) mul small product + a>=q reject;
# (3) inv roundtrip a*inv(a)==1 + inv(0)/inv(>=q) reject; (4) reduce >=q -> <q +
# idempotent; (5) hash_to_scalar deterministic + <q + distinct msgs differ. The byte-
# exact KAT vs the INDEPENDENT Python reference (tools/verify_ff_scalar.py, native
# bignums) is the §3.13 dual-oracle gate, wired both halves over
# tools/vectors/ff_scalar.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 finite-field scalar field mod q (§3.20 inc.3) ==="
OUT=$($DETERM test-ff-scalar-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-scalar-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_scalar_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_scalar_c99 (assertion failure or missing summary marker)"
  exit 1
fi
