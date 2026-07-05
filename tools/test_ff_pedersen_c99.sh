#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 1 — the C99 finite-field Pedersen commitment
# over the RFC 3526 MODP-3072 prime-order subgroup (src/crypto/ff/ffgroup.c). The
# MODERN-profile "large primes, not curves" backend for confidential-tx amount
# commitments: C = g^v * h^r mod p in G_q ⊂ Z_p*, p the RFC 3526 group-15 safe prime.
# Portable C99 32-bit-limb CIOS Montgomery bignum (no __int128 / intrinsics).
#
# 4 assertions: (1) the nothing-up-my-sleeve H generator (deterministic, non-trivial);
# (2) commit -> verify accept + wrong-v / wrong-r reject; (3) the additive
# homomorphism c1*c2 == commit(v1+v2, r1+r2); (4) input validation (r==0, v>=q, r>=q
# all reject). The byte-exact commit KAT vs the INDEPENDENT Python reference
# (tools/verify_ff_pedersen.py, native bignums, self-checks the safe prime + subgroup)
# is the §3.13 dual-oracle gate, wired both halves over tools/vectors/ff_pedersen.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 finite-field Pedersen over RFC 3526 MODP-3072 (§3.20 inc.1) ==="
OUT=$($DETERM test-ff-pedersen-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-pedersen-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_pedersen_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_pedersen_c99 (assertion failure or missing summary marker)"
  exit 1
fi
