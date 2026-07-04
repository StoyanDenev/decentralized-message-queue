#!/usr/bin/env bash
# PQ signature track, increment 1 — the C99 ML-DSA (Dilithium, NIST FIPS 204)
# arithmetic core at src/crypto/mldsa/: modular reduction over Z_q (q=8380417)
# and the negacyclic number-theoretic transform of Z_q[X]/(X^256+1). This is the
# ring machinery ML-DSA does all of its matrix/vector polynomial multiplication
# in; it is built on the C99 SHAKE XOF (test-sha3-c99). ADDITIVE — no in-tree
# signer yet; the full keygen/sign/verify + FIPS 204 byte-KATs are later
# increments. Keccak/NTT are data-independent → naturally constant-time.
#
# Assertions (no external oracle needed): (1) reduce32/caddq/montgomery_reduce
# residue + documented bound over a swept grid; (2) NTT round-trip
# invntt_tomont(ntt(a)) == a*2^32 (mod q); (3) the NTT-domain product equals the
# O(n^2) schoolbook negacyclic convolution (the decisive twiddle-exact gate);
# (4) ntt(1)==all-ones + (4b) the INDEPENDENT direct-DFT oracle ntt(X)[j] ==
# root^(2*brv8(j)+1) — a closed-form root evaluation reusing neither the zetas
# table nor the butterfly, so a symmetric zeta-ordering bug (invisible to the
# round-trip AND the convolution) cannot survive; (5-9) the increment-2 rounding
# layer — power2round/decompose reconstruction+bounds, the use_hint semantic
# round-trip, make_hint's definitional contract, and boundary KATs (both gamma2).
# The file corpus tools/vectors/mldsa_ntt.json additionally gates ntt.c via
# test-c99-vectors / test_c99_vector_files (independent from-scratch reference +
# direct-DFT oracle in tools/verify_mldsa_vectors.py).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 ML-DSA (Dilithium, FIPS 204) NTT/reduce core — self-consistency + KAT ==="
OUT=$($DETERM test-mldsa-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: mldsa-c99 unit test"; then
  echo ""
  echo "  PASS: mldsa-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: mldsa-c99 had assertion failures"
  exit 1
fi
