#!/usr/bin/env bash
# PQ signature track, increment 1 — the C99 ML-DSA (Dilithium, NIST FIPS 204)
# arithmetic core at src/crypto/mldsa/: modular reduction over Z_q (q=8380417)
# and the negacyclic number-theoretic transform of Z_q[X]/(X^256+1). This is the
# ring machinery ML-DSA does all of its matrix/vector polynomial multiplication
# in; it is built on the C99 SHAKE XOF (test-sha3-c99). ADDITIVE — no in-tree
# signer yet; the full keygen/sign/verify + FIPS 204 byte-KATs are later
# increments. Keccak/NTT are data-independent → naturally constant-time.
#
# Assertions (no external oracle needed — the transform is pinned by internal
# consistency + a fixed KAT): (1) reduce32/caddq/montgomery_reduce compute the
# right residue and stay in the documented bound over a swept grid; (2) NTT
# round-trip invntt_tomont(ntt(a)) == a*2^32 (mod q); (3) the NTT-domain product
# equals the O(n^2) schoolbook negacyclic convolution (the decisive twiddle-exact
# gate); (4) ntt(1) == all-ones (the constant-polynomial KAT). The file corpus
# tools/vectors/mldsa_ntt.json (byte-exact int32 NTT output + schoolbook-checked
# products) additionally gates ntt.c via test-c99-vectors / test_c99_vector_files
# (independent from-scratch reference in tools/verify_mldsa_vectors.py).
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
