#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 5 — the C99 single-value Bulletproofs RANGE PROOF
# over Z_p* (src/crypto/ff/ffrangeproof.c), the MODERN-profile confidential-tx amount
# range. Proves a Pedersen-committed value v ∈ [0, 2^n) without revealing v, in
# 2·log2(n)+O(1) group elements: V=g^v·h^gamma; A/S bit-vector commits; t-poly T1/T2;
# the <l,r>=t_hat check compressed by the §3.20 inc.4 IPA over (G_i, h'_i=y^-i·H_i, u).
# Transcript DETERM-FF-BP-RANGE-v1. Built on the §3.20 inc.1-4 primitives. NOT constant-
# time (owner-gated); n kept small (the 3072-bit modexp is ~1700x slower than P-256).
#
# 2 assertions (n=2,4): prove/verify round-trip + out-of-range (v=2^n) + tampered-proof
# + wrong-V all reject. The byte-exact V+proof KAT vs the INDEPENDENT Python reference
# (tools/verify_ff_rangeproof.py, native bignums, which also re-verifies each proof) is
# the §3.13 dual-oracle gate, wired both halves over tools/vectors/ff_rangeproof.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 single-value Bulletproofs range proof over Z_p* (§3.20 inc.5) ==="
OUT=$($DETERM test-ff-rangeproof-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-rangeproof-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_rangeproof_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_rangeproof_c99 (assertion failure or missing summary marker)"
  exit 1
fi
