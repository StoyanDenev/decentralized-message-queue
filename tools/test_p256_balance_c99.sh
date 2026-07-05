#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.19 increment 7 — the C99 confidential-tx BALANCE PROOF over NIST
# P-256 (src/crypto/pedersen/balance.c), the FIPS-profile sibling of the §3.20 inc.7
# finite-field balance proof and the amount-conservation half of a confidential
# transaction (the §3.19 inc.5/6 range proofs are the no-inflation half). Proves
# Σv_in = Σv_out + fee without revealing any amount: the excess
# E = Σ C_in − Σ C_out − fee*G (one multi-exponentiation; point subtractions are scalar
# negations (n−1)/(n−fee) in the exponent) is proven to open to zero via a Schnorr PoK
# E = x*H. Built on the PUBLIC §3.19 pedersen + §3.8c/§3.9b P-256 APIs (no change to the
# sealed p256 core). NOT constant-time (owner-gated).
#
# 3 assertions: a balanced tx proves + verifies; an unbalanced tx (one output value
# bumped so the excess gains a G-component) rejects; a tampered proof rejects. The
# byte-exact excess+proof KAT vs the INDEPENDENT Python reference
# (tools/verify_p256_balance.py, own scalar-mult ladder, which also re-verifies each
# proof) is the §3.13 dual-oracle gate, wired both halves over tools/vectors/p256_balance.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 confidential-tx balance proof over NIST P-256 (§3.19 inc.7) ==="
OUT=$($DETERM test-p256-balance-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: p256-balance-c99 unit test"; then
  echo ""
  echo "  PASS: test_p256_balance_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_p256_balance_c99 (assertion failure or missing summary marker)"
  exit 1
fi
