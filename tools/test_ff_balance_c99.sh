#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 7 — the C99 confidential-tx BALANCE PROOF over Z_p*
# (src/crypto/ff/ffbalance.c), the amount-conservation half of a confidential transaction
# (the §3.20 inc.5/6 range proofs are the no-inflation half). Proves Σv_in = Σv_out + fee
# without revealing any amount: the excess E = Π C_in · Π C_out^{-1} · g^{-fee} (one
# multi-exponentiation; inverses are scalar negations in the exponent) is proven to open
# to zero via a Schnorr PoK E = h^x. Built on the public §3.20 inc.1-3 primitives. NOT
# constant-time (owner-gated).
#
# 3 assertions: a balanced tx proves + verifies; an unbalanced tx (one output value
# bumped so the excess gains a g-component) rejects; a tampered proof rejects. The
# byte-exact excess+proof KAT vs the INDEPENDENT Python reference
# (tools/verify_ff_balance.py, native bignums, which also re-verifies each proof) is the
# §3.13 dual-oracle gate, wired both halves over tools/vectors/ff_balance.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 confidential-tx balance proof over Z_p* (§3.20 inc.7) ==="
OUT=$($DETERM test-ff-balance-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-balance-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_balance_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_balance_c99 (assertion failure or missing summary marker)"
  exit 1
fi
