#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.23c — the C99 RingCT SPEND-STATEMENT composition over NIST P-256
# (src/crypto/ringsig/ringct_spend.c), the input-unlinkability increment 3 (LIBRARY-only,
# ZERO consensus touch). It stitches the shipped privacy layers into ONE end-to-end
# confidential + unlinkable spend proof: §3.23b CLSAG (input membership + balance, amount-
# on-H, key-image nullifier) -> a §3.23c commitment-TRANSPOSITION proof (the amount-on-H
# <-> amount-on-G bridge — a Schnorr AND-proof with a shared value response) -> the §3.22c
# DCT1 bundle (range + balance over the outputs, amount-on-G). The transpose proof is the
# only new crypto; CLSAG + DCT1 are reused. Built on the PUBLIC P-256 + pedersen APIs (no
# new hardness assumption; soundness = P-256 ECDLP + the ROM). Deterministic.
#
# Assertions: the transpose proof (prove->verify + the DUAL-ORACLE byte-freeze vs the
# INDEPENDENT Python reference tools/verify_ringct_spend.py + a wrong-amount reject); and the
# full spend verifier — ACCEPT the honest CLSAG->transpose->DCT1 spend, REJECT a tamper of
# ANY layer (CLSAG / transpose / bundle), a wrong pseudo-out, and a wrong message. Two
# independent implementations agreeing on one frozen transpose proof means a divergence with
# both green is our bug, not the vector's.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 RingCT spend-statement composition over NIST P-256 (§3.23c) ==="
OUT=$($DETERM test-ringct-spend-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ringct-spend-c99 unit test"; then
  echo ""
  echo "  PASS: test_ringct_spend_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ringct_spend_c99 (assertion failure or missing summary marker)"
  exit 1
fi
