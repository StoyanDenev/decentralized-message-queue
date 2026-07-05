#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 6 — the C99 AGGREGATED Bulletproofs range proof over
# Z_p* (src/crypto/ff/ffrangeproof.c), the MODERN-profile confidential-tx BATCH range.
# Proves that m committed values v_0..v_{m-1} EACH lie in [0, 2^n) in ONE proof of size
# 2·log2(m·n)+O(1) group elements (vs. m separate proofs). Value j's 2^n slot is scaled
# by z^(2+j); m=1 recovers the single-value proof. Transcript DETERM-FF-BP-AGGRANGE-v1.
# Built on the §3.20 inc.1-5 primitives. NOT constant-time (owner-gated); m·n kept small
# (the 3072-bit modexp is ~1700x slower than P-256).
#
# 2 assertions (m·n = 4, 8): agg prove/verify round-trip + one-value-out-of-range +
# tampered-proof + wrong-V all reject. The byte-exact V+proof KAT vs the INDEPENDENT
# Python reference (tools/verify_ff_rangeproof.py emit-agg, native bignums, which also
# re-verifies each proof) is the §3.13 dual-oracle gate, wired both halves over
# tools/vectors/ff_aggrangeproof.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 aggregated Bulletproofs range proof over Z_p* (§3.20 inc.6) ==="
OUT=$($DETERM test-ff-agg-rangeproof-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-agg-rangeproof-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_agg_rangeproof_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_agg_rangeproof_c99 (assertion failure or missing summary marker)"
  exit 1
fi
