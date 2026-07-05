#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.20 increment 4 — the C99 Bulletproofs inner-product argument
# (IPA) over Z_p* (src/crypto/ff/ffipa.c), the MODERN-profile (large-prime) core of the
# range-proof track. Proves knowledge of vectors a, b with P = Π g_i^{a_i}·Π h_i^{b_i}·
# u^{<a,b>} mod p in 2·log2(n) group elements + 2 scalars, deterministic Fiat-Shamir.
# Built on the §3.20 group ops (determ_ff_msm/_gen) + scalar field (§3.20 inc.3).
# NOT constant-time (owner-gated); n kept small (the 3072-bit modexp is ~1700x slower
# than the P-256 IPA).
#
# 3 assertions (n in {1,2,4}): commit/prove/verify round-trip + proof-length + soundness
# (a wrong commitment P and a tampered proof both reject). The byte-exact commit/proof
# KAT vs the INDEPENDENT Python reference (tools/verify_ff_ipa.py, native bignums, which
# also re-verifies each proof) is the §3.13 dual-oracle gate, wired both halves over
# tools/vectors/ff_ipa.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Bulletproofs IPA over Z_p* (§3.20 inc.4) ==="
OUT=$($DETERM test-ff-ipa-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ff-ipa-c99 unit test"; then
  echo ""
  echo "  PASS: test_ff_ipa_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ff_ipa_c99 (assertion failure or missing summary marker)"
  exit 1
fi
