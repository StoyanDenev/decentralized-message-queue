#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.19 increment 6 — the C99 AGGREGATED Bulletproofs range
# proof over NIST P-256 (src/crypto/pedersen/rangeproof.c). Proves that m Pedersen-
# committed values EACH lie in [0, 2^n) in ONE proof of size 2*log2(m*n)+O(1) group
# elements, wrapping the inc.4 IPA over the m*n-wide generators. Value j's 2^n slot
# is scaled by z^(2+j); m=1 recovers the single-value proof.
#
# 4 assertions: (1) the proof_len contract (228 + ipa_proof_len(m*n); non-pow2 m*n
# / m*n>256 -> 0); (2) round-trip for (m,n) in {(1,4),(2,4),(4,4),(2,8)}; (3)
# determinism (identical V + proof bytes); (4) soundness — a tampered proof, a wrong
# batch of commitments, AND an out-of-range value anywhere in the batch all reject.
# The byte-exact proof KAT vs the INDEPENDENT Python reference
# (tools/verify_bp_agg_rangeproof.py, whose t0-oracle + round-trip + tamper +
# out-of-range self-tests pass) is the §3.13 dual-oracle gate, wired both halves
# over tools/vectors/bp_agg_rangeproof.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 aggregated Bulletproofs range proof over P-256 (§3.19 inc.6) ==="
OUT=$($DETERM test-bp-agg-rangeproof-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: bp-agg-rangeproof-c99 unit test"; then
  echo ""
  echo "  PASS: test_bp_agg_rangeproof_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_bp_agg_rangeproof_c99 (assertion failure or missing summary marker)"
  exit 1
fi
