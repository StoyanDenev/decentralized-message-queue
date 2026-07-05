#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.19 increment 5 — the C99 Bulletproofs single-value range
# proof over NIST P-256 (src/crypto/pedersen/rangeproof.c). Proves a Pedersen-
# committed value v lies in [0, 2^n) WITHOUT revealing v, in 2*log2(n)+O(1) group
# elements, wrapping the inc.4 inner-product argument. Pure composition over the
# §3.19 inc.1-4 pedersen/IPA primitives + the §3.8c P-256 ops.
#
# 4 assertions: (1) the proof_len contract (228 + ipa_proof_len(n); non-power-of-2
# / n>64 -> 0); (2) round-trip — prove -> verify accepts for n in {4,8,16}; (3)
# determinism (prove twice yields identical V + proof bytes); (4) soundness — a
# tampered proof, a wrong commitment, and an out-of-range v all reject. The byte-
# exact proof KAT vs the INDEPENDENT Python reference (tools/verify_bp_rangeproof.py,
# whose t0-oracle + round-trip + tamper + out-of-range self-tests pass) is the
# §3.13 dual-oracle gate, wired both halves over tools/vectors/bp_rangeproof.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Bulletproofs single-value range proof over P-256 (§3.19 inc.5) ==="
OUT=$($DETERM test-bp-rangeproof-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_bp_ipa_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: bp-rangeproof-c99 unit test"; then
  echo ""
  echo "  PASS: test_bp_rangeproof_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_bp_rangeproof_c99 (assertion failure or missing summary marker)"
  exit 1
fi
