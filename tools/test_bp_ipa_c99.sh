#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.19 increment 4 — the C99 Bulletproofs inner-product
# argument over NIST P-256 (src/crypto/pedersen/ipa.c). Proves knowledge of a,b
# with P = <a,g> + <b,h> + <a,b>*u in 2*log2(n) points + 2 scalars; non-interactive
# via a deterministic Fiat-Shamir transcript. Pure composition over the §3.19
# pedersen_gen/pedersen_msm + the §3.8c P-256 primitives.
#
# 4 assertions: (1) the proof_len contract (66*log2(n)+64; non-power-of-2 / n>MAX
# -> 0); (2) round-trip — commit -> prove -> verify accepts for n in {1,2,4,8};
# (3) determinism (prove twice yields identical bytes); (4) soundness — a tampered
# proof and a wrong commitment both reject. The byte-exact proof KAT vs the
# INDEPENDENT Python reference (tools/verify_bp_ipa.py, whose per-round-invariant
# + round-trip + soundness self-tests pass) is the §3.13 dual-oracle gate, wired
# both halves over tools/vectors/bp_ipa.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Bulletproofs inner-product argument over P-256 (§3.19 inc.4) ==="
OUT=$($DETERM test-bp-ipa-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: bp-ipa-c99 unit test"; then
  echo ""
  echo "  PASS: test_bp_ipa_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_bp_ipa_c99 (assertion failure or missing summary marker)"
  exit 1
fi
