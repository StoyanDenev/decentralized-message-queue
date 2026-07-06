#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.22 — the DCT1 confidential-transfer proof bundle (P-256):
# a serialized, fail-closed-verifiable composition of the shipped §3.19 primitives
# (input/output Pedersen commitments + ONE aggregated Bulletproofs range proof
# over the m outputs + a balance/excess proof). verify == range (each output in
# [0,2^n)) AND balance (Sum(v_in) = Sum(v_out) + fee); the excess E is recomputed
# by the verifier from C_in/C_out/fee, never carried. Additive — no new hardness
# assumption above §3.19 (which test-p256-confidential-tx-c99 already pins). A
# confidential-tx CONSENSUS integration (shielded-pool state model) is a separate,
# owner-gated step.
#
# DUAL ORACLE: the C side (`determ test-p256-ctx-bundle`) builds the bundle from
# fixed inputs, exercises accept / per-region tamper / malformed rejection, and
# pins the bundle's SHA-256; the python side (tools/verify_ctx_bundle.py) rebuilds
# the SAME bundle byte-for-byte through an INDEPENDENT composition of the
# verify_pedersen + verify_bp_agg_rangeproof + verify_p256_balance oracles.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

rc=0
echo "=== DCT1 confidential-transfer bundle — C side (determ test-p256-ctx-bundle) ==="
OUT=$($DETERM test-p256-ctx-bundle 2>&1)
echo "$OUT"
if ! echo "$OUT" | tail -2 | grep -q "PASS: p256-ctx-bundle unit test"; then
  echo "  FAIL: p256-ctx-bundle C-side assertions"; rc=1
fi

echo ""
echo "=== DCT1 confidential-transfer bundle — python oracle (verify_ctx_bundle.py) ==="
if python tools/verify_ctx_bundle.py; then :; else
  echo "  FAIL: verify_ctx_bundle.py byte-mismatch"; rc=1
fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: p256-ctx-bundle dual-oracle"; else echo "  FAIL: p256-ctx-bundle had failures"; fi
exit $rc
