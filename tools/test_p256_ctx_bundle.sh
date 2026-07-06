#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.22 — the DCT1 confidential-transfer proof bundle (P-256):
# a serialized, fail-closed-verifiable composition of the shipped §3.19 primitives
# (input/output Pedersen commitments + ONE aggregated Bulletproofs range proof
# over the m outputs + a balance/excess proof). verify == range (each output in
# [0,2^n)) AND balance (Sum(v_in) = Sum(v_out) + fee); the excess E is recomputed
# by the verifier from C_in/C_out/fee, never carried. Additive — no new hardness
# assumption above §3.19 (which test-p256-confidential-tx-c99 already pins). This
# gate covers the SERIALIZATION layout + accept / per-region tamper / malformed
# rejection. A confidential-tx CONSENSUS integration (shielded-pool state model)
# is a separate, owner-gated step.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DCT1 confidential-transfer bundle (P-256) — serialize + verify ==="
OUT=$($DETERM test-p256-ctx-bundle 2>&1)
echo "$OUT"
if echo "$OUT" | tail -2 | grep -q "PASS: p256-ctx-bundle unit test"; then
  echo ""
  echo "  PASS: p256-ctx-bundle unit test"
  exit 0
else
  echo ""
  echo "  FAIL: p256-ctx-bundle had assertion failures"
  exit 1
fi
