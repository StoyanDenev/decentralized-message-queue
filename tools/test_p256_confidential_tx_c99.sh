#!/usr/bin/env bash
# CRYPTO-C99-SPEC.md §3.19 increment 8 — the END-TO-END confidential-tx COMPOSITION over
# NIST P-256, the FIPS-profile sibling of the §3.20 inc.8 finite-field composition. NOT a
# new primitive: it composes the two shipped halves of a confidential transaction over the
# PUBLIC §3.19 APIs — a per-output inc.5 RANGE proof (the non-negativity / no-overflow
# half) plus the inc.7 BALANCE proof (amount conservation) — into one flow, and pins
# (a) the composition identity V_j == C_out[j] (a range proof's value commitment IS its tx
# output commitment, because both use the base point G and the §3.19 generator H), and
# (b) the division of labour: an INFLATION (Σv_out+fee != Σv_in) is caught by the BALANCE
# proof, an OUT-OF-RANGE output (= 2^n) by that output's RANGE proof. A cross-primitive
# generator mismatch would break the V_j == C_out[j] identity and turn this RED. NOT
# constant-time (owner-gated).
#
# 6 assertions: V_j == C_out[j] identity; every output range proof verifies; the balance
# proof verifies; the honest tx accepts (range AND balance); inflation caught by balance;
# out-of-range caught by range. The independent Python mirror is
# tools/verify_p256_confidential_tx.py (which composes the already-byte-exact inc.5/6/7
# references); no new corpus — the composed bytes are pinned by bp_rangeproof.json /
# bp_agg_rangeproof.json / p256_balance.json.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 end-to-end confidential-tx composition over NIST P-256 (§3.19 inc.8) ==="
OUT=$($DETERM test-p256-confidential-tx-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: p256-confidential-tx-c99 unit test"; then
  echo ""
  echo "  PASS: test_p256_confidential_tx_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_p256_confidential_tx_c99 (assertion failure or missing summary marker)"
  exit 1
fi
