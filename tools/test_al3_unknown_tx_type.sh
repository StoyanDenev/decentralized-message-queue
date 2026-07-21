#!/usr/bin/env bash
# AL-3 (AuditLayerSoundness) — check_transactions' `default:` unknown-tx-type
# fail-close, a HIGH gate-gap in docs/proofs/ProofClaimGateTraceability.md.
#
# The TxType enum is 0..17, but Transaction::from_json casts any int straight
# into the uint8_t-backed enum with NO range check (src/chain/block.cpp), so an
# out-of-range discriminator (e.g. 99) decodes cleanly off the wire and reaches
# the type switch; the ONLY thing between an unrecognized type and a silently
# accepted-then-skipped transaction is the `default:` reject in
# src/node/validator.cpp ("unknown tx type ... (fail-closed)"). Before that
# reject existed, an unknown type passed validation and no-op'd at apply,
# diverging the validator's nonce simulation from apply (the W-1/S-039 hazard).
#
# The subcommand drives check_transactions in isolation via the public
# check_transactions_for_test seam (the check reads only b.transactions — no
# committee/block-sig machinery). Both-legs design: a KNOWN type (TRANSFER)
# reaches the switch and does NOT hit `default:`; out-of-range types (99, 255)
# do, and the SPECIFIC "unknown tx type" message proves the switch was reached
# (only `default:` emits it), not a generic pre-switch failure.
#
# Falsify-on-mutant (executed, reverted): replacing the `default:` return with
# `break;` (src/node/validator.cpp:1352) drops the unknown-type tx through the
# switch → accept; all three unknown-type legs flip RED while the control stays
# GREEN.
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_al3_unknown_tx_type.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== AL-3: check_transactions default: unknown-tx-type fail-close ==="
OUT=$("$DETERM" test-al3-unknown-tx-type 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-al3-unknown-tx-type"; then
  echo "  PASS: test_al3_unknown_tx_type"
  exit 0
else
  echo "  FAIL: test_al3_unknown_tx_type (exit $rc)"
  exit 1
fi
