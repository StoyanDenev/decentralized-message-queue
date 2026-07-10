#!/usr/bin/env bash
# S-049 mint guard — the transaction apply path must never let amount+fee
# overflow u64 and mint value from nothing (Bitcoin CVE-2010-5139 class).
#
# The bug: `cost = amount + fee` was computed unchecked at every value-moving
# apply site (TRANSFER/PQ_TRANSFER, SHIELD, STAKE, DAPP_CALL). An attacker
# picks amount ~ 2^64-fee so `cost` wraps to ~0, the `balance < cost` gate
# passes on a near-zero debit, and the recipient is credited the FULL amount
# (recipient credit uses checked_add_u64, which succeeds since amount < 2^64).
# The A1 supply assertion is blind to it — A1 is a mod-2^64 identity and the
# injected discrepancy is exactly a multiple of 2^64.
#
# The fix: compute `cost` with checked_add_u64 and SKIP the tx (no state change)
# on overflow at every site; the validator additionally refuses amount+fee
# overflow fail-closed (authoritative accept-rule); per-block `total_fees`
# accumulation is checked too (throws -> block rejected).
#
# Scenarios (8 assertions):
#   (1) TRANSFER overflow -> recipient not credited, sender not debited, nonce
#       not advanced (tx skipped).
#   (2) Legitimate TRANSFER still applies unchanged (fix byte-invariant).
#   (3) STAKE overflow -> no free stake (locked consensus weight stays 0).
#   (4) SHIELD overflow -> no phantom confidential note.
#   (5) Per-block fee accumulation overflow -> block rejected.
#
# Discovered by the D1 shielded-pool adversarial-audit workflow.
#
# Run from repo root: bash tools/test_value_overflow_mint.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== value-overflow-mint: S-049 apply-path mint guard ==="
OUT=$($DETERM test-value-overflow-mint 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: value-overflow-mint all assertions"; then
  echo ""
  echo "  PASS: value-overflow-mint unit test"
  exit 0
else
  echo ""
  echo "  FAIL: value-overflow-mint had assertion failures"
  exit 1
fi
