#!/usr/bin/env bash
# S-035 Option 1 seed — applied_inbound_receipts dedup-set survives
# snapshot serialize / restore. This is the cross-shard
# exactly-once-credit guarantee under fast-sync bootstrap.
#
# Without persistence, a node that bootstraps from a snapshot would
# lose the dedup state. Any cross-shard receipt re-gossiped after
# bootstrap could then be re-credited, forging a double-credit
# attack on the destination shard's balances.
#
# The S-033 state_root binding through the `i:`-namespace of
# compute_state_root means a dedup-set divergence between source +
# restored chain would surface as a state_root mismatch. This test
# verifies the round-trip preservation of both the set AND the
# resulting state_root.
#
# 9 assertions:
#
#   Pre-restore baseline (2):
#     - bob credited 10+20+30 = 60 from 3 distinct receipts
#     - all 3 (src_shard, tx_hash) pairs in dedup set via
#       inbound_receipt_applied predicate
#
#   Snapshot serialize + restore (3):
#     - bob's balance preserved after restore
#     - snapshot JSON has applied_inbound_receipts array with 3 entries
#     - inbound_receipt_applied predicate true post-restore (all 3)
#
#   Critical: dedup contract survives bootstrap (1):
#     - duplicate receipt (same src_shard, tx_hash) on restored chain
#       silently skipped — exactly-once preserved across bootstrap
#
#   Fresh receipt post-restore (1):
#     - new (src_shard, tx_hash) credits normally
#
#   S-033 state_root preservation (1):
#     - compute_state_root identical pre- and post-restore (i:-namespace
#       contributes to root, so dedup-set divergence would diverge root)
#
#   A1 invariant (1):
#     - accumulated_inbound counter preserved (60); expected == live
#
# Run from repo root: bash tools/test_applied_receipt_restore.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== applied_inbound_receipts dedup survives snapshot restore ==="
OUT=$($DETERM test-applied-receipt-restore 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: applied-receipt-restore all assertions"; then
  echo ""
  echo "  PASS: applied-receipt-restore unit test"
  exit 0
else
  echo ""
  echo "  FAIL: applied-receipt-restore had assertion failures"
  exit 1
fi
