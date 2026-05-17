#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for cross-shard inbound
# receipt apply (rev.9 B3.4). Each `CrossShardReceipt` baked into a
# finalized block credits `to` with `amount` (sender debit + fee
# already happened on the source shard).
#
# The applied_inbound_receipts_ set is keyed by (src_shard, tx_hash):
# if a receipt with this pair has been applied before, the dedup
# check skips re-credit. This is the **exactly-once-credit guarantee**
# under chain replay or duplicate gossip — the validator rejects
# duplicates before they reach apply, but the apply-level guard makes
# replay safe.
#
# A1 unitary-supply: every successful receipt credit bumps
# `accumulated_inbound_` by the receipt amount. The A1 invariant
# (expected_total == live_total_supply) holds after apply because
# accumulated_inbound_ accounts exactly for the new value entering
# this shard's supply.
#
# Network-level: `tools/test_cross_shard_transfer.sh` exercises this
# end-to-end via 3-node clusters with beacon + 2 shards. This
# in-process test pins the apply-side semantics in <1s.
#
# Implementation note: every block sets `b.creators = {"alice"}` so
# fees route back and A1 stays balanced (the standard apply-test
# gotcha).
#
# ~12 assertions in seven blocks:
#
#   Basic credit (1):
#     - inbound receipt credits `to` account
#
#   A1 accumulated_inbound (2):
#     - counter bumped by exact amount
#     - invariant holds (expected == live)
#
#   Dedup contract (3):
#     - duplicate (src_shard, tx_hash) NOT re-credited
#     - accumulated_inbound NOT double-counted
#     - setup credited correctly
#
#   Multiple distinct receipts in single block (2):
#     - bob credited by sum of all receipts
#     - accumulated_inbound += sum
#
#   Receipt to non-existent domain (1):
#     - new account entry created with credit
#
#   inbound_receipt_applied predicate (2):
#     - false before apply
#     - true after apply
#
#   Determinism (1):
#     - two chains see same receipt → same state_root
#
# Run from repo root: bash tools/test_cross_shard_receipt_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Cross-shard inbound receipt apply (rev.9 B3.4, dedup, A1) ==="
OUT=$($DETERM test-cross-shard-receipt-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: cross-shard-receipt-apply all assertions"; then
  echo ""
  echo "  PASS: cross-shard-receipt-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: cross-shard-receipt-apply had assertion failures"
  exit 1
fi
