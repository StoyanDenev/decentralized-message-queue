#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for cross-shard outbound
# TRANSFER apply (rev.9 B3, source side).
#
# When a TRANSFER's `to` address routes (via `crypto::shard_id_for_address`)
# to a different shard than `my_shard_id`, the sender is debited
# locally (amount + fee) but the receiver is NOT credited here — the
# credit happens on the destination shard via the inbound-receipt
# path (covered by tools/test_cross_shard_receipt_apply.sh).
#
# A1 unitary-balance accounting:
#   - sender.balance -= (amount + fee)
#   - total_fees += fee → ultimately distributed to b.creators
#   - block_outbound += amount → accumulated_outbound_ counter
#   - NO local credit (no rcv.balance bump)
#
# So this shard's live supply decreases by `amount` (not amount+fee)
# because the fee returns to the creator on this shard. The
# accumulated_outbound_ counter accounts for the exact amount that
# "left" so the A1 invariant (expected == live) still holds.
#
# `tools/test_cross_shard_transfer.sh` exercises this end-to-end via
# beacon + 2 shards with the dst-side inbound receipt; this in-process
# test pins the source-side apply semantics in <1s.
#
# 11 assertions in five blocks:
#
#   Outbound TRANSFER (3):
#     - sender debited (amount + fee, fee returns via creator)
#     - dst address NOT credited locally (credit via inbound receipt)
#     - sender nonce++
#
#   A1 accumulated_outbound (1):
#     - counter bumped by exactly `amount` (fee stays in this shard)
#
#   A1 invariant (2):
#     - live supply decreases by `amount` (fee returns via creator)
#     - expected == live post-apply
#
#   Single-shard fallback (3):
#     - is_cross_shard always returns false when shard_count == 1
#     - local credit happens (TRANSFER credits dst locally)
#     - accumulated_outbound unchanged
#
#   Determinism (1):
#     - same outbound TRANSFER on two chains → same state_root
#
# Run from repo root: bash tools/test_cross_shard_outbound_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Cross-shard outbound TRANSFER apply (rev.9 B3 source side) ==="
OUT=$($DETERM test-cross-shard-outbound-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: cross-shard-outbound-apply all assertions"; then
  echo ""
  echo "  PASS: cross-shard-outbound-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: cross-shard-outbound-apply had assertion failures"
  exit 1
fi
