#!/usr/bin/env bash
# BlockIngress MEM-inbound-receipt-pool-unbounded — pending_inbound_receipts_ is
# capped at MAX_PENDING_INBOUND_RECEIPTS against a gossiped-receipt-bundle flood.
#
# Node::on_cross_shard_receipt_bundle admits every receipt of an UNAUTHENTICATED
# CROSS_SHARD_RECEIPT_BUNDLE into pending_inbound_receipts_ (keyed on
# (src_shard,tx_hash)); source-side K-of-K verification is deferred to B3.4, and
# a junk receipt (random tx_hash matching no real cross-shard TRANSFER) is never
# baked into a valid block, so the credit-erase never prunes it. A peer flooding
# distinct random tx_hashes grows the pool without bound = remote memory-
# exhaustion DoS. The fix caps the pool (drop-newest) at the S-008 mempool order.
#
# In-process SHARD-role node harness drives the handler:
#   CONTROL: a 5-receipt bundle is admitted in full (under cap);
#   FLOOD:   CAP+100 distinct receipts -> pool caps at MAX_PENDING_INBOUND_RECEIPTS;
#   second flood keeps the pool AT the cap (idempotent ceiling).
# Falsify-on-mutant (neutralize the cap): the FLOOD asserts flip while the CONTROL
# stays green. The complete fix that makes the cap non-lossy (B3.4 source-side
# receipt auth) is a consensus change, owner-gated.
#
# Run from repo root: bash tools/test_inbound_receipt_cap.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== inbound-receipt-cap — pending_inbound_receipts_ bounded against a gossip flood ==="
OUT=$($DETERM test-inbound-receipt-cap 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-inbound-receipt-cap"; then
  echo ""
  echo "  PASS: inbound-receipt-cap unit test"
  exit 0
else
  echo ""
  echo "  FAIL: inbound-receipt-cap had assertion failures"
  exit 1
fi
