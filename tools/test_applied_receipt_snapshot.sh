#!/usr/bin/env bash
# S-041 lesson extended to the i: (applied_inbound_receipts) state-root
# namespace. The sibling test_applied_receipt_restore.sh proves the dedup
# contract survives bootstrap (re-credit NO-OP) and that the root is
# preserved across ONE restore. This test closes the two angles that one
# does NOT cover:
#
#   (1) Field-for-field i:-set round-trip. After serialize_state ->
#       restore_from_snapshot, every applied (src_shard, tx_hash) pair is
#       present on the restored chain AND non-member pairs stay absent (no
#       over-restore), AND the snapshot JSON array matches the populated set
#       exactly. accumulated_inbound (the A1 supply binding) survives too.
#
#   (2) state_root SENSITIVITY. The i: namespace emits one leaf per applied
#       receipt (chain.cpp build_state_leaves: key "i:"+src_be8+tx_hash).
#       TAMPERING one receipt's tx_hash in the snapshot, or DROPPING a
#       receipt, must MOVE compute_state_root() after restore. A namespace
#       silently omitted from build_state_leaves (the S-037-class bug) would
#       leave the root insensitive to the i: set — this test catches that.
#
# The i: set is populated through the REAL apply path (4 NON-trivial
# inbound_receipts across 2 source shards), so the fixture is a genuine
# apply-built chain, not a JSON splice.
#
# 7 assertions:
#
#   Fixture sanity (1):
#     - all 4 NON-trivial receipts applied (i: set populated, not vacuous)
#
#   Field-for-field serialize (2):
#     - applied_inbound_receipts array has all 4 entries
#     - every i: entry matches an applied (src_shard, tx_hash)
#
#   Field-for-field restore (2):
#     - i: set round-trips exactly (originals present, non-members absent)
#     - accumulated_inbound + bob balance preserved (A1 binding)
#
#   state_root sensitivity (2 across 3 checks):
#     - S-033: compute_state_root preserved through round-trip
#     - tamper: mutated tx_hash diverges state_root
#     - drop: removed receipt diverges state_root + 3 remain in i: set
#
# Run from repo root: bash tools/test_applied_receipt_snapshot.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== i: namespace non-default snapshot round-trip + state_root ==="
OUT=$($DETERM test-applied-receipt-snapshot 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: applied-receipt-snapshot all assertions"; then
  echo ""
  echo "  PASS: applied-receipt-snapshot unit test"
  exit 0
else
  echo ""
  echo "  FAIL: applied-receipt-snapshot had assertion failures"
  exit 1
fi
