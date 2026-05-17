#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Block::to_json /
# Block::from_json full JSON round-trip across the field set.
#
# Block round-trips through JSON at every gossip hop (BLOCK MsgType,
# 4 MB cap), every chain.json save/load (Chain::save / load), and
# every snapshot tail-header save/restore. A field-loss regression
# in either to_json or from_json would silently corrupt the wire
# format. This test complements:
#
#   * test-block-hash       — compute_hash + signing_bytes algebra
#   * test-block-digest     — compute_block_digest signature target
#   * test-wire-types       — individual sub-object types (CrossShard-
#                              Receipt / AbortEvent / EquivocationEvent
#                              / GenesisAlloc) round-trip in isolation
#
# by exercising the Block container itself, with every field path
# populated, including sub-object arrays.
#
# 41 assertions in eleven blocks:
#
#   Minimal block (4): index / prev_hash / timestamp / cumulative_rand
#     round-trip on a block with only required fields populated.
#
#   Block with transactions (3): transactions[] count + per-tx fields
#     preserved; complements test-transaction's per-tx field coverage.
#
#   Committee block (11): creators + creator_tx_lists (incl. empty
#     inner list) + creator_ed_sigs + creator_dh_inputs +
#     creator_dh_secrets + creator_block_sigs + tx_root + delay_seed
#     + delay_output all round-trip preserving value and order.
#
#   BFT-mode block (2): consensus_mode + bft_proposer round-trip.
#
#   Block with aborts (3): abort_events array of AbortEvent
#     sub-objects.
#
#   Block with equivocation (3): equivocation_events array of
#     EquivocationEvent sub-objects.
#
#   Block with cross-shard receipts (4): cross_shard_receipts (V12)
#     + inbound_receipts (V13) arrays.
#
#   Genesis block (4): initial_state array of GenesisAlloc with
#     mixed region tag + empty region (R1 backward-compat).
#
#   Zero-skip fields (6): state_root (S-033 backward-compat) +
#     partner_subset_hash (R4 Phase 3 backward-compat) both
#     OMITTED from JSON when zero, PRESENT when non-zero, and
#     round-trip preserving value.
#
#   compute_hash invariance (1): the CRITICAL invariant — a block's
#     compute_hash is identical before and after a JSON round-trip.
#     Without this, gossiped blocks would have different block_hashes
#     on sender vs receiver, breaking the prev_hash chain.
#
# Run from repo root: bash tools/test_block_roundtrip.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block::to_json / Block::from_json — full field-set round-trip ==="
OUT=$($DETERM test-block-roundtrip 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-roundtrip all assertions"; then
  echo ""
  echo "  PASS: block-roundtrip unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-roundtrip had assertion failures"
  exit 1
fi
