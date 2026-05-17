#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `chain::Block`
# default-construction + field accessors + value-preservation.
#
# Block is the central wire structure — every gossip hop transits
# a Block, every chain.json save/load serializes blocks, every
# snapshot tail-header is a Block. The default-construction
# invariants (every field has a safe zero-equivalent default) are
# protocol-critical: partial Block construction during apply paths
# must not expose half-initialized garbage.
#
# Complements:
#   * test-block-roundtrip — full JSON round-trip with every field
#     populated
#   * test-block-hash      — compute_hash + signing_bytes
#   * test-block-digest    — compute_block_digest field coverage
#
# by locking the **default** values of every Block field — the
# state a Block has BEFORE any apply path or JSON load populates
# it. A regression that changed a default would silently shift
# behavior for any code path that constructs a Block and reads
# fields before fully populating it.
#
# 36 assertions in two blocks:
#
#   Default Block (24):
#     - Scalar field defaults (10): index=0, timestamp=0,
#       prev_hash=zero, tx_root=zero, delay_seed=zero,
#       delay_output=zero, consensus_mode=MUTUAL_DISTRUST,
#       bft_proposer="", cumulative_rand=zero
#     - Collection defaults (14): transactions, creators,
#       creator_tx_lists, creator_ed_sigs, creator_dh_inputs,
#       creator_dh_secrets, creator_block_sigs, abort_events,
#       equivocation_events, cross_shard_receipts,
#       inbound_receipts, initial_state — all empty
#     - Zero-skip backward-compat fields (2): state_root +
#       partner_subset_hash both zero (pre-S-033 / pre-R4
#       wire-format defaults that JSON omits when zero)
#
#   Field assignment preservation (12):
#     - transactions[] push_back + per-field readback
#     - creators[] order + values
#     - creator_ed_sigs sized to match + per-sig readback
#     - consensus_mode=BFT + bft_proposer preservation
#     - state_root non-zero value stored exactly (no
#       normalization or truncation)
#     - compute_hash determinism on two default Blocks
#     - compute_hash sensitive to index change (sanity canary)
#
# Run from repo root: bash tools/test_block_accessors.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== chain::Block — default-construction + field accessors + value preservation ==="
OUT=$($DETERM test-block-accessors 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-accessors all assertions"; then
  echo ""
  echo "  PASS: block-accessors unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-accessors had assertion failures"
  exit 1
fi
