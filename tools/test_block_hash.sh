#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Block::signing_bytes()
# and Block::compute_hash() — the FA1 chain-anchor identity.
#
# compute_hash is the function whose output becomes prev_hash on every
# subsequent block. It binds EVERY consensus-relevant field of the
# block (including Phase-2-reveal fields and apply-time-recomputed
# fields like state_root). signing_bytes is the underlying SHA-256
# digest; compute_hash extends signing_bytes by binding in the K-of-K
# block sigs themselves.
#
# Unlike compute_block_digest (the Phase-2 sign target, tested in
# test_block_digest.sh), compute_hash includes:
#   * the Phase-2-reveal fields (delay_output, creator_dh_secrets,
#     cumulative_rand)
#   * the S-030 D2 fields (abort_events event_hashes,
#     equivocation_events, timestamp, cross_shard_receipts,
#     inbound_receipts) — these vary across digest-shared blocks
#     but their inclusion in compute_hash means the actual block
#     IDENTITY is distinct.
#   * The K-of-K creator_block_sigs themselves.
#
# Locks in 16 assertions covering:
#
#   Determinism + purity (3):
#     1. compute_hash() deterministic
#     2. signing_bytes() pure (100 calls match)
#     3. signing_bytes() returns exactly 32 bytes
#
#   Field-sensitivity (5):
#     4. timestamp sensitivity
#     5. delay_output sensitivity (Phase-2-reveal)
#     6. creator_dh_secrets sensitivity (Phase-2-reveal)
#     7. cumulative_rand sensitivity
#     8. creator_block_sigs sensitivity (K-of-K committee sigs;
#        signing_bytes doesn't cover them but compute_hash does)
#
#   Zero-skip backward-compat (S-033 + R4 Phase 3) (5):
#     9. partner_subset_hash zero == default (preserves byte-identical
#        hashes for pre-R4 / non-merged blocks)
#    10. partner_subset_hash non-zero changes hash
#    11. state_root zero == default (preserves byte-identical hashes
#        for pre-S-033 blocks)
#    12. state_root non-zero changes hash
#    13. partner_subset_hash and state_root contribute independently
#        (neither's contribution masks the other's)
#
#   Order sensitivity + cross-field invariants (3):
#    14. creators[] ORDER sensitivity (committee-selection-order
#        invariant — pairs with test_block_rand.sh assertion #6)
#    15. equivocation_events change hash even when same-digest holds
#        (S-030 D2 mitigation at chain-anchor level — two same-digest
#        blocks differing in equivocation_events have different hashes)
#    16. abort_events event_hash bound into block hash
#
# Run from repo root: bash tools/test_block_hash.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Block::signing_bytes() + Block::compute_hash() — FA1 chain-anchor identity ==="
OUT=$($DETERM test-block-hash 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-hash all assertions"; then
  echo ""
  echo "  PASS: block-hash unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-hash had assertion failures"
  exit 1
fi
