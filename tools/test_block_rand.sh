#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the V8 randomness
# primitives in node/producer.cpp:
#
#   * compute_delay_seed     — Phase-1 inputs commitment
#   * compute_block_rand     — Phase-2 randomness output (after K reveals)
#   * proposer_idx           — BFT-mode designated proposer
#   * required_block_sigs    — committee quorum for MD vs BFT mode
#   * count_round1_aborts    — abort tally used for suspension + BFT escalation
#
# These five functions are the cryptographic core of FA1 (safety),
# FA5 (BFT safety), and FA8 (regional sharding committee selection).
# Every future committee derives from compute_block_rand's output via
# epoch_committee_seed → select_m_creators. A regression here either:
#
#   (a) silently forks randomness across nodes (different committees
#       per node → safety failure at signature gathering), OR
#   (b) lets a producer reorder Phase-2 reveals to bias future selection
#       (FA1 unpredictability violation; would defeat S-020 hybrid).
#
# The 21 assertions cover:
#
#   compute_delay_seed (7):
#     1. determinism
#     2. block_index sensitivity (cross-block monotonic anchor)
#     3. prev_hash sensitivity (chain history anchor)
#     4. tx_root sensitivity (block-content anchor)
#     5. creator_dh_inputs value sensitivity
#     6. creator_dh_inputs ORDER sensitivity (committee-selection-order contract)
#     7. determinism on empty input + distinct-from-non-empty
#
#   compute_block_rand (5):
#     8. determinism
#     9. delay_seed sensitivity
#    10. ordered_secrets value sensitivity
#    11. ordered_secrets ORDER sensitivity (matches Phase-1 order)
#    12. domain separation from compute_delay_seed
#
#   proposer_idx (4):
#    13. determinism
#    14. in-range invariant for k = 1, 2, 3, 6, 9, 100
#    15. returns 0 on empty committee (no modulo-by-zero)
#    16. abort events change output (BFT-retry rotation mechanism)
#
#   required_block_sigs (2):
#    17. MD: returns committee_size for K = 1, 3, 6, 9, 100
#    18. BFT: returns ceil(2K/3) for K = 1, 2, 3, 4, 6, 9, 12
#
#   count_round1_aborts (2):
#    19. empty list returns 0
#    20. filters round-2 out (only round-1 counts for suspension /
#        BFT escalation)
#
# Run from repo root: bash tools/test_block_rand.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== V8 randomness primitives — compute_delay_seed / compute_block_rand / proposer_idx / required_block_sigs / count_round1_aborts ==="
OUT=$($DETERM test-block-rand 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-rand all assertions"; then
  echo ""
  echo "  PASS: block-rand unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-rand had assertion failures"
  exit 1
fi
