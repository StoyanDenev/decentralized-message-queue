#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the random-state
# primitives in crypto/random.cpp:
#
#   * compute_dh_output       — fold 2 DH shares (legacy)
#   * compute_dh_output_m     — fold M DH shares (current path)
#   * update_random_state     — chain the per-block random state
#   * compute_abort_hash      — abort-dependent offset (S5 anti-cartel)
#   * chain_abort_hash        — fold abort hashes across rounds
#   * genesis_random_state    — derive block-0 random state
#
# These are foundation-layer to V8 (block randomness) and the S5
# anti-cartel defense — committee re-selection after an abort must
# depend on the abort details (who aborted, when) so an attacker
# can't pre-plan abort sequences to navigate into a favorable
# committee. test-block-rand covers the higher-level
# compute_delay_seed / compute_block_rand; this fills in the layer
# below.
#
# A regression would either silently fork randomness across nodes
# (different folds → different committees) or weaken the anti-cartel
# defense (abort_hash that doesn't include the aborting node would
# let an attacker plan the post-abort selection).
#
# 27 assertions across six blocks:
#
#   compute_dh_output (2-share fold) (3):
#     1. determinism
#     2. argument-order matters (concat-sensitive)
#     3. per-share sensitivity
#
#   compute_dh_output_m (M-share fold) (5):
#     4. determinism
#     5. empty input deterministic
#     6. single-share fold deterministic
#     7. share ORDER sensitivity (committee-selection-order contract)
#     8. per-share sensitivity for each slot
#
#   update_random_state (3):
#     9.  determinism
#    10.  per-input sensitivity (prev_state + dh_output)
#    11.  argument order matters
#
#   compute_abort_hash (5):
#    12.  determinism
#    13.  round sensitivity
#    14.  aborting_node sensitivity (S5 anti-cartel defense)
#    15.  timestamp sensitivity
#    16.  random_state sensitivity
#
#   chain_abort_hash (3):
#    17.  determinism
#    18.  prev_abort_hash sensitivity
#    19.  aborting_node sensitivity
#
#   genesis_random_state (3):
#    20.  determinism
#    21.  seed sensitivity
#    22.  non-zero output on patterned seed
#
# Run from repo root: bash tools/test_random_state.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Random-state primitives (compute_dh_output / update_random_state / compute_abort_hash / chain_abort_hash / genesis_random_state) ==="
OUT=$($DETERM test-random-state 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: random-state all assertions"; then
  echo ""
  echo "  PASS: random-state unit test"
  exit 0
else
  echo ""
  echo "  FAIL: random-state had assertion failures"
  exit 1
fi
