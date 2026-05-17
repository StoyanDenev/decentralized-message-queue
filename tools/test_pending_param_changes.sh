#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `Chain::stage_param_change`
# + `Chain::pending_param_changes()`. The A5 Phase 2 governance staging
# primitive: a validated PARAM_CHANGE tx stages a (name, value) pair
# for activation at a future block via `effective_height`. At each
# `apply_transactions(b)`, pending entries with effective_height <=
# b.index are activated (the named chain field is mutated, after which
# the block applies under the new value).
#
# The activation order is deterministic across replays because:
#   (a) the pending map is keyed by effective_height (std::map = sorted
#       ascending iteration);
#   (b) within a single height bucket, vector push_back preserves
#       insertion order — so two PARAM_CHANGE txs in different blocks
#       both targeting the same effective_height activate in the order
#       their blocks were applied;
#   (c) the entire pending map round-trips through
#       Chain::serialize_state / restore_from_snapshot.
#
# This test pins the read-write surface in <1s without exercising the
# apply path (which involves Transaction sig verification + the larger
# apply_transactions state machine — those are covered end-to-end by
# `tools/test_governance.sh`).
#
# 13 assertions in seven blocks:
#
#   Default state (1):
#     - default Chain: pending_param_changes empty
#
#   Single stage (3):
#     - 1 entry at height 100: map size 1, key 100 present
#     - inner bucket size = 1
#     - name + value preserved byte-for-byte
#
#   Multi-stage at SAME height (2):
#     - 2 entries at height 200: bucket size 2
#     - insertion order preserved (vector push_back contract)
#
#   Multi-stage at DIFFERENT heights (2):
#     - 3 heights → 3 map entries
#     - std::map sorted-by-key iteration → heights ascending
#
#   Edge values (2):
#     - empty value vector preserved (delete-param sentinel form)
#     - 256-byte value round-trips intact
#
#   Chain independence (1):
#     - stage on one Chain doesn't leak to another (no static state)
#
# Run from repo root: bash tools/test_pending_param_changes.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::stage_param_change + pending_param_changes() (A5 governance staging) ==="
OUT=$($DETERM test-pending-param-changes 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: pending-param-changes all assertions"; then
  echo ""
  echo "  PASS: pending-param-changes unit test"
  exit 0
else
  echo ""
  echo "  FAIL: pending-param-changes had assertion failures"
  exit 1
fi
