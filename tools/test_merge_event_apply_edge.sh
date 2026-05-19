#!/usr/bin/env bash
# S-035 Option 1 seed — R7 under-quorum merge edge cases beyond the
# happy-path tested in test-merge-event-apply.
#
# test-merge-event-apply pins: BEGIN inserts entry, END removes,
# wrong-partner rejection, shard_count=1 no-op, multi-merge,
# shards_absorbed_by helper, basic determinism.
#
# This test fills the EDGE cases:
#   - MERGE_END with NO prior BEGIN (lost-gossip scenario must not
#     corrupt state)
#   - Double MERGE_BEGIN for same shard (idempotent — no duplicates)
#   - BEGIN/END/BEGIN cycle (re-merge after END must be allowed)
#   - Self-merge (shard_id == partner_id): rejected at apply
#   - Out-of-range shard_id (>= shard_count): rejected
#   - Empty refugee_region in BEGIN: accepted (region is optional)
#   - A1 invariant unchanged by merge events (pure metadata)
#   - state_root sensitive to merge_state (m:-namespace coverage)
#   - Determinism across the edge-case mix
#
# 13 assertions across 9 scenarios.
#
# Run from repo root: bash tools/test_merge_event_apply_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== merge-event apply EDGE — lost gossip, cycles, rejection paths, m:-state_root ==="
OUT=$($DETERM test-merge-event-apply-edge 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-event-apply-edge all assertions"; then
  echo ""
  echo "  PASS: merge-event-apply-edge unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-event-apply-edge had assertion failures"
  exit 1
fi
