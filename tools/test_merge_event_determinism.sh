#!/usr/bin/env bash
# MERGE_EVENT (R7 under-quorum-merge) canonical encoding +
# apply-determinism + cross-event composition contract — pin seven
# axes:
#   (1) Replay determinism: a chain with a MERGE_EVENT saved + loaded
#       via Chain::save / Chain::load preserves every MergeEvent field
#       byte-for-byte through the apply-path round-trip.
#   (2) Canonical encoding: Transaction JSON round-trip via
#       Transaction::to_json + ::from_json preserves the MERGE_EVENT
#       payload byte-for-byte; re-encoding the decoded form yields the
#       original bytes (encode is idempotent).
#   (3) Field-binding completeness: mutating any MergeEvent field
#       (event_type, shard_id, partner_id, effective_height,
#       evidence_window_start, merging_shard_region) changes both
#       MergeEvent::encode AND the enclosing
#       Transaction::signing_bytes (no silent field-drop in consensus
#       binding).
#   (4) Apply determinism: applying the same MERGE_EVENT-bearing block
#       to two fresh chains produces byte-identical state_root +
#       merge_state.
#   (5) Snapshot round-trip: Chain::serialize_state +
#       Chain::restore_from_snapshot preserves merge_state (S-037
#       closure paired with the m:-namespace S-033 coverage).
#   (6) Edge values: UINT64_MAX effective_height +
#       evidence_window_start, empty region (END semantics), max-32-
#       byte region all round-trip cleanly via encode/decode.
#   (7) Cross-event composition: a block with MERGE_EVENT + TRANSFER +
#       STAKE applies deterministically; the post-apply state_root is
#       reproducible across twin chains and is distinct from a
#       baseline-without-MERGE chain — proves MERGE_EVENT presence
#       binds into state_root (FA-Apply-15 T-M5 + T-M4 specialization
#       for the m: namespace).
#
# Companion to:
#   - test-merge-event-codec (round-trip + field sensitivity)
#   - test-merge-event-bytes (golden byte-layout vectors)
#   - test-merge-event-apply (BEGIN/END apply path)
#   - test-merge-event-apply-edge (edge cases)
#   - test-merge-state (state-machine)
#
# 17 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_merge_event_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== MERGE_EVENT determinism contract — replay + canonical + apply ==="
OUT=$($DETERM test-merge-event-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-event-determinism all assertions"; then
  echo ""
  echo "  PASS: merge-event-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-event-determinism had assertion failures"
  exit 1
fi
