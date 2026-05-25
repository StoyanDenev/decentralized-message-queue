#!/usr/bin/env bash
# R7 under-quorum-merge merge_state JSON round-trip + deterministic
# eviction-order + m:-namespace state_root binding — pin five axes
# independent of the MergeEvent wire encoding:
#   (1) Fixture round-trip: serialize_state → restore_from_snapshot
#       → serialize_state produces bytewise-identical "merge_state"
#       JSON. Every MergePartnerInfo field round-trips through the
#       snapshot.
#   (2) Empty merge_state: chains with no refugee regions serialize
#       "merge_state" as an empty JSON array (not absent, not null,
#       not a scalar). Wire-schema stability for fast-bootstrap
#       peers.
#   (3) Distinct fixtures → distinct serialized JSON: two
#       merge_states differing in exactly one field (partner_id)
#       produce non-equal "merge_state" JSON (no silent fold in
#       serialize_state).
#   (4) Deterministic iteration order: serialize_state emits the
#       "merge_state" array sorted-ascending-by-ShardId regardless
#       of the input order at restore_from_snapshot time
#       (std::map<ShardId, ...> iteration is stable).
#   (5) state_root binding: toggling partner_id OR refugee_region
#       changes compute_state_root() — both fields contribute to
#       the m:-namespace value-hash per PROTOCOL.md §4.1.1.
#
# Companion to:
#   - test-merge-event-determinism (event wire + apply + state_root)
#   - test-merge-state (read-API on the in-memory map)
#   - test-state-root-namespaces (exhaustive m: namespace coverage)
#   - test-snapshot-roundtrip (whole-chain snapshot)
#
# 7 assertions across 5 scenarios.
#
# Run from repo root: bash tools/test_merge_state_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== merge_state determinism contract — JSON round-trip + eviction order ==="
OUT=$($DETERM test-merge-state-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-state-determinism all assertions"; then
  echo ""
  echo "  PASS: merge-state-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-state-determinism had assertion failures"
  exit 1
fi
