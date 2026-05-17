#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the R7 under-quorum-
# merge MERGE_EVENT apply path.
#
# Merge state machine (apply-side):
#   MERGE_BEGIN: insert (shard_id → {partner_id, refugee_region}) into
#                merge_state_, but ONLY when shard_count > 1 AND
#                partner_id == ((shard_id + 1) % shard_count). The
#                partner constraint enforces the canonical "next shard
#                in the ring" absorption pattern.
#
#   MERGE_END:   remove the entry for shard_id from merge_state_, but
#                ONLY when partner_id matches the recorded value. Wrong
#                partner = silent no-op (defense against malformed events
#                slipping past validator checks).
#
# Single-shard chains (shard_count <= 1) reject all MERGE events at
# apply (the partner-ring constraint can't be satisfied). Validator
# rejects them earlier (no inter-shard merge concept on a single
# chain), but apply-side defense-in-depth makes the no-op safe under
# replay.
#
# 13 assertions in nine blocks:
#
#   BEGIN inserts entry (3):
#     - merge_state has entry for shard_id
#     - partner_id correct
#     - refugee_region preserved
#
#   is_shard_merged predicate (2):
#     - merged shard returns true with out_partner = recorded partner
#     - unmerged shard returns false
#
#   END removes entry (1):
#     - matching-partner END removes the merge_state entry
#
#   END with wrong partner (1):
#     - no-op (recorded entry untouched)
#
#   BEGIN partner constraint (1):
#     - wrong partner_id at BEGIN: NO entry created (apply defense
#       complements validator gate)
#
#   Single-shard chains (1):
#     - shard_count=1: MERGE_BEGIN no-op (ring constraint unsatisfiable)
#
#   Multiple distinct merges (2):
#     - two BEGIN events on different shards: both tracked
#     - region preserved per entry
#
#   shards_absorbed_by helper (2):
#     - inverse-lookup returns (shard, region) pairs per absorber
#
#   Determinism (1):
#     - two chains apply same MERGE_BEGIN → same compute_state_root
#
# Run from repo root: bash tools/test_merge_event_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== MERGE_EVENT apply (R7 under-quorum-merge state machine) ==="
OUT=$($DETERM test-merge-event-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-event-apply all assertions"; then
  echo ""
  echo "  PASS: merge-event-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-event-apply had assertion failures"
  exit 1
fi
