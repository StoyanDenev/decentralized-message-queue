#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the Chain merge-state
# read API + R4 governance threshold setters.
#
# Merge state is the R4 under-quorum-merge primitive's apply-side
# bookkeeping: when a MERGE_EVENT applies to a chain, the affected
# shard becomes a refugee (key in merge_state_) tagged with its partner
# shard id and refugee_region. Validator + producer paths read this via
# `merge_state()`, `is_shard_merged()`, and `shards_absorbed_by()` during
# EXTENDED-mode block production. This test pins the read API + the A5
# governance setters for the three merge-policy knobs.
#
# 11 assertions in three blocks:
#
#   Default-empty merge state (4):
#     - merge_state() empty on default Chain
#     - is_shard_merged() returns false with out_partner unmodified
#     - is_shard_merged(0, nullptr) safe (null pointer permissive)
#     - shards_absorbed_by(any) returns empty vector
#
#   R4 threshold setters round-trip (6):
#     - merge_threshold_blocks default 100 + setter
#     - revert_threshold_blocks default 200 (2x merge — hysteresis) + setter
#     - merge_grace_blocks default 10 + setter
#     - threshold setters independent (setting one preserves the others)
#
#   MergePartnerInfo struct (2):
#     - default partner_id == 0; refugee_region empty (R1 global pool)
#
# Run from repo root: bash tools/test_merge_state.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain merge-state read API + R4 governance setters ==="
OUT=$($DETERM test-merge-state 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merge-state all assertions"; then
  echo ""
  echo "  PASS: merge-state unit test"
  exit 0
else
  echo ""
  echo "  FAIL: merge-state had assertion failures"
  exit 1
fi
