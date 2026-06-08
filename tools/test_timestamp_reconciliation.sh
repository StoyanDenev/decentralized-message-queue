#!/usr/bin/env bash
# S-030-D2 timestamp dimension: the deterministic median reconciliation that
# closes the last block-digest residual. `compute_block_digest` cannot bind a
# RAW block timestamp (honest committee clocks differ within the validator's
# ±30s window, so two honest members would sign divergent digests and abort the
# round — S030-D2-Analysis.md §5). The fix: each member commits its local time
# in its signed Phase-1 ContribMsg (proposer_time), the assembler reconciles the
# K committed times to a deterministic LOWER-MEDIAN at build_body, sets it as
# the canonical block timestamp, and compute_block_digest binds THAT. The
# validator re-derives the same median from creator_proposer_times and rejects
# on mismatch.
#
# 16 assertions over the pure new primitives (no keys/registry/Chain):
#   reconcile_median_time — empty->0, single, K=3/5 middle, K=4 lower-median,
#     permutation-determinism, K=7 f=2 Byzantine-robustness (outliers can't move
#     the median out of the honest cluster);
#   compute_block_digest gate — timestamp BOUND iff creator_proposer_times
#     present, NOT bound (v1 shape) when empty, binds the median value not the
#     raw times;
#   make_contrib_commitment gate — proposer_time=0 keeps the byte-identical v1
#     commitment, non-zero binds it, distinct times -> distinct commitments;
#   ContribMsg JSON round-trip — emitted when non-zero, survives round-trip,
#     omitted when zero.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== S-030-D2 timestamp median-reconciliation contract ==="
OUT=$($DETERM test-timestamp-reconciliation 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: timestamp-reconciliation all assertions"; then
  echo ""
  echo "  PASS: timestamp-reconciliation unit test"
  exit 0
else
  echo ""
  echo "  FAIL: timestamp-reconciliation had assertion failures"
  exit 1
fi
