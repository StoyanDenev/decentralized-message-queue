#!/usr/bin/env bash
# D3.5d-ii (ShardTipMergeDesign.md §9.6) — the build_body shard-tip reconciliation
# fold. Block::shard_tip_records is the committee-wide reconcile_intersection of the
# K members' Phase-1 shard-tip views (creator_view_shardtip_lists) intersected with
# the assembler's candidates, so it is a pure function of the K signed contribs —
# every honest beacon co-signer assembles the identical set (no S-047 wedge).
#
# The binary test pins: hash_shard_tip determinism (full-content, binds
# committee_sig_root); build_body folds the full unanimous intersection; a record
# missing from ANY member's view is excluded (full-K, never a threshold); no
# candidates → empty set (byte-neutral); one empty view empties the intersection
# (fail-closed); and the committee_sig_root formula is order-independent over the
# sig set + binds the source_shard_id + the actual K-of-K signature set (the
# anti-wedge pure-function invariant). Composes with test_shard_tip_fold (the
# apply-path fold) and test_contrib_wire_verify (the DTM-STV-v1 signed-view binding).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D3.5d-ii shard-tip reconciliation fold ==="
OUT=$($DETERM test-shardtip-reconciliation 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_shardtip_reconciliation (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: shardtip-reconciliation"; then
  echo ""
  echo "  PASS: test_shardtip_reconciliation"
  exit 0
else
  echo ""
  echo "  FAIL: test_shardtip_reconciliation (missing summary marker)"
  exit 1
fi
