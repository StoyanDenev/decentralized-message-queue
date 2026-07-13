#!/usr/bin/env bash
# D3.7 / S-036 falsifier — the D3.6 MERGE_BEGIN historical-witness admission gate
# (ShardTipMergeDesign.md §3.4/§9). On a BEACON, a MERGE_BEGIN is accepted ONLY when
# the committed `t:` shard-tip records show CONTIGUOUS sub-2K distress over the
# source-shard window [evidence_window_start, +merge_threshold_blocks); every
# fabrication is fail-closed; and MERGE_EVENT on any non-BEACON chain is fail-closed
# entirely (the D3.6 reachable-exploit fix).
#
# The binary test drives BlockValidator::check_transactions in isolation (D3.7 test
# seam) over 8 scenarios: A genuine contiguous sub-2K distress ACCEPTED; B1 no records;
# B2 window gap; B3 a healthy (>= 2K) in-window record; B4 window predating the retained
# ring (pruned == absent); B5 merge_threshold_blocks==0 — all REJECTED; C MERGE_EVENT on
# a SHARD chain fail-closed; A2 the genuine-accept verdict is deterministic. Composes
# with test_under_quorum_merge.sh (the LIVE shard-path fail-close + no-stall) and
# test_shardtip_reconciliation.sh (the write side that folds the `t:` records).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D3.7 S-036 MERGE_BEGIN historical-witness falsifier ==="
OUT=$($DETERM test-s036-merge-witness 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_s036_merge_witness (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: s036-merge-witness"; then
  echo ""
  echo "  PASS: test_s036_merge_witness"
  exit 0
else
  echo ""
  echo "  FAIL: test_s036_merge_witness (missing summary marker)"
  exit 1
fi
