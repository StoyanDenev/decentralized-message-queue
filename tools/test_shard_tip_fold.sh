#!/usr/bin/env bash
# D3.5b (ShardTipMergeDesign.md §9.6) — the apply-path fold that populates the `t:`
# state namespace from a Block's shard_tip_records inside Chain::apply_transactions.
# This is the write-side twin of the D3.3b committee-checkpoint fold, but
# CONTENT-DRIVEN (no shard_count_ gate): an empty record set folds zero `t:` leaves
# (byte-neutral), so only a BEACON producer under EXTENDED (D3.5c) ever populates it.
#
# The binary test pins: the fold FIRES from b.shard_tip_records even on a SINGLE
# chain (proving it is content-driven, not shard-gated); an empty set folds nothing
# and leaves state_root byte-identical; a folded record CHANGES state_root (the `t:`
# leaf is bound); the binding survives a Chain::load replay identically; and it is
# A4-reorg-safe via the __ensure_shard_tip_records lazy-capture — revert_head rolls
# the ring back to its pre-fold image and a re-append re-folds the identical records
# + state_root (idempotent). Composes with test_shard_tip_namespace (which drives
# add_shard_tip_record directly) and test_committee_fold (the cc: fold twin).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== D3.5b shard-tip-record apply-path fold ==="
OUT=$($DETERM test-shard-tip-fold 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_shard_tip_fold (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: shard-tip-fold"; then
  echo ""
  echo "  PASS: test_shard_tip_fold"
  exit 0
else
  echo ""
  echo "  FAIL: test_shard_tip_fold (missing summary marker)"
  exit 1
fi
