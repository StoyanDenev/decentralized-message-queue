#!/usr/bin/env bash
# R40 D1 — A1 unitary-supply invariant across a FULL cross-shard cycle.
#
# test-cross-shard-atomicity models a 2-Chain pair and asserts each
# shard's own A1 (expected == live) plus src_outbound == dst_inbound.
# This test goes one level up: it builds a K=3 shard set, funds a
# STAKED account on the source shard, runs the outbound debit on S and
# the inbound credit on D, and pins the GLOBAL accounting identity:
#
#   Σ_shards (balances + staked + outbound-in-flight) + Σ slashed
#     == Σ expected_total at genesis
#
# What it pins that the pair test does not:
#   - K=3 (not 2) shards — the aggregate sum is over the whole set.
#   - a non-zero STAKED term in the aggregate (atomicity used stake=0).
#   - the coin "in flight" (debited on S, not yet credited on D) is
#     conserved — the aggregate equals the genesis baseline mid-cycle.
#   - serialize_state → restore_from_snapshot → re-derive yields a
#     byte-identical state_root and identical supply totals.
#   - replay of the same cross-shard sequence → byte-identical state.
#   - duplicate inbound receipt is a no-op (FA-Apply-9 dedup) and does
#     NOT inflate supply — the catastrophic double-credit failure mode.
#
# Proofs: FA7 (CrossShardReceipts.md), FA-Apply-13
# (CrossShardOutboundApply.md), FA-Apply-9 (CrossShardReceiptDedup.md).
#
# ~30 assertions across the K-shard cross-shard cycle.
#
# Run from repo root: bash tools/test_cross_shard_supply_invariant.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== cross-shard supply invariant — A1 across a full K-shard cross-shard cycle ==="
OUT=$($DETERM test-cross-shard-supply-invariant 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: cross-shard-supply-invariant all assertions"; then
  echo ""
  echo "  PASS: cross-shard-supply-invariant unit test"
  exit 0
else
  echo ""
  echo "  FAIL: cross-shard-supply-invariant had assertion failures"
  exit 1
fi
