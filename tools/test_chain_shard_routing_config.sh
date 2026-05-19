#!/usr/bin/env bash
# S-035 Option 1 seed — Chain::set_shard_routing + is_cross_shard
# contract at the Chain level.
#
# Distinct from test-shard-routing (which tests the crypto-layer
# primitive shard_id_for_address): this test pins the Chain wrapper's
# behavior — how it stores the (shard_count, shard_salt, my_shard_id)
# triple and how its is_cross_shard helper short-circuits in single-
# shard mode and delegates to the crypto layer in multi-shard mode.
#
# Why this layer matters: every cross-shard apply path (producer +
# validator + chain.apply_transactions) reads chain.is_cross_shard(addr)
# to decide whether a TRANSFER becomes outbound (debit only) or local
# (debit + credit atomic). A bug at this layer means cross-shard
# semantics break silently, with no apparent symptom on single-chain
# deployments but catastrophic on sharded runs.
#
# Covered:
#   - Default Chain: shard_count=1, is_cross_shard always false
#   - shard_count<=1 short-circuit (1, 0): is_cross_shard always false
#   - shard_count>1: routes via shard_id_for_address (5 addresses)
#   - my_shard_id parameter: address routes to exactly 1 of N shards
#   - Salt sensitivity: changing salt changes routing for >=1 of 8 addrs
#   - Re-set (same args)^2 idempotent: shard_count + my_shard_id stable
#   - Re-set (different my_shard_id): flips is_cross_shard appropriately
#
# Defends against:
#   - Single-shard mode losing short-circuit (would falsely flag
#     local addresses as cross-shard → spurious outbound debits).
#   - is_cross_shard ignoring my_shard_id (would route to wrong shard).
#   - Salt drift (e.g., post-A6 salt change unintentionally bound).
#
# 23 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_chain_shard_routing_config.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::set_shard_routing + is_cross_shard (chain-level shard routing) ==="
OUT=$($DETERM test-chain-shard-routing-config 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-shard-routing-config all assertions"; then
  echo ""
  echo "  PASS: chain-shard-routing-config unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-shard-routing-config had assertion failures"
  exit 1
fi
