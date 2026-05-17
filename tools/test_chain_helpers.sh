#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Chain's read-side
# API surface (`include/determ/chain/chain.hpp`):
#
#   * balance / next_nonce / stake / stake_unlock_height
#   * balance_lockfree / next_nonce_lockfree / stake_lockfree
#     (the read-only paths that skip the per-Chain mutex — used by
#     concurrent RPC handlers reading state while apply runs)
#   * height / empty / head_hash
#   * shard_count / my_shard_id / shard_salt / is_cross_shard
#   * A1 supply counters (accumulated_subsidy / _slashed / _inbound /
#     _outbound; genesis_total / expected_total / live_total_supply)
#   * Operator-tunable parameters (block_subsidy / min_stake /
#     suspension_slash / unstake_delay)
#
# These are queried by every RPC handler + every block-apply step
# that consults state before mutating. A regression in default-
# value behavior would cascade through every safety proof that
# assumes a consistent state view (e.g., a non-zero default for
# balance() would credit unknown addresses on lookup).
#
# 23 assertions covering:
#
#   Default Chain shape (3): height==0, empty(), no-data domain
#     balance/nonce/stake all 0.
#   Lock-free equivalence (3): balance_lockfree == balance,
#     next_nonce_lockfree == next_nonce, stake_lockfree == stake
#     on default Chain (no concurrency yet).
#   Setter round-trip (4): set_block_subsidy / set_min_stake /
#     set_suspension_slash / set_unstake_delay all round-trip
#     through their getters.
#   Shard routing (7): default Chain has shard_count==1 + my_shard_id==0
#     + is_cross_shard==false unconditionally; set_shard_routing
#     round-trips count + id + salt; with shard_count=4 some
#     addresses route locally + some cross-shard.
#   A1 supply counters (4): default Chain has all four accumulator
#     fields zero (no genesis applied, no mutations).
#
# Run from repo root: bash tools/test_chain_helpers.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain read API (balance / next_nonce / stake / shard routing / supply counters) ==="
OUT=$($DETERM test-chain-helpers 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-helpers all assertions"; then
  echo ""
  echo "  PASS: chain-helpers unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-helpers had assertion failures"
  exit 1
fi
