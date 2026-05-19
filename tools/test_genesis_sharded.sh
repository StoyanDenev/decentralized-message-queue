#!/usr/bin/env bash
# S-035 Option 1 seed — genesis variants for sharded deployments.
#
# compute_genesis_hash is the chain-identity anchor. This test verifies
# that two sharded chains in the same deployment with different
# `shard_id` OR different `chain_role` produce DIFFERENT genesis
# hashes — so a BEACON's chain identity can never collide with a
# SHARD's, and shard 0's identity is distinct from shard 1's.
#
# Covered:
#   - chain_role sensitivity (SINGLE / BEACON / SHARD pairwise distinct)
#   - shard_id sensitivity (shards 0, 1, 2 all distinct hashes)
#   - JSON round-trip preserves chain_role + shard_id +
#     initial_shard_count
#   - BEACON with non-zero shard_id is hash-distinct (the genesis-hash
#     level is identity-only; semantic constraints are validator-side)
#   - S-039 documented gap lock-in: initial_shard_count NOT bound into
#     the hash (changing 4→8 produces same hash — wire-compat-break to
#     fix, deferred to coordinated migration per S-039)
#   - Determinism: same config → same hash
#   - SHARD genesis block constructs cleanly: index=0, prev_hash=zero,
#     compute_hash() == compute_genesis_hash(cfg)
#   - Chain bootstraps from SHARD genesis
#
# Defends against accidental identity collision in multi-shard
# deployments (catastrophic — would cross-mount different shards as
# the same chain) and against silent demotion of chain_role.
#
# 14 assertions across 8 scenarios.
#
# Run from repo root: bash tools/test_genesis_sharded.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== genesis variants for sharded deployments — chain_role + shard_id sensitivity ==="
OUT=$($DETERM test-genesis-sharded 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis-sharded all assertions"; then
  echo ""
  echo "  PASS: genesis-sharded unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis-sharded had assertion failures"
  exit 1
fi
