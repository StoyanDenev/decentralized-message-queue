#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for compute_genesis_hash
# and make_genesis_block — the chain-identity origin.
#
# Every node MUST compute the same genesis hash from the same
# GenesisConfig or the chain identity diverges (operators see
# "genesis_hash mismatch" at startup and the node refuses to start).
#
# 19 assertions covering:
#
#   Determinism + chain_id sensitivity (2)
#
#   Operational params NOT in hash (6) — DOCUMENTED GAP:
#     The following fields contribute NOTHING to compute_genesis_hash
#     by current design (the hash inputs are chain_id + chain_role +
#     shard_id + committee_region + genesis_message + creators'
#     ed_pubs + governance fields + suspension_slash/unstake_delay +
#     merge thresholds — when non-default):
#       * m_creators (committee size K)
#       * k_block_sigs (Phase-2 quorum)
#       * block_subsidy / subsidy_pool_initial / subsidy_mode
#       * min_stake
#       * initial_shard_count
#       * bft_enabled / bft_escalation_threshold
#       * epoch_blocks
#       * shard_address_salt
#
#     Diagnostic-UX impact: two operators running the same chain_id
#     with different m_creators get cryptic consensus failures (their
#     K-committees differ → signature gathering never converges)
#     rather than a clear "your m_creators doesn't match the chain's"
#     error.
#
#     Wire-compat impact: adding any of these to the hash would
#     change every existing chain's genesis hash. Tracked as a
#     forward-dev item; lock the CURRENT no-effect behavior in
#     here so we notice if it changes accidentally.
#
#   Fields that ARE bound into the hash (6):
#     shard_id, chain_role, suspension_slash (non-default → mixed),
#     merge_threshold_blocks (non-default → mixed), genesis_message,
#     committee_region (non-empty → mixed)
#
#   make_genesis_block invariants (3): index == 0, prev_hash zero,
#     compute_hash matches compute_genesis_hash.
#
#   JSON round-trip (2): preserves identity hash; oversized
#     genesis_message rejected at JSON-load.
#
# Run from repo root: bash tools/test_genesis.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== compute_genesis_hash + make_genesis_block — chain identity origin ==="
OUT=$($DETERM test-genesis 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis all assertions"; then
  echo ""
  echo "  PASS: genesis unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis had assertion failures"
  exit 1
fi
