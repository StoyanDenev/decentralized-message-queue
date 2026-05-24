#!/usr/bin/env bash
# GenesisConfig::to_json + make_genesis_block byte-identity contract —
# pin four axes that protect the chain-identity surface of every Determ
# deployment:
#   (a) JSON round-trip: to_json → from_json → to_json byte-identical
#       (both empty and all-fields-populated configs; no silent field
#       drops, no default-mismatch drift between to_json defaults and
#       from_json defaults).
#   (b) make_genesis_block determinism: 3 calls on the same config
#       produce byte-identical Block 0 (hash + cumulative_rand + full
#       JSON), AND two independently-constructed (direct vs. from_json)
#       configs produce identical blocks.
#   (c) Field-binding completeness: every hash-relevant GenesisConfig
#       field (chain_id, chain_role, shard_id, committee_region,
#       genesis_message, initial_creators ed_pub, suspension_slash)
#       actually binds the genesis hash. Reordering initial_creators[]
#       changes the hash (the order is committed to chain identity).
#   (d) S-039 documented gap: operational params NOT in
#       compute_genesis_hash (m_creators, k_block_sigs, block_subsidy,
#       subsidy_pool_initial, min_stake, initial_shard_count,
#       bft_enabled, bft_escalation_threshold, epoch_blocks,
#       shard_address_salt) stay NOT-bound. Pinning this contract lets
#       us notice if someone accidentally promotes one to the hash
#       without a coordinated migration.
#
# Companion to:
#   - test-genesis (compute_genesis_hash sensitivity / S-018 hardening)
#   - test-genesis-sharded (sharding-mode invariants)
#   - test-genesis-with-region (R1 region-tag mixing)
#   - test-make-genesis-block (block shape invariants)
#   - test-config-determinism / test-state-root-determinism /
#     test-tx-signing-determinism / test-hello-handshake-determinism
#     (the broader in-process determinism suite)
#
# 21 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_genesis_determinism.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== genesis-determinism: GenesisConfig + make_genesis_block byte-identity ==="
OUT=$($DETERM test-genesis-determinism 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: genesis-determinism all assertions"; then
  echo ""
  echo "  PASS: genesis-determinism unit test"
  exit 0
else
  echo ""
  echo "  FAIL: genesis-determinism had assertion failures"
  exit 1
fi
