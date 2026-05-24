#!/usr/bin/env bash
# Minimal / edge-case GenesisConfig contract — pin behavior at the
# corners of the chain-bootstrap surface that the sibling test-genesis*
# suite doesn't cover:
#
#   (1) Default-constructed GenesisConfig: every header default at
#       its expected value (empty collections, K=M=3 strong BFT,
#       SINGLE / shard 0, STAKE_INCLUSION, bft_enabled=true,
#       min_stake=1000, default genesis_message).
#   (2) Genesis with zero allocations: 1 creator + empty
#       initial_balances. make_genesis_block succeeds; Chain boots;
#       creator's account auto-creates at 0.
#   (3) Single-creator genesis (K=1): degenerate-but-valid committee.
#       Chain bootstraps; select_m_creators(K=1, N=1) returns [0]
#       deterministically.
#   (4) Allocation with balance=0: accepted, NOT silently dropped.
#       Both the Chain's account map and the block's initial_state[]
#       record the entry.
#   (5) Creator with initial_stake=0: RegistryEntry installed
#       (ed_pub != zero), but stakes_[] entry skipped per
#       apply_transactions's `if (a.stake > 0)` guard. Balance
#       auto-created at 0.
#   (6) Genesis-hash determinism on empty config: 4 compute_genesis_hash
#       calls (2 instances × 2 calls) byte-identical + non-zero.
#   (7) compute_state_root on minimal genesis: non-zero (k:/c:
#       namespaces always populate via Chain constants + A1
#       accumulators); cross-instance deterministic.
#
# Companion to:
#   - test-genesis (compute_genesis_hash sensitivity / S-018 hardening)
#   - test-genesis-determinism (R33A5 JSON + block byte-identity)
#   - test-genesis-message (genesis_message hash-mixing)
#   - test-genesis-sharded (chain_role / shard_id / committee_region)
#   - test-genesis-with-region (R1 regional creator coverage)
#
# 7 scenarios, ~17 assertions.
#
# Run from repo root: bash tools/test_empty_genesis_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== empty-genesis-edge: minimal / edge-case Genesis pinning ==="
OUT=$($DETERM test-empty-genesis-edge 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: empty-genesis-edge all assertions"; then
  echo ""
  echo "  PASS: empty-genesis-edge unit test"
  exit 0
else
  echo ""
  echo "  FAIL: empty-genesis-edge had assertion failures"
  exit 1
fi
