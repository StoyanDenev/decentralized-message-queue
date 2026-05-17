#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `make_genesis_block`,
# the genesis-block builder consumed by `determ init` and the
# fork-choice / snapshot-restore paths.
#
# `make_genesis_block` produces the deterministic block-0 ancestor for
# every chain instance. Its invariants ARE the chain's bootstrap
# contract:
#
#   Structural:
#     - index == 0
#     - prev_hash == zero (no parent — orphans root)
#     - timestamp == 0 (genesis is timeless)
#     - transactions[]    empty (no apply-time tx)
#     - creator_tx_lists  empty
#     - creator_ed_sigs   empty
#     - creator_dh_inputs empty
#     - creator_block_sigs empty
#     - tx_root           zero
#
#   Creator-list invariants:
#     - creators[] populated from cfg.initial_creators (domain-only)
#     - creators[] sorted ALPHABETICALLY (deterministic order
#       regardless of cfg insertion order — genesis must be byte-equal
#       across nodes from different `determ init` invocations).
#
#   initial_state population:
#     - One entry per initial_creators[] with (domain, ed_pub, stake,
#       region) populated; balance defaults to 0 unless overridden by
#       initial_balances merge.
#
#   initial_balances merge semantics:
#     - For each balance whose domain MATCHES an existing
#       initial_state entry → balance ADDED to that entry's balance
#       field (in-place merge, no duplicate entry).
#     - For each balance whose domain does NOT match any entry → a
#       NEW initial_state entry created (domain + balance set; stake=0,
#       ed_pub default-zero — these are "pure-balance" recipients,
#       e.g. faucet / treasury / pre-mine allocations).
#
#   Determinism:
#     - Same GenesisConfig → byte-identical Block on every call (no
#       wall-clock, no /dev/urandom, no map-iteration-order leak).
#       Critical for cross-node genesis agreement.
#
# 34 assertions in five blocks covering every invariant above.
#
# Run from repo root: bash tools/test_make_genesis_block.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== make_genesis_block invariants (genesis builder bootstrap contract) ==="
OUT=$($DETERM test-make-genesis-block 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: make-genesis-block all assertions"; then
  echo ""
  echo "  PASS: make-genesis-block unit test"
  exit 0
else
  echo ""
  echo "  FAIL: make-genesis-block had assertion failures"
  exit 1
fi
