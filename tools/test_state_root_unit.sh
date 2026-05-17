#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for
# Chain::compute_state_root() — the S-033 / v2.1 state-Merkle commitment.
#
# compute_state_root() is the foundation of FA1 (safety): it deterministically
# binds the entire post-apply state into a single 32-byte hash, which is
# carried in Block.state_root and verified at apply time (S-033 gate) and at
# snapshot restore (S-037 + S-038 chain). Light clients verify
# state_proof responses against this root — see v2.2.
#
# What this test locks in (13 assertions):
#
#   1. Determinism: two identically-built Chains produce identical
#      state_roots. Without this, K-of-K nodes would disagree on every
#      block's state_root field and never reach signature gathering.
#   2. Purity: 10 sequential calls on an unmodified Chain return the
#      same hash. Defeats hidden cache-accumulation or builder-reset
#      bugs.
#   3. Non-zero baseline: a default Chain has a non-zero state_root
#      because the "k:" namespace always emits leaves. Catches a
#      regression where build_state_leaves() returns empty.
#   4-7, 12-13. Per-field sensitivity: every public set_*() that maps
#      into the "k:" namespace produces a distinct state_root when its
#      value changes. Covers block_subsidy, min_stake,
#      subsidy_pool_initial, shard_routing (count + id + salt),
#      lottery_jackpot_multiplier (u32), subsidy_mode (u8).
#   9. Invertibility: change-then-revert returns to the original root —
#      no hidden mutation state outside what build_state_leaves emits.
#  10. Cross-namespace distinction: two different mutations produce two
#      different alternate roots (neither equal to baseline NOR equal
#      to each other). Defeats hidden namespace collisions.
#  11. Order independence: build_state_leaves() sorts leaves by key
#      before hashing, so the order in which setters were called must
#      not affect the final root.
#
# These complement the network-level tools/test_state_root.sh (3-node
# RPC roundtrip on a live chain) and tools/test_dapp_snapshot.sh
# (snapshot-restore S-037+S-038 contract) by exercising the underlying
# algebra in <5s with no network involvement.
#
# Run from repo root: bash tools/test_state_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::compute_state_root() — S-033 / v2.1 commitment algebra ==="
OUT=$($DETERM test-state-root 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-root all assertions"; then
  echo ""
  echo "  PASS: state_root unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-root had assertion failures"
  exit 1
fi
