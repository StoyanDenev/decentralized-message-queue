#!/usr/bin/env bash
# S-035 Option 1 seed — Chain constructor bootstrap paths.
#
# The Chain class has two ctors:
#   - Chain() = default → produces an empty Chain
#   - explicit Chain(Block genesis) → bootstraps by applying genesis
#     as block 0 (via apply_transactions(genesis))
#
# Plus the legacy bootstrap path: Chain c; c.append(make_genesis_block(cfg))
#
# This test pins:
#   - Chain() is empty (height=0, empty()=true)
#   - head() on empty Chain throws with "Empty chain" diagnostic
#   - at(N) on empty Chain throws std::out_of_range-style
#   - Chain(genesis) bootstraps to height=1; head matches genesis
#   - Both bootstrap paths (Chain c; c.append(g) vs Chain c(g)) produce
#     equivalent state (head_hash, state_root, account/stake state)
#   - Both bootstrap paths support continued append
#
# 15 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_chain_ctor_bootstrap.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain ctor bootstrap paths — Chain() + Chain(genesis) equivalence ==="
OUT=$($DETERM test-chain-ctor-bootstrap 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-ctor-bootstrap all assertions"; then
  echo ""
  echo "  PASS: chain-ctor-bootstrap unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-ctor-bootstrap had assertion failures"
  exit 1
fi
