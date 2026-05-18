#!/usr/bin/env bash
# S-035 Option 1 seed — chain-level CONTINUITY invariants across an
# N-block append sequence (N=10).
#
# Per-block apply paths are already covered exhaustively
# (TRANSFER / STAKE / UNSTAKE / DEREGISTER / slash / cross-shard /
# subsidy / DApp / merge / equivocation / abort). This test fills the
# gap of CHAIN-WIDE invariants over many heights:
#
#   - prev_hash linkage: block[i].prev_hash == block[i-1].compute_hash()
#     for every i; the property snapshot/replay/light-client relies on
#   - height monotonicity: block[i].index == i (no gaps, no rewinds)
#   - A1 invariant at EVERY boundary (10 blocks, mixed empty/TRANSFER
#     content + subsidy mint each block)
#   - accumulated_subsidy = N * block_subsidy (linear accrual)
#   - state_root mutates on state-changing block (TRANSFER → root delta)
#   - Determinism: parallel chains apply identical sequence → identical
#     state_root at every height
#   - compute_hash idempotency
#
# 7 scenarios; ~9 assertions.
#
# Run from repo root: bash tools/test_multi_block_chain.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== multi-block-chain (N=10 append continuity invariants) ==="
OUT=$($DETERM test-multi-block-chain 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: multi-block-chain all assertions"; then
  echo ""
  echo "  PASS: multi-block-chain unit test"
  exit 0
else
  echo ""
  echo "  FAIL: multi-block-chain had assertion failures"
  exit 1
fi
