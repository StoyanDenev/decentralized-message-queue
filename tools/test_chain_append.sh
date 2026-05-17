#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `Chain::append`,
# `Chain::head`, `Chain::at`, `Chain::head_hash` mutation invariants.
#
# `Chain::append` is the public mutation entry point — every block
# transitions through it: the apply path during sync, replay during
# chain.json load, the tentative-chain compute_state_root step
# during finalize. The prev_hash continuity check
# (`b.prev_hash != head_hash()`) is the central chain-integrity
# invariant; without it a peer could insert a block at the wrong
# height and silently corrupt state.
#
# 16 assertions covering:
#
#   Empty Chain invariants (3):
#     - head() throws "Empty chain"
#     - head_hash() throws (via head())
#     - at(0) throws "out of range"
#
#   Initial append (3):
#     - block at index 0 with prev_hash=zero succeeds (genesis-like)
#     - height becomes 1, empty() returns false
#     - head().index == 0
#
#   Second append (3):
#     - block at index 1 with prev_hash = previous head_hash() succeeds
#     - height becomes 2, head().index == 1
#     - head().prev_hash == previous head_hash()
#
#   prev_hash continuity (2):
#     - append with wrong prev_hash throws 'prev_hash mismatch'
#     - append with zero prev_hash (at non-zero index) also rejected
#
#   Multi-block chain (4):
#     - Build a 5-block chain with correct prev_hash continuity
#     - height == 5, at(0).index == 0, at(4).index == 4
#     - head().index == 4
#     - at(5) out of range
#
#   prev_hash transitivity (1):
#     - Every block's prev_hash matches the prior block's compute_hash
#       across a chain of arbitrary length. The chain-anchor invariant.
#
# Run from repo root: bash tools/test_chain_append.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::append + head + at + head_hash — chain mutation invariants ==="
OUT=$($DETERM test-chain-append 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-append all assertions"; then
  echo ""
  echo "  PASS: chain-append unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-append had assertion failures"
  exit 1
fi
