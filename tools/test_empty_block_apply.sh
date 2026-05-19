#!/usr/bin/env bash
# S-035 Option 1 seed — empty / minimal-content block apply behavior.
#
# The happy-path tests use blocks with non-empty creators + transactions;
# this test pins the degenerate cases that DON'T appear in routine flow:
#
#   - Block with empty creators[] (no committee) — subsidy gated OFF
#     in chain.cpp at line 1286 / 1390 via !b.creators.empty(). Live
#     supply unchanged; A1 invariant holds.
#   - Block with creators={alice} but NO transactions / events. Subsidy
#     minted to sole creator; A1 invariant holds.
#   - 5 consecutive empty blocks: chain advances cleanly, accumulated_subsidy
#     accrues linearly, A1 holds at every boundary.
#   - Block with a single TX that fails (insufficient balance): TX silently
#     skipped via continue in the apply loop, subsidy still mints, nonce
#     NOT bumped on skipped sender.
#   - state_root sensitivity: parallel empty blocks produce same root;
#     genesis-only chain differs from chain that advanced via empty block
#     (subsidy mint touches a:-namespace).
#   - prev_hash chain intact across consecutive empty blocks.
#
# Defends against subsidy double-distribution on empty creators (would
# mint to nowhere → silent supply inflation) and against empty-block
# apply hangs / crashes.
#
# 16 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_empty_block_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== empty / minimal block apply — empty-creators subsidy gate, multi-empty advance ==="
OUT=$($DETERM test-empty-block-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: empty-block-apply all assertions"; then
  echo ""
  echo "  PASS: empty-block-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: empty-block-apply had assertion failures"
  exit 1
fi
