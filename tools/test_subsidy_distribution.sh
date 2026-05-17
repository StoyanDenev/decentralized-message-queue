#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the E1/E3/E4 subsidy
# distribution apply path.
#
# Per-block subsidy + total fees are distributed equally across
# `b.creators`. Modulo dust goes to `creator[0]`. Three modes /
# pillars covered:
#
#   FLAT (subsidy_mode_=0, default):
#     Every block pays `block_subsidy_` exactly (or 0 if creators
#     empty). Steady, predictable per-block issuance.
#
#   LOTTERY (subsidy_mode_=1):
#     Probability 1/M of paying `block_subsidy * M`, otherwise 0.
#     M = `lottery_jackpot_multiplier_`. Seeded by
#     `cumulative_rand[0..7]` (big-endian u64 mod M). Expected
#     per-block value equals FLAT subsidy. Defeats selective-abort
#     attacks against jackpot blocks because commit-reveal makes
#     cumulative_rand unpredictable at Phase-1 decision time.
#
#   E4 finite-pool (subsidy_pool_initial_ != 0):
#     Caps cumulative paid subsidy at the pool value. Once
#     accumulated_subsidy_ reaches the cap, subsequent blocks pay 0
#     (chain runs on fees alone — self-terminating subsidy fund).
#     Pairs cleanly with LOTTERY: jackpot payouts still cap.
#
# Network-level: the chain-summary supply counters in production
# exercise these across many blocks. This in-process test pins the
# per-block apply semantics in <1s.
#
# ~17 assertions in eight blocks:
#
#   FLAT mode (4):
#     - subsidy 100 / 1 creator: full 100
#     - accumulated_subsidy counter += subsidy_this_block
#     - subsidy 100 / 2 creators: 50/50 split
#     - subsidy 101 / 2 creators: 50/50 + dust(1) to creator[0]
#
#   LOTTERY mode (4):
#     - jackpot (cumulative_rand seed % M == 0): pays subsidy * M
#     - miss (seed % M != 0): pays 0
#
#   E4 finite pool (3):
#     - block 1: full subsidy (cumulative < cap)
#     - block 2: partial subsidy (remaining = cap - cumulative)
#     - block 3: drained → 0
#
#   A1 invariant under mint (2):
#     - subsidy mints exactly block_subsidy into live supply
#     - expected == live post-mint
#
#   Empty-creators no-op (2):
#     - subsidy NOT paid (A1-safe contract)
#     - supply unchanged
#
# Run from repo root: bash tools/test_subsidy_distribution.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Subsidy distribution apply (FLAT + LOTTERY + E4 finite pool) ==="
OUT=$($DETERM test-subsidy-distribution 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: subsidy-distribution all assertions"; then
  echo ""
  echo "  PASS: subsidy-distribution unit test"
  exit 0
else
  echo ""
  echo "  FAIL: subsidy-distribution had assertion failures"
  exit 1
fi
