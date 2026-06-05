#!/usr/bin/env bash
# E4 finite-pool / E3 lottery subsidy CLAMP accounting. Companion to
# test-subsidy-distribution and test-fee-distribution-edge, which pin the
# FULL-payment split (each creator gets block_subsidy/N + dust). THIS test
# pins the PARTIAL-payment block — the one where the E4 pool holds fewer
# units than block_subsidy_, so chain.cpp:1267-1272 clamps
# subsidy_this_block = min(base_subsidy, remaining):
#   - Scenario 1: clamped block credits creators the CLAMPED value (15/15
#     from a 30-clamp), NOT block_subsidy/N; accumulated_subsidy ticks by
#     the clamp (chain.cpp:1390-1391), not the literal
#   - Scenario 2: clamp leaving an odd remainder still routes dust to
#     creator[0] (dust rule fires on the clamped total)
#   - Scenario 3: post-drain "runs on fees alone" — subsidy_this_block==0
#     but fees still split to creators; accumulated_subsidy does NOT tick
#   - Scenario 4: LOTTERY jackpot (block_subsidy*M) truncated by a finite
#     pool (subsidy_mode_==1 AND subsidy_pool_initial_!=0 together — the
#     combo neither sibling test drives)
#   - Scenario 5: A1 invariant holds across the full -> clamped -> drained
#     transition; total mint == pool cap, never block_subsidy*blocks
#   - Scenario 6: c:-namespace state_root sensitive to the clamped
#     accumulated_subsidy (divergent pool caps -> divergent root)
#   - Scenario 7: determinism — identical clamp sequence -> identical root
#
# Run from repo root: bash tools/test_subsidy_pool_clamp.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== subsidy pool clamp (E4 finite-pool / E3 lottery clamp accounting) ==="
OUT=$($DETERM test-subsidy-pool-clamp 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: subsidy-pool-clamp all assertions"; then
  echo ""
  echo "  PASS: subsidy-pool-clamp unit test"
  exit 0
else
  echo ""
  echo "  FAIL: subsidy-pool-clamp had assertion failures"
  exit 1
fi
