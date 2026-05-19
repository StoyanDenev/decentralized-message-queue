#!/usr/bin/env bash
# S-035 Option 1 seed — randomized height-delay contract via REGISTER
# active_from + DEREGISTER inactive_from. chain.cpp's static derive_delay
# returns 1 + (sha256(tx_hash || cumulative_rand)[0..7] %
# REGISTRATION_DELAY_WINDOW), with REGISTRATION_DELAY_WINDOW = 10. So
# delay ∈ [1, 10] per registration / deregistration.
#
# Covered:
#   - Determinism: same (cumulative_rand, tx) → same active_from
#   - Range bound: active_from ∈ [height+1, height+10]
#   - cumulative_rand sensitivity (distinct seeds → distinct delays)
#   - tx_hash sensitivity (distinct payloads → distinct delays;
#     requires test fixture to set tx.hash explicitly, since the
#     apply path reads tx.hash directly without recomputing)
#   - Distribution: ≥7 of 10 possible delays observed across 60 runs
#     (defends against regression collapsing the formula to a small
#     subset — e.g., always returning 1, or only even delays)
#   - DEREGISTER uses the same formula (inactive_from ∈ [h+1, h+10])
#
# Defends against drift in the randomization formula that would either
# (a) collapse delay to a predictable value (operator picks own
# activation height) or (b) escape the [1, 10] window (silent over- /
# under-delay of activations).
#
# 9 assertions across 6 scenarios.
#
# Run from repo root: bash tools/test_randomized_delay.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== randomized-delay contract — derive_delay via REGISTER + DEREGISTER apply ==="
OUT=$($DETERM test-randomized-delay 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: randomized-delay all assertions"; then
  echo ""
  echo "  PASS: randomized-delay unit test"
  exit 0
else
  echo ""
  echo "  FAIL: randomized-delay had assertion failures"
  exit 1
fi
