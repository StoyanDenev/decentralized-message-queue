#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the A5 Phase 2
# PARAM_CHANGE apply path: stage at block N, activate at the block
# whose index >= effective_height.
#
# `Chain::activate_pending_params(current_height)` runs at the start
# of each `apply_transactions(b)` for `b.index > 0`. It iterates the
# `pending_param_changes_` map in ascending-by-effective_height order
# (std::map), activates every entry with `effective_height <=
# current_height`, mutates the named chain-storage field, invokes the
# optional `param_changed_hook_` (the Node-installed callback so
# validator-side fields can be mirrored), and erases the activated
# bucket.
#
# Names that map to chain-storage fields:
#   - MIN_STAKE         → Chain::min_stake_
#   - SUSPENSION_SLASH  → Chain::suspension_slash_
#   - UNSTAKE_DELAY     → Chain::unstake_delay_
#
# Names with no chain-storage are passed to the hook only (no chain
# mutation); the Node uses the hook to update validator-side fields
# like bft_escalation_threshold, param_keyholders, param_threshold.
#
# Unknown names are activated as silent no-ops on chain storage (the
# validator already enforces the whitelist; unknowns at apply mean
# a future-version chain — fail-soft at apply, fail-loud at validate).
# The hook still fires so the Node can forward.
#
# Network-level: `tools/test_governance.sh` exercises the full
# governance flow (PARAM_CHANGE tx → validator → stage → apply →
# activation). This in-process test pins the apply-side semantics in
# <1s.
#
# ~16 assertions in eight blocks:
#
#   Staging contract (3):
#     - default field values (baseline)
#     - stage only: field unchanged before activation height
#     - pending_param_changes reflects the staged entry
#
#   Activation (3):
#     - activation: chain field mutated at first apply where
#       block.index >= effective_height
#     - pending map drained after activation
#     - effective_height=0 activates at the first non-genesis apply
#
#   Multi-param same-height (1):
#     - 3 params staged at same height: all activated in apply order
#
#   Multi-param different-height (4):
#     - earlier-height entry activates first; later still pending
#     - all-heights-reached: pending map empty
#
#   Unknown name (2):
#     - chain storage unchanged
#     - hook still fires (Node forwarding path)
#
#   Hook for known params (2):
#     - hook fires AND chain field updated
#
#   Determinism (1):
#     - two chains same staging → same state_root
#
# Run from repo root: bash tools/test_param_change_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A5 PARAM_CHANGE apply (stage → activate at effective_height → mutate) ==="
OUT=$($DETERM test-param-change-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: param-change-apply all assertions"; then
  echo ""
  echo "  PASS: param-change-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: param-change-apply had assertion failures"
  exit 1
fi
