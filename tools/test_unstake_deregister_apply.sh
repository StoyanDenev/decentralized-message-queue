#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for UNSTAKE + DEREGISTER
# apply paths — the stake-lifecycle complement to STAKE.
#
# DEREGISTER:
#   (a) Charges fee from sender (silent skip on insufficient balance).
#   (b) Sets registry inactive_from = height + derive_delay (randomized
#       so the operator can't pick their own deactivation height).
#   (c) Sets stake unlock_height = inactive_from + unstake_delay_ so
#       any subsequent UNSTAKE is gated until the deactivation +
#       cooldown window has elapsed.
#   (d) Increments next_nonce.
#
# UNSTAKE:
#   (a) Requires 8-byte LE payload encoding the unstake amount.
#   (b) Charges fee, with fee REFUND on failed UNSTAKE (so honest users
#       aren't penalized for a too-early request).
#   (c) Gated on: stake entry exists AND locked >= amount AND
#       height >= unlock_height. Failure on ANY of these refunds fee
#       and skips the unlock.
#   (d) On success: deducts from locked, adds to balance, nonce++.
#
# Network-level tests exercise this end-to-end via 3-node clusters;
# this in-process test pins the apply semantics in <1s.
#
# Implementation note: every block sets `b.creators = {"alice"}` so
# fees route back and A1 stays balanced (the standard apply-test
# gotcha). The DEREGISTER → advance → UNSTAKE flow uses
# `set_unstake_delay(1)` to avoid burning 1000+ blocks just to reach
# the unlock_height.
#
# ~16 assertions in six blocks:
#
#   UNSTAKE too-early (3):
#     - stake unchanged, balance unchanged (fee refunded), nonce++
#
#   DEREGISTER sets inactive_from + unlock_height (3):
#     - inactive_from = height + derive_delay (> height)
#     - stake unlock_height = inactive_from + unstake_delay
#     - nonce++
#
#   DEREGISTER on non-registrant (2):
#     - nonce++ (defensive no-op)
#     - still no registry entry
#
#   UNSTAKE success after unlock (3):
#     - stake reduced by amount
#     - balance += amount (fee net-zero with creator fee-return)
#     - height advance to unlock_height verified
#
#   UNSTAKE insufficient locked (2):
#     - stake unchanged, balance unchanged
#
#   A1 invariant (2):
#     - live total unchanged across UNSTAKE (value moves stake → balance)
#     - expected == live post-apply
#
# Run from repo root: bash tools/test_unstake_deregister_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== UNSTAKE + DEREGISTER apply (stake lifecycle) ==="
OUT=$($DETERM test-unstake-deregister-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: unstake-deregister-apply all assertions"; then
  echo ""
  echo "  PASS: unstake-deregister-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: unstake-deregister-apply had assertion failures"
  exit 1
fi
