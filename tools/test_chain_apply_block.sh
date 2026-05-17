#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for `Chain::append` /
# `apply_transactions` — the central state-transition function under
# every block-application path in the system.
#
# Genesis bootstrap (b.index == 0) installs `initial_state` into
# `accounts_` + `stakes_` + `registrants_` + `genesis_total_`. Regular-
# block apply (b.index > 0) replays each tx (TRANSFER / REGISTER /
# STAKE / UNSTAKE / DEREGISTER / etc.), charges fees, enforces nonce
# gating, distributes fees + subsidy to `b.creators`, updates the A1
# unitary-supply counters, and asserts the unitary-supply invariant
# (`expected_total == live_total_supply`) before returning.
#
# Network-level integration tests (test_bearer.sh, test_a1_unitary_*.sh,
# etc.) exercise this path end-to-end via 3-node gossip; this in-process
# test pins the read-side semantics in <1s.
#
# **Critical implementation gotcha** (captured here so future test
# additions don't repeat the discovery cost): every Block passed to
# `Chain::append` that contains txs with non-zero `fee` MUST set
# `b.creators` non-empty. Otherwise apply charges the fee from the
# sender but skips the distribution loop (which checks
# `!b.creators.empty()`) and the A1 invariant fires inside apply,
# throwing — and if uncaught at the top level the runtime triggers
# STATUS_STACK_BUFFER_OVERRUN via std::terminate. The fix below uses
# `b.creators = {"alice"}` so fees route back to alice and A1 holds.
#
# 22 assertions in eight blocks:
#
#   Genesis bootstrap (8):
#     - chain.height() == 1 after append
#     - accounts populated from initial_state.balance (alice + bob)
#     - alice stake_entry created (non-zero stake)
#     - bob no stake entry (stake=0 not added)
#     - alice registry entry (ed_pub non-zero from initial_creators)
#     - bob no registry entry (ed_pub zero from initial_balances merge)
#     - genesis_total == sum(balances + stakes) == 1700
#     - A1 invariant baseline: expected_total == live_total_supply
#
#   Empty block apply (1):
#     - state preserved, height advances to 2
#
#   TRANSFER apply (5):
#     - balance debits + credits + nonce++ (fee routes to creator)
#     - bad nonce silently skipped, nonce not incremented
#     - insufficient balance silently skipped
#
#   STAKE apply (2):
#     - stake_entry locked amount += payload (8-byte LE)
#     - sender balance debited (amount + fee)
#
#   REGISTER apply (5):
#     - seed TRANSFER funds carol's balance
#     - REGISTER creates RegistryEntry for new domain
#     - active_from = height + derive_delay (deterministic from
#       cumulative_rand + tx.hash; > height)
#     - inactive_from sentinel UINT64_MAX
#     - nonce++
#
#   prev_hash continuity (1):
#     - append with wrong prev_hash throws (chain integrity)
#     - throwing append: no state mutation visible (apply rollback)
#
#   A1 invariant sequence (4):
#     - invariant holds after genesis + empty + TRANSFER + STAKE
#
# Run from repo root: bash tools/test_chain_apply_block.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain::append / apply_transactions (central state-transition surface) ==="
OUT=$($DETERM test-chain-apply-block 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chain-apply-block all assertions"; then
  echo ""
  echo "  PASS: chain-apply-block unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chain-apply-block had assertion failures"
  exit 1
fi
