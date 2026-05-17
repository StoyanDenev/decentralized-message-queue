#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the four chain
# state structs and their sentinel semantics:
#
#   * AccountState   — balance + next_nonce
#   * StakeEntry     — locked + unlock_height (UINT64_MAX while active)
#   * RegistryEntry  — ed_pub + registered_at + active_from +
#                       inactive_from (UINT64_MAX while active) + region
#   * DAppEntry      — service_pubkey + endpoint_url + topics +
#                       retention + metadata + registered_at +
#                       active_from + inactive_from (UINT64_MAX)
#
# The UINT64_MAX sentinel for `unlock_height` and `inactive_from` is
# a protocol-critical invariant: "active until set to a concrete
# height by an apply-path event". A regression to a zero default
# would cause every fresh stake to look immediately unlockable
# (every fresh registrant to look immediately deregistered),
# breaking suspension policy + UNSTAKE semantics.
#
# 30 assertions covering:
#
#   AccountState (2): default balance=0 + next_nonce=0;
#     assignment + preservation.
#
#   StakeEntry (5): default locked=0 + unlock_height=UINT64_MAX
#     (active-stake sentinel); locked + unlock_height assignment
#     (concrete post-DEREGISTER value); sentinel-vs-concrete
#     distinguishability.
#
#   RegistryEntry (7): default ed_pub=zero, registered_at=0,
#     active_from=0, inactive_from=UINT64_MAX (active sentinel —
#     same pattern as StakeEntry.unlock_height), region="" (global
#     pool member); post-DEREGISTER concrete inactive_from
#     distinguishable from sentinel; region tag round-trip.
#
#   DAppEntry (12): default service_pubkey=zero, endpoint_url="",
#     topics empty, retention=0 (full retention), metadata empty,
#     registered_at=0, active_from=0, inactive_from=UINT64_MAX
#     (active sentinel); all field assignments preserved.
#
#   Cross-struct sentinel consistency (3): RegistryEntry and
#     DAppEntry share the same UINT64_MAX inactive_from sentinel;
#     StakeEntry.unlock_height uses the same sentinel.
#
# Apply paths compare these sentinels against block.index in the
# same way across all three types, so the consistency check is
# protocol-meaningful — a divergent sentinel for any one type
# would break the comparison semantics.
#
# Run from repo root: bash tools/test_state_types.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Chain state struct defaults — AccountState / StakeEntry / RegistryEntry / DAppEntry ==="
OUT=$($DETERM test-state-types 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: state-types all assertions"; then
  echo ""
  echo "  PASS: state-types unit test"
  exit 0
else
  echo ""
  echo "  FAIL: state-types had assertion failures"
  exit 1
fi
