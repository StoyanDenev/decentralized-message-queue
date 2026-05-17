#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the apply-side
# handling of EquivocationEvent (FA6 full equivocation slashing +
# deregistration per rev.8 follow-on).
#
# Each EquivocationEvent baked into a finalized block (validator
# already verified the two-sig proof against the equivocator's
# registered Ed25519 key):
#   (a) Forfeits the equivocator's ENTIRE staked balance — the primary
#       economic disincentive in STAKE_INCLUSION mode. Much harsher
#       than SUSPENSION_SLASH because equivocation is a deliberate
#       double-sign attack, not just absence.
#   (b) Marks the equivocator's registry entry inactive_from =
#       b.index + 1, removing them from committee selection regardless
#       of stake. This is what actually removes them in
#       DOMAIN_INCLUSION mode (where stake is already 0).
#   (c) Bumps accumulated_slashed_ by the full forfeit amount (A1).
#
# The dual mechanism (stake forfeit + deregistration) unifies the
# two inclusion modes — neither mode leaves the equivocator able to
# rejoin without registering a fresh domain.
#
# Network-level integration via tools/test_equivocation_slashing.sh;
# this in-process test pins the apply semantics in <1s.
#
# Implementation note: every block sets `b.creators = {"alice"}` so
# fees route back and A1 stays balanced (the standard apply-test
# gotcha). The two sigs in the EquivocationEvent are default-
# constructed — apply doesn't re-verify (validator's job); this test
# focuses purely on apply-path semantics.
#
# ~10 assertions in five blocks:
#
#   Full stake forfeiture (1):
#     - stake → 0 after equivocation
#
#   Registry deactivation (2):
#     - baseline: inactive_from sentinel UINT64_MAX
#     - post-apply: inactive_from == b.index + 1
#
#   Robustness on ghost equivocator (2):
#     - apply succeeds (no crash on missing stake/registry)
#     - other domains unaffected
#
#   A1 supply invariant (3):
#     - accumulated_slashed bumped by exactly the full stake
#     - live supply decreases by exactly the forfeit
#     - expected == live after forfeit
#
#   Determinism (1):
#     - two chains see same equivocation → same state_root
#
# Run from repo root: bash tools/test_equivocation_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== EquivocationEvent apply (FA6 full forfeit + deregistration, A1) ==="
OUT=$($DETERM test-equivocation-apply 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: equivocation-apply all assertions"; then
  echo ""
  echo "  PASS: equivocation-apply unit test"
  exit 0
else
  echo ""
  echo "  FAIL: equivocation-apply had assertion failures"
  exit 1
fi
