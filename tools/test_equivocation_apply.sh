#!/usr/bin/env bash
# In-process gate for the apply-side handling of EquivocationEvent under the
# owner decision of 2026-09-16 (DECISION-LOG D4, O-1 option (b)): an
# EquivocationEvent baked into a finalized block is an on-chain EVIDENCE
# RECORD with NO L1 consequence. `Chain::apply_transactions` reads nothing
# from it — no stake forfeiture, no registry deactivation, no counter.
#
# Why the rule exists (log 2026-08-12 / 2026-08-13): the former full-forfeit
# + deregister branch cost an HONEST validator its whole stake on a valve /
# re-round same-height pair with no attacker signature, and made the R-8
# digest demotion unsound (ordering result 7570989).
#
# Network-level closed loop via tools/test_equivocation_slashing.sh; this
# in-process gate pins the apply semantics in <1s, at the layer where the
# rule lives. Mutants M1-M8 (audit record 2026-09-16) each go RED across the
# five apply-side gates: restoring `locked = 0` (A1 throws), the forfeit, the
# deregistration, the whole loop, a NEW consequence (abort_records++), a
# consequence hidden inside the DEREGISTER unlock window and one keyed on a
# zero stake floor (both caught by test-equivocation-multi), and one keyed on
# the contrib evidence family (caught by the two traces, which draw both kinds).
#
# Implementation note: every block sets `b.creators = {"alice"}` so fees
# route back and A1 stays balanced. The two sigs in the EquivocationEvent
# are default-constructed — apply doesn't re-verify (validator's job).
#
# 14 assertions in four scenarios:
#
#   No consequence (5 + baseline 2):
#     - stake unchanged; registry inactive_from sentinel unchanged
#     - accumulated_slashed stays 0; live supply unchanged; A1 holds
#
#   Neutrality + positive control (4):
#     - state_root(with event) == state_root(without event)
#     - abort_records identical
#     - the event IS in the appended block; the block hash differs from
#       the event-free block (the record persists — the check is not vacuous)
#
#   Robustness on ghost equivocator (2):
#     - apply succeeds (no crash on missing stake/registry); others unaffected
#
#   Determinism (1):
#     - two chains apply the same event → same state
#
# Run from repo root: bash tools/test_equivocation_apply.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== EquivocationEvent apply (D4: evidence record, no L1 consequence; neutrality + A1) ==="
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
