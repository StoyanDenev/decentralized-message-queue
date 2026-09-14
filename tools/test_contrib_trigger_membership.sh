#!/usr/bin/env bash
# S-058 (docs/SECURITY.md; DECISION-LOG 2026-08-13 `3dbe5f2` K3) — a
# registered NON-member's Phase-1 contrib wedged the round.
#
# on_contrib deliberately admits a contrib from any registry signer (it may
# precede this node's committee computation) but triggered the Phase-1 ->
# Phase-2 transition when the pending MAP SIZE reached K, and
# enter_block_sig_phase cancelled the Phase-1 timer BEFORE checking that every
# committee member's contrib was present. One contrib from a registered
# non-member therefore (a) made the size match with a member still missing ->
# timer cancelled, call returned, no timeout, no abort claim: the round wedged
# on every committee member that received it; (b) afterwards the size could
# never equal K again, so even the missing member's contrib could not trigger
# the transition. Fix: trigger on committee COMPLETENESS
# (committee_contribs_complete_locked) and release the timer only after the
# completeness loop.
#
# Harness: one node under a virtual-time loop (M=4, K=3 genesis; logical time
# advanced once so the startup grace fires and node0 enters CONTRIB as a
# member); contribs injected via on_contrib_for_test; round state read via
# round_probe_for_test (phase, committee, Phase-1 timer armed, pending count).
#
# Falsify-on-mutant (executed 2026-09-14, reverted):
#   M1 restore the size-equality trigger in on_contrib -> the two recovery
#      arms flip RED (with the map at K+1 the old trigger can never fire, so
#      the last member's contrib no longer reaches Phase 2).
#   M3 restore the size-equality trigger in start_contrib_phase (pre-phase
#      site) -> the "pre-phase site ... straight to Phase 2" arm flips RED.
#   M2 move contrib_timer_.cancel() back above the completeness loop (keeping
#      the completeness trigger) -> the "direct transition call ... STILL
#      ARMED" arm flips RED (the completeness trigger alone hides the ordering
#      from on_contrib, so the gate calls the transition directly through
#      enter_block_sig_phase_for_test).
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_contrib_trigger_membership.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-058: a registered non-member contrib neither triggers Phase 2 nor kills the Phase-1 timer ==="
OUT=$("$DETERM" test-contrib-trigger-membership 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-contrib-trigger-membership"; then
  echo "  PASS: test_contrib_trigger_membership"
  exit 0
else
  echo "  FAIL: test_contrib_trigger_membership (exit $rc)"
  exit 1
fi
