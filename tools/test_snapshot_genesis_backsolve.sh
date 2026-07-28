#!/usr/bin/env bash
# SnapshotRestoreGateAudit (round-10 apply-path invariant audit, wf_a941ce55) —
# the fieldless-snapshot genesis_total back-solve is the EXACT inverse of the
# 6-term expected_total(), including the §3.22 accumulated_shielded_ term.
#
# When a snapshot OMITS genesis_total, restore_from_snapshot back-solves it from
# the loaded live sum + A1 counters (chain.cpp:2628-2637). That back-solve MUST be
# the exact inverse of expected_total() (chain.hpp:590 = genesis + subsidy + inbound
# - slashed - outbound - shielded). Before the fix it omitted the §3.22 NEGATIVE
# term accumulated_shielded_ (restored at :2443, BEFORE the back-solve), so a
# fieldless snapshot carrying accumulated_shielded_>0 back-solved genesis_total_
# UNDER by exactly that amount => expected_total() == live - shielded != live =>
# the A1 re-check FAILS CLOSED (require_supply_invariant at :2693, else the first
# post-restore apply at :1868) and REJECTS a VALID snapshot. Not a live bug today
# (serialize writes genesis_total UNCONDITIONALLY at :2212, so any fieldless
# snapshot predates §3.22 => shielded==0), but a latent liveness landmine.
#
# The gate hand-builds the otherwise-unreachable fieldless+shielded snapshot and
# asserts the back-solve reproduces an A1-consistent genesis. Falsify-on-mutant:
# delete the `+ c.accumulated_shielded_` term -> genesis under-computed by X, so the
# fieldless+shielded asserts flip RED; the shield-free control (X==0) stays green
# (byte-neutral on every honest snapshot).
#
# Run from repo root: bash tools/test_snapshot_genesis_backsolve.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== snapshot-genesis-backsolve — fieldless back-solve is the 6-term inverse of expected_total() ==="
OUT=$($DETERM test-snapshot-genesis-backsolve 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-snapshot-genesis-backsolve"; then
  echo ""
  echo "  PASS: snapshot-genesis-backsolve unit test"
  exit 0
else
  echo ""
  echo "  FAIL: snapshot-genesis-backsolve had assertion failures"
  exit 1
fi
