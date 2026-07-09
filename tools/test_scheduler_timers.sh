#!/usr/bin/env bash
# Deterministic scheduler — increment 2: the loop-local VIRTUAL-TIME timer
# source on VirtualEventLoop (DeterministicSchedulerDesign.md §2b). A
# wall-clock-free, deterministic timer queue the no-thread FA4 scheduler
# advances — the prerequisite for byte-reproducible FA4 traces + the
# deterministic S-048 reproduction.
#
# Pins (see test-scheduler-timers in src/main.cpp):
#   * earliest-deadline-first fire order + virtual `now` tracks each deadline
#   * the 200 ms schedule drains in ~0 wall time (virtual, never slept — the
#     proof it bypassed the real TimerService)
#   * same-deadline ties fire in schedule (seq) order — the stable total order
#   * cancel-by-id suppresses; pending_timer_count tracks; double-cancel is
#     idempotent
#   * a firing callback may re-arm a later timer (runs outside the timer lock)
#   * posted closures drain before the next timer fires (ready-work-before-time)
#   * the same schedule replays byte-identical (determinism)
#   * LoopTimer (the real consumer) routes through the virtual source unchanged
#
# The DEFAULT TimerService path is byte-neutral — proven by test_net_virtual.sh
# staying green (it exercises the real TimerService, untouched here).
# Pure std, no OS resource — identical assertions on MSVC + GCC. In-process,
# <1s — FAST=1 eligible.
#
# Run from repo root: bash tools/test_scheduler_timers.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== deterministic scheduler inc.2: virtual-time timer source ==="
OUT=$($DETERM test-scheduler-timers 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: scheduler-timers"; then
  echo ""
  echo "  PASS: scheduler-timers unit test"
  exit 0
else
  echo ""
  echo "  FAIL: scheduler-timers had assertion failures"
  exit 1
fi
