#!/usr/bin/env bash
# deterministic-scheduler inc.3 — Node::start_external() (no-self-thread entry).
#
# A single M=K=1 Node is built on an injected VirtualEventLoop (virtual time
# enabled) + VirtualTransport + VirtualClock, started via start_external() — which
# spawns NO loop worker thread, NO async save thread, and does NOT block — and
# driven ENTIRELY by the caller advancing logical time (run_until_idle +
# advance_to_next_timer). This is the enabler for A4's deterministic S-048
# reorg reproduction: no wall-clock worker concurrency ⇒ a scenario replays
# byte-identically.
#
# Assertions:
#   1. the externally-driven node self-produces >=4 blocks with NO loop thread
#      (every round's contrib/block-sig timer fires only because the driver
#      advances virtual time);
#   2. virtual_now advanced past the 1500ms grace deadline (logical time, not
#      steady_clock, drove the rounds);
#   3. two runs produce the SAME block COUNT — the logical-time schedule is
#      deterministic (block-CONTENT byte-replay additionally needs a
#      deterministic-RNG seam: each round draws a fresh commit-reveal secret
#      from OS entropy; that seam is the remaining piece for A4);
#   4. both runs reach the SAME virtual time.
#
# In-process (no cluster) — FAST-eligible.
#
# Run from repo root: bash tools/test_scheduler_external.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== scheduler-external: Node::start_external no-self-thread drive (inc.3) ==="
OUT=$($DETERM test-scheduler-external 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: scheduler-external all assertions"; then
  echo ""
  echo "  PASS: scheduler-external unit test"
  exit 0
else
  echo ""
  echo "  FAIL: scheduler-external had assertion failures"
  exit 1
fi
