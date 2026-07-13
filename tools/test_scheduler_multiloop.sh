#!/usr/bin/env bash
# deterministic-scheduler inc.4 — the GLOBAL multi-loop scheduler.
#
# Generalizes the inc.3 single-node external drive to a 3-of-5 (M=5, K=3)
# cluster: FIVE real node::Node instances, each on its own virtual-time
# VirtualEventLoop, sharing ONE VirtualNetwork + ONE FROZEN VirtualClock, each
# with a distinct fixed-seed identity key AND a distinct fixed crypto::SeededRng,
# all started via start_external() (NO loop threads, NO save threads) and driven
# ENTIRELY by net::GlobalScheduler — fixpoint-drain ready work across every loop,
# then fire the single global-earliest virtual timer (after lockstepping every
# loop's virtual now onto the global clock). This is the substrate for the
# reliable loss-liveness gate + a deterministic S-048-heals-under-loss repro
# (inc.5): a fixed schedule replays byte-for-byte.
#
# Assertions:
#   1. LIVENESS — 5 nodes finalize blocks 1..3 under pure external drive (the
#      cross-loop contribs/sigs are delivered as ready work, so a 3-of-5 round
#      completes with no wall thread);
#   2. AGREEMENT — blocks 1..3 are byte-identical across all 5 nodes (no fork);
#   3. REPLAY (head/state) — two same-seed runs reach an identical per-node
#      terminal head_hash + state_root;
#   4. REPLAY (block list) — the ordered per-height block list is identical;
#   5. REPLAY (schedule) — the scheduler action-trace hash is identical (the only
#      signal that catches an interleave that diverges yet converges to the same
#      chain — the SCHEDULE determinism inc.4 introduces).
#
# In-process (no cluster) — FAST-eligible.
#
# Run from repo root: bash tools/test_scheduler_multiloop.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== scheduler-multiloop: global multi-loop deterministic drive (inc.4) ==="
OUT=$($DETERM test-scheduler-multiloop 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: scheduler-multiloop all assertions"; then
  echo ""
  echo "  PASS: scheduler-multiloop unit test"
  exit 0
else
  echo ""
  echo "  FAIL: scheduler-multiloop had assertion failures"
  exit 1
fi
