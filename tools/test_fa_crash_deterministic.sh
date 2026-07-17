#!/usr/bin/env bash
# deterministic-scheduler inc.6 — node CRASH + RESTART-REJOIN on the inc.4
# substrate.
#
# The threaded failover harness (test_fa_liveness_virtual.sh) samples the
# crash fault dimension probabilistically: the S-047 wedge modes needed 12+
# wall-clock loops per platform to reproduce, and its failover gate had to be
# weakened to a 3-of-4 MAJORITY (pre-A4, a survivor stranded on a minority
# same-height fork could not reorg). Here the same crash runs under the inc.4
# GlobalScheduler: the kill lands at a deterministic drain boundary with the
# dead node's final sends still queued on SOME survivor loops — the S-047
# asymmetric-death shape — and the whole schedule replays byte-for-byte.
#
# Assertions (all hard):
#   1. STEADY STATE — all 5 nodes reach height 3 under the deterministic
#      drive;
#   2. FAILOVER LIVENESS (ALL-4, stronger than the threaded majority gate) —
#      every survivor finalizes +3 past the kill baseline (S-047
#      abort/reselect; a stranded survivor reorgs via A4; a straggler is
#      recovered by the S-050 valve, clock stepped ≤10s at quiescent points);
#   3. FAILOVER FORK-FREEDOM — the 4 survivors byte-agree on every settled
#      block;
#   4. REJOIN — the dead node's identity restarts on fresh loop/transport
#      (same key, same saved chain tail) and catches up over the REAL
#      GET_CHAIN/CHAIN_RESPONSE sync path, deterministically;
#   5. OUTAGE ADOPTION — a block finalized while the node was dead is
#      byte-identical on the rejoined node;
#   6. REPLAY — the whole crash/failover/rejoin schedule run twice is
#      byte-identical (kill height, terminal per-node head_hash + state_root,
#      concatenated per-phase scheduler trace hash).
#
# In-process (no cluster) — FAST-eligible.
#
# Run from repo root: bash tools/test_fa_crash_deterministic.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== fa-crash-deterministic: crash/failover/rejoin under the global scheduler (inc.6) ==="
OUT=$($DETERM test-fa-crash-deterministic 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-crash-deterministic all assertions"; then
  echo ""
  echo "  PASS: fa-crash-deterministic unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fa-crash-deterministic had assertion failures"
  exit 1
fi
