#!/usr/bin/env bash
# deterministic-scheduler inc.5 — ADVERSARIAL schedules on the inc.4 substrate.
#
# The wall-clock FA4 harness (test_fa_partition_virtual.sh) had to treat loss
# liveness as a NON-GATING diagnostic and hedge every check behind budgets,
# grace sleeps, and quiescence barriers, because wall time on a contended host
# is adversarial in its own right. Here the same faults run under the inc.4
# GlobalScheduler: one thread, virtual loop time, a stepped consensus
# VirtualClock, per-node SeededRng, per-link seeded drop RNGs advanced in
# scheduler order — the ENTIRE adversarial run replays byte-for-byte and every
# liveness property is a HARD gate.
#
# Assertions (all hard):
#   1. LOSS LIVENESS — +2 blocks finalized under 10% per-frame loss on every
#      link (the S-047 retry property, previously non-gating);
#   2. LOSS FORK-FREEDOM — all 5 nodes byte-agree on every finalized block;
#   3. PARTITION LIVENESS — the 4-node majority finalizes +2 with node4
#      isolated (deterministic abort/reselect around the unreachable member);
#   4. PARTITION SAFETY — node4's held chain is a byte-identical PREFIX of
#      the majority's;
#   5. S-050 VALVE REGRESSION — after heal, stepping the injected clock past
#      the stall windows trips Node::maybe_stall_reset_locked (the valve reads
#      clock_.steady_now(), the §Q1 seam): stall re-probe + tolerance-0 sync +
#      the A4.4 chunk path re-converge the stranded node4 onto the majority
#      chain — deterministic, where the wall-clock harness could only NOTE it;
#   6. REPLAY — the whole adversarial schedule run twice is byte-identical
#      (terminal per-node head_hash + state_root + scheduler trace hash).
#
# In-process (no cluster) — FAST-eligible.
#
# Run from repo root: bash tools/test_fa_adversarial_deterministic.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== fa-adversarial-deterministic: loss/partition/heal/valve under the global scheduler (inc.5) ==="
OUT=$($DETERM test-fa-adversarial-deterministic 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-adversarial-deterministic all assertions"; then
  echo ""
  echo "  PASS: fa-adversarial-deterministic unit test"
  exit 0
else
  echo ""
  echo "  FAIL: fa-adversarial-deterministic had assertion failures"
  exit 1
fi
