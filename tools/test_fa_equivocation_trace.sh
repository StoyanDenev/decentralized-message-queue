#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — increment 1: equivocation
# EVIDENCE NEUTRALITY over a multi-block randomized TRACE (D4, 2026-09-16: an
# EquivocationEvent baked into a block moves NO L1 state).
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path. This is
# the consensus-layer analog of test-supply-invariant-fuzz (which already covers
# the ECONOMIC A1 trace).
#
# `determ test-fa-equivocation-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace that injects EquivocationEvents (first-seen targets and REPEAT
# submissions, both event kinds) via the REAL Chain::append apply path, next to
# an event-free TWIN chain fed the same blocks minus the events, and asserts
# after every block:
#   - every validator's stake and registry entry exactly at genesis;
#   - accumulated_slashed == 0;
#   - A1: expected_total == live_total_supply;
#   - state_root == the twin's (no consequence of ANY kind);
#   - block hash != the twin's (positive control: the record really is there);
#   - non-vacuous (first-seen AND repeat events were baked);
#   - negative control (an event-free block keeps the twin equality);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness inc-1: equivocation-evidence neutrality trace (real engine, D4) ==="
OUT=$($DETERM test-fa-equivocation-trace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-equivocation-trace all assertions"; then
  echo ""
  echo "  PASS: fa-equivocation-trace harness"
  exit 0
else
  echo ""
  echo "  FAIL: fa-equivocation-trace had assertion failures"
  exit 1
fi
