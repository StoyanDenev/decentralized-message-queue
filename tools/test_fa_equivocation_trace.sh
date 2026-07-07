#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — increment 1: equivocation
# SLASHING over a multi-block randomized-Byzantine TRACE.
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path. This is
# the consensus-layer analog of test-supply-invariant-fuzz (which already covers
# the ECONOMIC A1 trace).
#
# `determ test-fa-equivocation-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace that injects EquivocationEvents (a mix of FRESH targets and
# DUPLICATE re-submissions) via the REAL Chain::append apply path, and asserts
# after every block:
#   - fresh slash: equivocator's stake -> 0, registry deactivated,
#     accumulated_slashed bumped by exactly its stake;
#   - DUPLICATE: idempotent (no double-slash — stake stays 0, counter frozen);
#   - A1: expected_total == live_total_supply after every block;
#   - accumulated_slashed monotone non-decreasing;
#   - exact: accumulated_slashed == Σ distinct-slashed stakes (no double-count);
#   - non-vacuous (real slashes AND real duplicates occurred);
#   - negative control (an event-free block moves nothing);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness inc-1: equivocation-slashing multi-block trace (real engine) ==="
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
