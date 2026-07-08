#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — MIXED multi-event
# COMPOSITION over a multi-block randomized-Byzantine TRACE (the
# FA-Apply-15 MultiEventComposition canonical F-1 target).
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path.
#
# `determ test-fa-multi-event-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace where each block randomly carries 0-2 TRANSFER txs and/or an
# EquivocationEvent and/or a Phase-1 AbortEvent — all injected via the REAL
# Chain::append apply path — and asserts after every block, JOINTLY:
#   - A1: expected_total == live_total_supply;
#   - accumulated_slashed EXACT running total across BOTH slash kinds
#     (equivocation full forfeit + abort SUSPENSION_SLASH), monotone;
#   - sender balances + nonces match a shadow model updated per the real
#     apply rules (fees route to the block creator); nonces monotone;
#   - validator stakes match the shadow, never negative/underflowed;
#   - non-vacuous (every event kind occurred; >=1 block carried >=2 kinds
#     simultaneously); negative control (an event-free block moves nothing);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness: mixed multi-event composition trace (real engine) ==="
OUT=$($DETERM test-fa-multi-event-trace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-multi-event-trace all assertions"; then
  echo ""
  echo "  PASS: fa-multi-event-trace harness"
  exit 0
else
  echo ""
  echo "  FAIL: fa-multi-event-trace had assertion failures"
  exit 1
fi
