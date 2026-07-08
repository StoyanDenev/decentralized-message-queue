#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — increment 2: abort-event
# SUSPENSION slashing (the S-032/SUSPENSION_SLASH family) over a multi-block
# randomized-Byzantine TRACE.
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path.
#
# `determ test-fa-abort-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace that injects AbortEvents (a forced repeat-target schedule that
# drains one small-stake validator, random Phase-1 targets, and scheduled
# Phase-2 no-ops) via the REAL Chain::append apply path, and asserts after
# every block:
#   - EXACT stake accounting: each Phase-1 abort deducts exactly
#     min(SUSPENSION_SLASH, stake) — full, PARTIAL, and floored-at-0 ZERO
#     deducts all exercised (never negative);
#   - accumulated_slashed == exact running total, monotone non-decreasing;
#   - S-032 abort_records cache exact per domain (count increments +
#     last_block updates; Phase-2 rounds NEVER recorded);
#   - A1: expected_total == live_total_supply after every block;
#   - non-vacuous (fresh + repeat targets, real stake movement, >=1 partial
#     and >=1 zero deduct, real Phase-2 no-ops);
#   - negative control (an event-free block moves nothing);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness inc-2: abort-event suspension-slash multi-block trace (real engine) ==="
OUT=$($DETERM test-fa-abort-trace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-abort-trace all assertions"; then
  echo ""
  echo "  PASS: fa-abort-trace harness"
  exit 0
else
  echo ""
  echo "  FAIL: fa-abort-trace had assertion failures"
  exit 1
fi
