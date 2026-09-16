#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — increment 2: abort-event
# SUSPENSION RECORD (the S-032 family; D13, 2026-09-16 — the round-1 stake
# deduction is retired) over a multi-block randomized-Byzantine TRACE.
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path.
#
# `determ test-fa-abort-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace that injects AbortEvents (a forced repeat-target schedule
# against one small-stake validator, random Phase-1 targets, and scheduled
# Phase-2 no-ops) via the REAL Chain::append apply path, alongside an
# abort-free TWIN chain, and asserts after every block:
#   - every validator's stake equals its genesis value and
#     accumulated_slashed stays 0 (a round-1 abort moves NO stake — D13);
#   - S-032 abort_records cache exact per domain (count increments +
#     last_block updates; Phase-2 rounds NEVER recorded);
#   - A1: expected_total == live_total_supply after every block;
#   - every NON-`b:` leaf (s:/a:/r: of every domain + the five A1 counters,
#     via state_proof value hashes) byte-identical to the twin; the `b:`
#     record leaf present on the aborted chain only (positive control — the
#     record IS committed, so state_root equality is NOT expected); the
#     block hash differs from the twin's (the event is in the block);
#   - non-vacuous (fresh + repeat targets, the 25-stake validator hit >= 3
#     times keeps 25, real Phase-2 no-ops, a non-zero inert suspension_slash);
#   - negative control (an event-free block keeps the twin equality);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness inc-2: abort-event suspension-record multi-block trace (real engine, D13) ==="
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
