#!/usr/bin/env bash
# FA harness (real-engine, self-contained path) — merge-event increment:
# R7 MERGE_EVENT (regional-shard merge) state machine over a multi-block
# randomized-adversarial TRACE.
#
# Per the owner decision (2026-07-07), determ-dsf stays a self-contained TOY
# framework; the F-1/FA4 gap (multi-block randomized-Byzantine CONSENSUS
# properties over the REAL engine) is closed by `test-fa-*` harnesses that live
# in the determ binary — which already links the real Chain/apply path.
#
# `determ test-fa-merge-trace` drives a seeded (SplitMix64), reproducible
# 48-block trace injecting merge BEGIN/END events (fresh BEGINs, duplicate
# BEGINs with a guaranteed-different region, valid ENDs, stale ENDs,
# bad-partner attempts) via the REAL Chain::append apply path, and asserts
# after every block:
#   - merge_state() equals an independent model FIELD-FOR-FIELD (and the
#     is_shard_merged / shards_absorbed_by read APIs agree with it);
#   - duplicate BEGIN is FIRST-WRITE-WINS (original pairing + region survive);
#   - stale END + bad-partner events are exact no-ops;
#   - fee + nonce are consumed on EVERY event, incl. rejected mutations;
#   - merge events move NO value: supply constant, A1 after every block;
#   - non-vacuous (every event kind actually occurred);
#   - negative control (an event-free block moves nothing);
#   - determinism (same seed -> identical final state root).
#
# Fully in-process, <1s, no network. See docs/proofs/RealEngineFAHarness.md.

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== FA harness: merge-event multi-block trace (real engine) ==="
OUT=$($DETERM test-fa-merge-trace 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: fa-merge-trace all assertions"; then
  echo ""
  echo "  PASS: fa-merge-trace harness"
  exit 0
else
  echo ""
  echo "  FAIL: fa-merge-trace had assertion failures"
  exit 1
fi
