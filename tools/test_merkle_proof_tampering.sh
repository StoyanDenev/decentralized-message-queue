#!/usr/bin/env bash
# v2.1 / S-035 follow-on — exhaustive Merkle inclusion-proof tamper-
# detection coverage. Companion to tools/test_merkle.sh (which pins
# the positive surface and a few representative negative paths).
#
# This test pins the FULL negative space for crypto::merkle_verify:
# every byte-level field a proof carries can be tampered, and every
# tamper MUST be rejected (reduces to SHA-256 collision-resistance
# per docs/proofs/Preliminaries.md §2.1).
#
# Why a dedicated test: the v2.2 light-client surface (state_proof
# RPC, verify-state-proof CLI) and v2.3 trustless fast sync both
# trust merkle_verify as the ground-truth gate. A single missed
# negative path would silently let a malicious snapshot server forge
# state inclusion. Reducing the negative space to a fixed mechanical
# input set we can pin defends that contract.
#
# Scenarios covered (~30 assertions across 15 scenario groups):
#   (1)  Baseline: 16-leaf balanced tree, every leaf round-trips.
#   (2)  value_hash byte-flip at byte 0/16/31 (start/mid/end).
#   (3)  Sibling-hash tamper at EVERY position in the proof chain.
#   (4)  target_index ±1 off-by-one (and index 0's edge case).
#   (5)  target_index out-of-range (== leaf_count, >> leaf_count).
#   (6)  Proof truncation (drop last sibling).
#   (7)  Proof extension (append phantom sibling).
#   (8)  leaf_count drift (claim wrong total tree size).
#   (9)  Empty-tree behavior (leaf_count=0 → rejected as bad input).
#   (10) Single-leaf (leaf_count=1) — empty proof + phantom rejection.
#   (11) Two-leaf (leaf_count=2) — 1-sibling proof + sibling tamper.
#   (12) Odd-leaf (5 leaves) — padding path + leaf_count drift.
#   (13) 7-leaf — heaviest padding; every sibling tampered.
#   (14) Repeated-leaf (same value_hash, distinct keys) — key
#        slot-swap must reject (not value-only Merkle).
#   (15) Key tamper at same slot + shortened-key rejection.
#
# Run from repo root: bash tools/test_merkle_proof_tampering.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== v2.1 Merkle proof-tamper detection ==="
OUT=$($DETERM test-merkle-proof-tampering 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: merkle-proof-tampering all assertions"; then
  echo ""
  echo "  PASS: v2.1 Merkle proof-tamper detection coverage"
  exit 0
else
  echo ""
  echo "  FAIL: merkle-proof-tampering had assertion failures"
  exit 1
fi
