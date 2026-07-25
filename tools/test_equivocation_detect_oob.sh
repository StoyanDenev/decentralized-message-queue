#!/usr/bin/env bash
# BlockIngress EQV-assemble-OOB — node::detect_equivocation bounds-guards the
# creator_block_sigs indexing on the UNVALIDATED duplicate-block path.
#
# Node::apply_block_locked's b.index<height() branch runs BEFORE any validate()
# call (validate only runs on the accept path), and Block::from_json does NOT
# enforce creator_block_sigs.size()==creators.size(). The inline equivocation-
# detection code indexed creator_block_sigs[bidx] by the proposer's creators-
# position with no bounds check, so a peer gossiping a BFT block at an already-
# committed height with a size-short creator_block_sigs triggered an out-of-
# bounds read (remote crash / DoS). The assembly is now the size-guarded free
# function node::detect_equivocation, matching every sibling that indexes
# creator_block_sigs by a creators-position (validator.cpp:453, maybe_reorg,
# beacon-header, shardtip_verify).
#
# The gate drives the helper directly: a genuine same-height double-sign still
# assembles evidence (positive control); a size-short block returns nullopt with
# no OOB; guard-independent negatives stay green. Falsify-on-mutant
# (`if (false && (sidx>=... || bidx>=...))`) segfaults on the empty-vector read
# (MSVC) / ASan-traps the heap over-read (Linux) — the size-short asserts flip
# while the positive control + negatives do not.
#
# Run from repo root: bash tools/test_equivocation_detect_oob.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== equivocation-detect-oob — creator_block_sigs bounds guard on the duplicate-block path ==="
OUT=$($DETERM test-equivocation-detect-oob 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: equivocation-detect-oob"; then
  echo ""
  echo "  PASS: equivocation-detect-oob unit test"
  exit 0
else
  echo ""
  echo "  FAIL: equivocation-detect-oob had assertion failures"
  exit 1
fi
