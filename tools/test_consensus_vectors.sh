#!/usr/bin/env bash
# Cross-toolchain consensus-determinism contract. Runs `determ
# test-consensus-vectors`, which pins GOLDEN hex for genesis_hash +
# compute_state_root() + head block_hash over a fixed scenario battery
# (bare genesis + the composite i:/m:/p: state namespaces). Every build
# — MSVC, GCC, any future target — must reproduce the goldens byte-for-
# byte; a mismatch is a cross-compiler consensus FORK caught at test time
# (the failure mode of the 2026-07-03 chain.cpp:336 shift-UB, which the
# sibling test-state-root-determinism, being within-build, could not see).
# Regenerate goldens deliberately with `determ test-consensus-vectors
# --emit` and re-verify on both toolchains.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== consensus golden-vector determinism ==="
OUT=$($DETERM test-consensus-vectors 2>&1)
echo "$OUT"

if echo "$OUT" | tail -2 | grep -q "PASS: consensus-vectors"; then
  echo ""; echo "  PASS: consensus-vectors unit test"; exit 0
else
  echo ""; echo "  FAIL: consensus-vectors cross-toolchain divergence"; exit 1
fi
