#!/usr/bin/env bash
# S-009 / rev.9 compute_block_rand distribution + per-block randomness
# contracts — companion to test-block-rand (which exercises baseline
# sensitivity + domain separation). Pin seven axes:
#   (1) Replay determinism: same delay_seed + ordered_secrets produce
#       byte-identical block_rand across 3 invocations + freshly-built
#       containers + std::map-rebuilt secrets vector.
#   (2) Avalanche: single-byte XOR-flip of a secret byte, prev_hash, or
#       index change moves block_rand (binary "did it move at all" —
#       not a Hamming-distance measure).
#   (3) Order binding: swap two ordered_secrets / reverse the vector
#       → block_rand changes (committee-selection order is canonical
#       — Phase-1/Phase-2 indexing must match per FA1).
#   (4) Per-bit uniformity smoke: 256 samples (index 0..255), mean of
#       per-bit set-counts across the 256 bit positions lands in
#       [120, 136] (1σ window around binomial(256, 0.5) expectation
#       of 128). Non-flaky non-crypto-strength sanity that block_rand
#       "looks random" at the per-bit level.
#   (5) K-subset behavior: K=3 vs K=5 different; K=1 deterministic;
#       K=0 well-defined (empty reveal vector — all-aborted-Phase-2
#       path); K=0 distinct from K=3 baseline.
#   (6) Cross-scope identity: two independent scopes with identical
#       inputs compute byte-identical block_rand (peer-node analogue
#       — no scope-local / container-identity dependence).
#   (7) Output-domain coverage: ≥90 of 100 block_rand values are
#       pairwise distinct across varying index (pins block_rand is
#       not stuck or degenerate; birthday-paradox collisions are
#       astronomically unlikely on the 2^256 output domain).
#
# Companion to:
#   - test-block-rand (baseline determinism + domain separation +
#     value sensitivity for compute_delay_seed + compute_block_rand
#     + proposer_idx + required_block_sigs + count_round1_aborts).
#
# 18 assertions across 7 scenarios.
#
# Run from repo root: bash tools/test_block_rand_distribution.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== block_rand distribution contract — replay + avalanche + order + uniformity ==="
OUT=$($DETERM test-block-rand-distribution 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-rand-distribution all assertions"; then
  echo ""
  echo "  PASS: block-rand-distribution unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-rand-distribution had assertion failures"
  exit 1
fi
