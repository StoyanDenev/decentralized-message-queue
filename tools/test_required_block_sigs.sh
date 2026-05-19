#!/usr/bin/env bash
# S-035 Option 1 seed — required_block_sigs(mode, committee_size) BFT/MD
# quorum arithmetic. The formula at the heart of safety/liveness proofs
# (BFTSafety.md |K_h|/Q analysis; PROTOCOL.md §5.3 BFT escalation gate;
# Liveness.md L-4.3 BFT-mode finalize condition).
#
# Formula:
#   MD mode:  required = committee_size (full K-of-K)
#   BFT mode: required = ceil(2 * committee_size / 3)
#
# BFT mode permits up to (committee_size - ceil(2k/3)) sentinel-zero
# slots — slots where a designated proposer's signature is acceptable
# but the rest of the committee can have empty sentinel signatures.
# This is the LIVENESS escape hatch: BFT can never require MORE
# signatures than MD (would defeat the escalation's purpose).
#
# Covered:
#   - MD(k) == k for k in {1, 2, 3, 5, 9}
#   - BFT(1) == 1, BFT(2) == 2 (degenerate)
#   - BFT(3) == 2, BFT(4) == 3, BFT(5) == 4, BFT(6) == 4, BFT(7) == 5,
#     BFT(9) == 6 — concrete ceil(2k/3) values from the proofs
#   - Invariant: BFT(k) <= MD(k) for all k in [1, 16]
#   - Determinism: pure function (same inputs → same output)
#
# Defends against drift in the formula that would either over-tighten
# (liveness break — escalation can't actually fire) or under-tighten
# (safety break — BFT quorum too small for f < N/3 safety).
#
# 14 assertions across 11 scenarios (4 are determinism replays).
#
# Run from repo root: bash tools/test_required_block_sigs.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== BFT/MD quorum arithmetic — required_block_sigs(mode, k) formula ==="
OUT=$($DETERM test-required-block-sigs 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: required-block-sigs all assertions"; then
  echo ""
  echo "  PASS: required-block-sigs unit test"
  exit 0
else
  echo ""
  echo "  FAIL: required-block-sigs had assertion failures"
  exit 1
fi
