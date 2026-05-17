#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for Shamir's Secret
# Sharing over GF(2^8) (wallet/shamir.cpp, A2 Phase 1 wallet
# recovery primitive).
#
# shamir::split divides a secret into N shares such that any T of
# them reconstruct the original, but T-1 or fewer reveal nothing
# (information-theoretic security via Lagrange interpolation in
# GF(2^8)). The wallet recovery flow wraps each share in an AEAD
# envelope (see test_envelope.sh / test_wallet_envelope.sh)
# guarded by the user's recovery password + a per-guardian OPRF key.
#
# A regression here would either silently weaken the threshold
# (T-1 shares accidentally enable reconstruction → information leak,
# defeats the central A2 safety claim) or break reconstruction so
# users can't recover their wallets.
#
# 18 assertions covering:
#
#   T-of-N reconstruction (4):
#     1. 3-of-5 round-trip
#     2. All C(5,3) = 10 subsets of 3 shares reconstruct
#     3. 4-of-5 (T+1) also reconstructs
#     4. 2-of-5 (T-1) does NOT reconstruct
#
#   Share-shape invariants (4):
#     5. Distinct x-coordinates across shares (no collision)
#     6. No share has x=0 (would leak secret via Lagrange at x=0)
#     7. Every share's y-vector matches secret size
#     8. Two independent splits produce different shares (fresh
#        polynomial)
#
#   Degenerate thresholds (3):
#     9. T=1 (every share IS the secret)
#    10-11. T=N (all shares required; T-1 doesn't reconstruct)
#
#   Empty-secret edge case (3):
#    12-14. split(empty) produces shares with empty y-vectors;
#           combine() rejects empty-y shares (documented edge case
#           in shamir.cpp lines 93-94)
#
#   Invalid-input rejection (4):
#    15. split: threshold=0 throws invalid_argument
#    16. split: threshold > share_count throws invalid_argument
#    17. combine: empty share list returns std::nullopt
#    18-19. combine: duplicate x-coordinates / mismatched y-sizes
#           return nullopt
#
# Run from repo root: bash tools/test_shamir.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== Shamir's Secret Sharing (wallet/shamir.cpp, A2 Phase 1) ==="
OUT=$($DETERM test-shamir 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: shamir all assertions"; then
  echo ""
  echo "  PASS: shamir unit test"
  exit 0
else
  echo ""
  echo "  FAIL: shamir had assertion failures"
  exit 1
fi
