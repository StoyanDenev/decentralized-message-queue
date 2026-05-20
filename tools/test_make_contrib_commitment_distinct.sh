#!/usr/bin/env bash
# Exhaustive pin on make_contrib_commitment hash distinctness across
# every input perturbation. Complements tools/test_view_root.sh (which
# covers v1-compat short-circuit + DTM-F2-v1 domain separator at a high
# level) by walking each commit-input dimension and asserting the
# resulting hash changes — or, where the protocol expects collision (v1
# vs F2-with-all-zero-roots), that it's byte-identical.
#
# Why this exists: make_contrib_commitment is the pre-image for the
# Phase-1 commitment signature on every ContribMsg. Any drift in its
# input mixing — a forgotten field, a tag byte, a domain-separator
# reorder — would silently change the commit hash and break signature
# replay resistance (S-006 / S-013), equivocation detection (S-006), and
# cross-version compatibility (v1 ↔ v2.7 F2). The function lives in
# src/node/producer.cpp:219+ and is consumed by make_contrib +
# validator.cpp; this test pins it independently of either consumer.
#
# Assertions (~25 across 21 scenarios):
#   1. Determinism: same inputs → same commit (v1 path).
#   2. block_index 42→43 → different commit.
#   3. prev_hash single-byte flip → different commit.
#   4a-d. tx_hashes: append / remove / canonical-sort-reversed /
#         unsorted-permutation behaviours.
#   5. dh_input single-byte flip → different commit.
#   6. view_eq_root non-zero → F2 path, distinct from v1.
#   7. view_abort_root non-zero only → distinct from v1 AND (6).
#   8. view_inbound_root non-zero only → distinct from v1, (6), (7).
#   9. All three roots non-zero → distinct from each single-root form
#      (each root contributes independently).
#  10. F2-active path: prev_hash still binds.
#  11. F2-active path: block_index still binds.
#  12. Per-root domain separation: same value X in different slots →
#      different commits (eq vs abort vs inbound).
#  13. F2-active path deterministic (re-compute byte-identical).
#  14. v1 path deterministic (re-compute byte-identical).
#  15. v1 == F2-with-all-zero-roots (positive collision: backward-
#      compat byte-parity per the explicit short-circuit).
#  16. Empty tx_hashes: deterministic + distinct from baseline.
#  17. block_index = 0 edge case.
#  18. block_index near uint64 max edge case.
#  19. All-zero prev_hash distinct from patterned.
#  20. All-zero dh_input distinct from patterned.
#  21. Cross-perturbation: two-field flip distinct from each single
#      single-field flip and the baseline (no internal cancellation).
#
# Run from repo root: bash tools/test_make_contrib_commitment_distinct.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== make_contrib_commitment distinctness pin (Phase-1 commit pre-image) ==="
OUT=$($DETERM test-make-contrib-commitment-distinct 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: make-contrib-commitment-distinct all assertions"; then
  echo ""
  echo "  PASS: make-contrib-commitment-distinct unit test"
  exit 0
else
  echo ""
  echo "  FAIL: make-contrib-commitment-distinct had assertion failures"
  exit 1
fi
