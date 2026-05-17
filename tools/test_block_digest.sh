#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for compute_block_digest
# (the FA1 signature target at Phase-2 of K-of-K consensus).
#
# compute_block_digest is the hash each committee member signs in
# Phase-2. The signed digest binds the block's IDENTITY for the
# K-of-K threshold; once K signatures gather, those K members are
# collectively responsible (and slashable for equivocation) for
# that block instance at that height.
#
# This test locks in TWO contracts:
#
#   (a) INCLUSION list (11 assertions): every field in
#       compute_block_digest must change the digest when mutated.
#       A regression silently removing a field would break the
#       signature-domain coverage — two distinct blocks could share
#       a digest, and K-of-K would certify both, violating FA1.
#
#   (b) EXCLUSION list (8 assertions): the S-030 D2 surface.
#       Fields NOT in compute_block_digest MUST NOT change the
#       digest, because they're reconciled at apply time (state_root
#       via S-033 + S-038) or are Phase-2-reveal values (not yet
#       known at digest-sign time) or are in v2.7 F2 territory
#       (abort_events, equivocation_events, timestamp). A future
#       commit that silently adds one of these to the digest would
#       break the S-030 D2 / F2 design assumptions.
#
# Together they "fence" the digest at exactly the surface FA1 / the
# S-030 D2 analysis / the v2.7 F2 spec assume.
#
# 19 assertions total:
#
#   Determinism + INCLUSION (11):
#     1. compute_block_digest deterministic
#     2. index sensitivity
#     3. prev_hash sensitivity
#     4. tx_root sensitivity
#     5. delay_seed sensitivity
#     6. consensus_mode sensitivity
#     7. bft_proposer sensitivity
#     8. creators value sensitivity
#     9. creator_tx_lists sensitivity
#    10. creator_ed_sigs sensitivity
#    11. creator_dh_inputs sensitivity (Phase-1 commit)
#
#   EXCLUSION (S-030 D2 / Phase-2-reveal / v2.7 F2 territory) (8):
#    12. delay_output EXCLUDED (Phase-2-reveal)
#    13. creator_dh_secrets EXCLUDED (Phase-2-reveal)
#    14. cumulative_rand EXCLUDED
#    15. abort_events EXCLUDED (S-030 D2 / v2.7 F2 territory)
#    16. equivocation_events EXCLUDED (S-030 D2 / v2.7 F2 territory)
#    17. state_root EXCLUDED (apply-time gate via S-033 + S-038)
#    18. partner_subset_hash EXCLUDED
#    19. timestamp EXCLUDED (v2.7 F2 territory)
#
# Cross-reference: docs/proofs/S030-D2-Analysis.md §1 "Field-coverage
# table" + docs/proofs/F2-SPEC.md §1 "Scope".
#
# Run from repo root: bash tools/test_block_digest.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== compute_block_digest — FA1 signature target (S-030 D2 fence) ==="
OUT=$($DETERM test-block-digest 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: block-digest all assertions"; then
  echo ""
  echo "  PASS: block-digest unit test"
  exit 0
else
  echo ""
  echo "  FAIL: block-digest had assertion failures"
  exit 1
fi
