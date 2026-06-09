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
# This test locks in THREE contracts:
#
#   (a) INCLUSION list (11 assertions): every field in
#       compute_block_digest must change the digest when mutated.
#       A regression silently removing a field would break the
#       signature-domain coverage — two distinct blocks could share
#       a digest, and K-of-K would certify both, violating FA1.
#
#   (b) EXCLUSION list (8 assertions): the S-030 D2 surface.
#       Fields NOT bound on the non-F2 / v1-sentinel path MUST NOT
#       change the digest, because they're reconciled at apply time
#       (state_root via S-033 + S-038), are Phase-2-reveal values
#       (delay_output / creator_dh_secrets / cumulative_rand, not yet
#       known at digest-sign time), are the un-reconciled local pool on
#       a non-F2 block (abort_events / equivocation_events when the
#       per-creator view roots are all zero), or are the timestamp on a
#       block carrying no per-creator proposer_times. A future commit
#       that silently changed one of these on the v1 path would break
#       the S-030 D2 design assumptions.
#
#   (c) CONDITIONAL-BINDING list (7 assertions): the S-030-D2 / v2.7 F2
#       closures. compute_block_digest now CONDITIONALLY appends a tail —
#       partner_subset_hash (iff non-zero), timestamp (iff
#       creator_proposer_times non-empty), and the three F2 view roots
#       (inbound_receipts iff non-empty; equivocation/abort sets iff the
#       matching per-creator view root is non-zero). These assertions pin
#       BOTH directions: the trigger present ⇒ digest changes (so the
#       K-of-K Phase-2 sig attests to the value and a post-sign
#       strip/alter breaks verification), AND the trigger absent ⇒ the
#       digest stays byte-identical to the v1 digest (backward compat).
#
# Together they "fence" the digest at exactly the surface FA1 / the
# S-030 D2 analysis / the v2.7 F2 spec assume.
#
# 26 assertions total:
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
#   EXCLUSION (S-030 D2 / Phase-2-reveal / non-F2-sentinel path) (8):
#    12. delay_output EXCLUDED (Phase-2-reveal)
#    13. creator_dh_secrets EXCLUDED (Phase-2-reveal)
#    14. cumulative_rand EXCLUDED (Phase-2-reveal derivative)
#    15. abort_events EXCLUDED on the non-F2 path (zero abort view roots)
#    16. equivocation_events EXCLUDED on the non-F2 path (zero eq roots)
#    17. state_root EXCLUDED (apply-time gate via S-033 + S-038)
#    18b. zero partner_subset_hash keeps byte-identical v1 digest
#    19. timestamp EXCLUDED when creator_proposer_times empty (v1 path;
#        baseline carries no proposer_times). NOTE: producer.cpp BINDS
#        timestamp once proposer_times is non-empty — the harness only
#        exercises the empty / v1-sentinel direction here.
#
#   CONDITIONAL BINDING (S-030-D2 + v2.7 F2 — trigger present ⇒ bound) (7):
#    18. partner_subset_hash BOUND when non-zero (S-030-D2 partner
#        dimension closed; deterministic, gossip-async-safe — mirrors
#        signing_bytes' conditional append at block.cpp). Paired with 18b
#        above for the zero / backward-compat direction.
#    20. inbound_receipts INCLUDED when present (F2 / S-016 gate: non-empty)
#    21. inbound_receipts SET-sensitive (strip/add detected)
#    22. F2 eq-block gate fires on a non-zero creator_view_eq_root
#    23. equivocation_events BOUND inside an F2 eq-block (set sealed)
#    24. F2 abort-block gate fires on a non-zero creator_view_abort_root
#    25. abort_events BOUND inside an F2 abort-block (set sealed)
#
#   (The timestamp-BOUND direction — proposer_times non-empty ⇒ digest
#    binds b.timestamp — is NOT exercised in-process here; it is pinned
#    end-to-end by the cross-binary parity surface below.)
#
# Cross-reference: docs/proofs/S030-D2-Analysis.md §1 "Field-coverage
# table" + docs/proofs/F2-SPEC.md §1 "Scope". The conditional tail
# (partner_subset_hash + timestamp) and the LIGHT mirror
# (light/verify.cpp::light_compute_block_digest) are pinned against this
# ground truth by tools/test_block_digest_xbinary_parity.sh +
# docs/proofs/BlockDigestCrossBinaryParity.md (this round).
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
