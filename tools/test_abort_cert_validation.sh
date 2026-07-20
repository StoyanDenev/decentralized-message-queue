#!/usr/bin/env bash
# NEGATIVE GATE for the two abort-path validator clusters:
#   * BlockValidator::check_abort_certs   (V10, 6th gate) — T-C1/T-C3/T-C4/T-C5
#   * the BFT-escalation arm of check_block_sigs (9th)    — T-1, T-2, PE-4
#
# check_abort_certs is the last line of defense against a FORGED ABORT
# CERTIFICATE, whose consequence is consensus-level FALSE SUSPENSION-SLASHING of
# an honest validator. The docs/proofs/ProofClaimGateTraceability.md audit found
# it had NO negative coverage whatsoever (T-C1/T-C3/T-C4/T-C5, the top-ranked
# HIGH): of 31 `abort_events.push_back` sites in src/main.cpp none had a
# validate() within +/-40 lines, and the two witnesses the proof doc named
# contained the substring "abort" once (a comment) and never.
#
# This gate builds a real 4-node genesis with REAL Ed25519 keypairs, derives the
# at-event committee the way the validator does, and drives a self-consistent
# abort-carrying block through the full BlockValidator::validate() path. The
# baseline asserts a well-formed certificate CLEARS V10; twelve mutants each
# assert their SPECIFIC V10 reject (claim field bindings, accused-self-claim,
# non-member claimer, duplicate claimer, forged signature, under/over-sized
# quorum, non-array claims, and accusing a non-selected node).
#
# The block builder RE-DERIVES creators + per-creator commitments from the abort
# inputs on every call — necessary because check_creator_selection itself reads
# b.abort_events (it excludes aborting_node and folds event_hash into the
# selection rand), so a naive build-once-then-mutate test would trip THAT gate
# and never reach V10.
#
# FALSIFY-ON-MUTANT (executed): turning the per-claim signature reject into a
# `continue` — the exact silent mutation the audit named — flips EXACTLY the
# T-C3 assertion RED and nothing else. Before this gate that mutation passed all
# 257 tests.
#
# SECOND CLUSTER — the BFT-escalation arm of check_block_sigs (T-1, T-2, PE-4).
# A BFT block is by construction an abort-ESCALATED block, so it must carry a
# certificate that clears V10 first; these assertions therefore extend THIS
# fixture rather than duplicating it. check_creator_selection enforces only the
# mode<->SIZE pairing (m == ceil(2K/3) for BFT) and never consults bft_enabled_,
# which is what lets a BFT block reach the 9th gate with the genesis flag off.
#
# PE-4 is asserted without re-deriving proposer_idx() — that would merely mirror
# the code under test. Instead EVERY committee member is driven as the claimed
# proposer and EXACTLY ONE must survive: deleting the equality leaves zero
# rejected, inverting it rejects both.
#
# FALSIFY-ON-MUTANT (executed, three separate mutations):
#   * neutralize the `!bft_enabled_` guard      -> only the T-1 assertion RED
#   * neutralize the abort-threshold arm        -> only the T-2 assertion RED
#   * neutralize the proposer-identity equality -> exactly the TWO PE-4
#     assertions RED ("exactly ONE valid proposer" + "outsider rejected")
#
# Run from repo root: bash tools/test_abort_cert_validation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== FA-Cert V10 + BFT-escalation arm — abort-path negative gate ==="
OUT=$("$DETERM" test-abort-cert-validation 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-abort-cert-validation"; then
  echo "  PASS: abort-cert validation (forged certificates rejected)"
  exit 0
else
  echo "  FAIL: abort-cert validation (exit $rc)"
  exit 1
fi
