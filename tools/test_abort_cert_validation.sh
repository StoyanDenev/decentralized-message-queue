#!/usr/bin/env bash
# FA-Cert V10 NEGATIVE GATE — BlockValidator::check_abort_certs.
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
# Run from repo root: bash tools/test_abort_cert_validation.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== FA-Cert V10 — abort-certificate verification negative gate ==="
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
