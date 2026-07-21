#!/usr/bin/env bash
# DSSO Bundle-A gates G1 + G2 (v2.25-DSSO-DAPP-SPEC §4 login, §9 green gates).
#
# The "Sign-In With Determ" login is a t-of-n, UNORDERED threshold OPRF: the
# user Shamir-deals the OPRF key k over the P-256 scalar field Z_n, each server
# holds a share k_i and returns Z_i = k_i·B, and the client Lagrange-combines
# ANY t of them at x=0 to recover Z = k·B. This is the paper's "not all nodes,
# no predefined order" property (academia.edu/80188125), thresholdized per
# TOPPSS (JKKX 2017). Zero new primitive: Shamir + Lagrange-in-the-exponent over
# the SHIPPED P-256 group/scalar ops (the two additive scalar ops the combine
# needs, determ_p256_scalar_add/sub_mod_n, are exposed from the existing
# internal sc_add_raw/sc_sub_raw — the RFC-9497 OPRF-enabler pattern).
#
# This gate proves the math over the shipped stack BEFORE any ceremony code:
#   G1  t-of-n identity: Lagrange over EVERY t-subset == direct k·B == the
#       single-key OPRF output (enumerated exhaustively for 3-of-5 and 2-of-3).
#   G2  per-response DLEQ: a tampered Z_i fails its VOPRF proof AND, if admitted,
#       corrupts the combine — the check is load-bearing (spec C4).
#   +   threshold realness: < t shares cannot reconstruct (spec C1/C3).
#   +   scalar-op self-validation: (a±b)·G ties the two exposed additive ops to
#       the group with NO external oracle.
#
# FALSIFY-ON-MUTANT (executed, each reverted): swapping the body of
# determ_p256_scalar_add_mod_n to sc_sub (or sub->add) turns the scalar-op
# self-check AND both G1 assertions RED — the exposed ops are load-bearing for
# the whole threshold identity.
#
# Full mechanism: docs/proofs/DssoThresholdOprfSoundness.md.
# Run from repo root: bash tools/test_dsso_threshold_oprf.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== DSSO threshold-OPRF — Bundle-A gates G1 (t-of-n identity) + G2 (DLEQ) ==="
OUT=$("$DETERM" test-dsso-threshold-oprf 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: test-dsso-threshold-oprf"; then
  echo "  PASS: test_dsso_threshold_oprf"
  exit 0
else
  echo "  FAIL: test_dsso_threshold_oprf (exit $rc)"
  exit 1
fi
