#!/usr/bin/env bash
# S-068 — small-order REGISTER keys rejected (companion to V-REG-1; recorded
# DECISION-LOG 2026-08-14 `1c0a61d`, landed 2026-09-15).
#
# determ_ed25519_verify enforces y-canonicality and S < L but performs no
# torsion check (RFC 8032 does not require one), so a small-order public key
# (the 8-torsion subgroup) is forgeable: under the neutral element (R = O,
# S = 0) verifies EVERY message ([S]B = R + [k]A for any k), and under the
# other seven points the same pair verifies whenever [k]A = O — one message
# in at most eight. A REGISTER whose payload key is such a point therefore
# carries a vacuous proof of possession and, under create-only, a permanently
# forgeable identity. Now the verifier's REGISTER case rejects any payload
# key with [8]P == O (determ_ed25519_point_has_small_order, three doublings
# after one decode, src/crypto/ed25519/ed25519.c) AFTER the signature check,
# so an unauthenticated REGISTER pays nothing beyond the verification it
# already paid; the ingress mirror does the same.
#
# The gate DEMONSTRATES the forgery first (for each of the 10 accepted
# small-order encodings — 8 canonical + the 2 sign-bit variants of the x = 0
# points — a REGISTER whose (R = O, S = 0) signature VERIFIES is found within
# a few domain-name trials), re-derives the order of every listed encoding
# with the library (a wrong constant fails the precondition instead of
# passing silently), keeps a normal-key REGISTER accepted, rejects every
# forged REGISTER with the S-068 reason, and pins the ingress mirror (dropped
# at gossip, rejected at RPC submit, normal-key control admitted).
#
# Falsify-on-mutant (executed 2026-09-15, reverted):
#   M1 delete the small-order rule in the verifier's REGISTER case -> the
#      "every forged small-order REGISTER REJECTED" arm flips RED (the forged
#      REGISTERs are ACCEPTED by the verifier).
#   M2 make determ_ed25519_point_has_small_order return 0 unconditionally ->
#      the precondition arm, the rejection arm and the mirror arms flip RED.
#   M3 delete the mirror rule in verify_tx_signature_locked -> the mirror
#      arms flip RED (the forged REGISTER becomes resident).
#
# In-process (no cluster), so it runs in the FAST suite.
# Run from repo root: bash tools/test_register_small_order_key.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== S-068: a REGISTER whose payload key is small-order is rejected (after the signature) ==="
OUT=$("$DETERM" test-register-small-order-key 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-register-small-order-key"; then
  echo "  PASS: test_register_small_order_key"
  exit 0
else
  echo "  FAIL: test_register_small_order_key (exit $rc)"
  exit 1
fi
