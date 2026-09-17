#!/usr/bin/env bash
# DSSO G4 END-TO-END inc.2 — v2.25-DSSO-DAPP-SPEC §3-5 / §9 G4.
# The full "Sign-In With Determ" login as a COMPOSITION of the shipped Bundle-A
# pieces: registration mints a FRESH P-256 DSSO credential (owner decision
# 2026-07-21: the DSSO identity is SEPARATE from the chain Ed25519 identity) and
# seals it in the envelope under AAD = the RFC 9807 §4.1.1 CleartextCredentials
# block (C2, 2026-09-17); login runs the t-of-n threshold OPRF (G1/G2), unseals
# the envelope with the recovered output y (G3), and runs the OPAQUE-3DH AKE core
# (§3.26, test-dsso-opaque3dh) with cred_request = the OPRF blind and
# cred_response = the combined OPRF evaluation || the envelope.
#
# ZERO new primitive — every operation is already byte-frozen (OPRF / AEAD / HKDF /
# P-256 / opaque3dh); this gate proves the pieces COMPOSE and the security
# properties hold end-to-end:
#   E2E-1 honest login: both parties derive the SAME sso_key + transcript-MAC
#         mutual authentication (credential recovered via the OPRF).
#   E2E-2 password binding: a wrong password fails the envelope AEAD tag -> the
#         login aborts BEFORE the AKE (no sk_c, no sso_key).
#   E2E-3 credential-transcript binding: a MITM swapping cred_response between
#         server and client breaks the transcript MAC (the OPRF/envelope layer is
#         BOUND into the AKE, not merely adjacent). [falsify: dropping cred_response
#         from the AKE preamble flips exactly this leg RED, E2E-1 stays green.]
#   E2E-4 fault tolerance: n=5, t=3, one crash + one byzantine -> the DLEQ filter
#         admits the honest t -> the login + AKE still succeed.
#   E2E-10 C2 (spec §0.0(2)): the envelope's AAD is the CleartextCredentials block
#         {pk_s, pk_c, server_identity, client_identity} -- the byte-identical block
#         the AKE transcript binds -- so a substituted server (or client) static
#         public key in ke2 fails the AEAD tag and the login ABORTS before the AKE.
#         This is where the client's pk_s becomes AUTHENTIC; transcript binding
#         alone cannot supply that. [falsify: re-nulling the AAD on both the seal
#         and the open (mutant M7) flips E2E-10a/b RED, E2E-1..9 stay green.]
#
# Run from repo root: bash tools/test_dsso_login_e2e.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DSSO G4 end-to-end (register -> t-of-n login -> OPAQUE-3DH AKE) ==="
OUT=$($DETERM test-dsso-login-e2e 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dsso-login-e2e all assertions"; then
  echo ""
  echo "  PASS: dsso-login-e2e unit test"
  exit 0
else
  echo ""
  echo "  FAIL: dsso-login-e2e had assertion failures"
  exit 1
fi
