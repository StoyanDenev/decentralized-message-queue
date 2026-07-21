#!/usr/bin/env bash
# DSSO Bundle-A gate G4 (assertion layer) — v2.25-DSSO-DAPP-SPEC §5, claim C6.
#
# The RP-facing "Sign-In With Determ" token is the paper's DUAL-HASH
# challenge-response over co-generated keys (NO signature, NO FROST, NO block
# co-sign):
#   H1' = H(sso_key,    challenge)     (keyed by the login-session key)
#   H2  = H(tenant_key, H1')           (keyed by the RP's registration key)
# the RP holds tenant_key + receives H1' and accepts iff HMAC(tenant_key, H1')
# == H2. The challenge binds the SIWE-class claim (iss, sub, aud, iat, exp,
# nonce). H = HMAC-SHA256 — the shipped, KAT-gated keyed hash; ZERO new primitive.
#
# Seven soundness properties (claim C6, PRF security of H). The token is a sound
# keyed COMMITMENT — unforgeable without the keys, binding keys+claim:
#   1. correctness         (verifier)   honest token -> RP accepts
#   2. audience binding    (verifier)   a token for RP-B is rejected under RP-A's key
#   3. session binding     (verifier)   a token whose H1' came from another sso_key fails
#   4. nonce commitment    (generation) a fresh nonce -> a distinct token
#   5. claim commitment    (generation) mutating any of iss/sub/aud/iat/exp -> distinct token
#   6. layer separation    (verifier)   the bare inner H1' is rejected as the token
#   7. forgery             (verifier)   an arbitrary H2 is rejected
#
# SCOPE: this gates the ASSERTION-TOKEN soundness (a keyed commitment). The
# t-of-n login that authenticates the user + unseals the credential is gated by
# test-dsso-threshold-oprf (G1/G2/G3). The OPAQUE AKE that co-generates sso_key
# is the owner-gated remainder of G4 — here sso_key is a given handshake output.
#
# RESIDUAL (adversarial-verification finding): the §5 accept rule is STATELESS
# (HMAC(tenant_key, H1') == H2) and the RP cannot recompute H1' (no sso_key), so
# the token in ISOLATION does not reject a verbatim replay of a captured
# (H1', H2) nor a claim substituted at presentation. Verifier-side replay/expiry
# rejection needs RP session state (single-use nonce + clock) — a ceremony
# property, part of the owner-gated G4 end-to-end flow. See the proof doc §6.
#
# Full mechanism: docs/proofs/DssoThresholdOprfSoundness.md.
# Run from repo root: bash tools/test_dsso_assertion.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== DSSO §5 dual-hash RP assertion — Bundle-A gate G4 (assertion layer, C6) ==="
OUT=$("$DETERM" test-dsso-assertion 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -3 | grep -q "PASS: test-dsso-assertion"; then
  echo "  PASS: test_dsso_assertion"
  exit 0
else
  echo "  FAIL: test_dsso_assertion (exit $rc)"
  exit 1
fi
