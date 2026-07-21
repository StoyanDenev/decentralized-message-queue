#!/usr/bin/env bash
# DSSO G4 OPAQUE-3DH AKE core — CRYPTO-C99-SPEC §3.26 / RFC 9807 §6.4.
# The "Sign-In With Determ" login (v2.25-DSSO-DAPP-SPEC §4-5) co-generates a shared
# session key sso_key between the client wallet and the threshold IdP via an OPAQUE
# authenticated key exchange. This gate covers the AKE CORE: the 3DH key schedule
# + transcript-MAC mutual auth in src/crypto/dsso/opaque3dh.c. The credential_
# request / credential_response are opaque transcript blobs here (they are produced
# by the already-shipped threshold-OPRF + OPAQUE envelope, G1/G2/G3, and threaded
# in at the login layer in inc.2), so this proves the AKE in isolation.
#
# NO new hardness assumption / NO new primitive: three P-256 scalar mults (the 3DH,
# determ_p256_point_mul), an RFC-9807/TLS-1.3 HKDF-Expand-Label schedule over HKDF-
# SHA256 (built on determ_hmac_sha256), and streaming determ_sha256 over the
# transcript preamble. All present in determ::c99.
#
# Gates (via `determ test-dsso-opaque3dh`): both parties derive the SAME session_key
# from the three DH + the whole transcript; the two MACs mutually authenticate;
# a changed server_nonce yields a different key AND a server MAC the honest client
# rejects (the transcript is bound into every output); fail-closed NULL edges; and
# the KAT (session_key / server_mac / client_mac) is byte-for-byte identical to the
# independent python oracle tools/verify_opaque3dh.py (the dual-oracle discipline).
#
# Run from repo root: bash tools/test_dsso_opaque3dh.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== DSSO G4 OPAQUE-3DH AKE core (RFC 9807 3DH) — dual-oracle KAT ==="
OUT=$($DETERM test-dsso-opaque3dh 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: dsso-opaque3dh all assertions"; then
  echo ""
  echo "  PASS: dsso-opaque3dh unit test"
  exit 0
else
  echo ""
  echo "  FAIL: dsso-opaque3dh had assertion failures"
  exit 1
fi
