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
# Gates (via `determ test-dsso-opaque3dh`, 43 assertions): both parties derive the
# SAME session_key from the three DH + the whole transcript; the two MACs mutually
# authenticate; a changed server_nonce yields a different key AND a server MAC the
# honest client rejects (the transcript is bound into every output); fail-closed
# NULL edges; and the KAT (CleartextCredentials / session_key / server_mac /
# client_mac) is byte-for-byte identical to the independent python oracle
# tools/verify_opaque3dh.py (the dual-oracle discipline).
#
# Plus the C2 arms (v2.25-DSSO-DAPP-SPEC §0.0(2), closed 2026-09-17). The v1
# transcript bound NEITHER static public key, so an attacker holding only the
# victim's PUBLIC pk_c impersonated the whole threshold IdP and shared sso_key with
# her — reproduced end to end before the fix. The v2 transcript carries the RFC 9807
# §4.1.1 CleartextCredentials block and the static keys enter ONLY through it:
#   C2-a  an impersonator holding only pk_c is REJECTED (server_mac_ok == 0) and
#         shares no session key with the client;
#   C2-b  a server holding the REAL sk_s but CLAIMING a different static key is
#         REJECTED although all three DH values agree — the arm that fails again if
#         a static key is ever unbound (M1/M6);
#   C2-c  a substituted client_public_key is REJECTED although the client's own 3DH
#         never reads it (M2);
#   C2-d/e  substituted server_identity / client_identity are REJECTED (M3);
#   C2-f  the CleartextCredentials bytes change with the key and with the identity,
#         so the envelope AAD built from them cannot carry a substituted pk_s;
#   C2-g  a server_mac differing only in its first or its last byte is REJECTED
#         (a truncated / shortcut MAC compare, M5).
# Falsify-on-mutant: M1 drop pk_s from the transcript, M2 drop pk_c, M3 drop the
# identities, M4 bind on the server side only, M5 weaken the MAC compare, M6 restore
# the v1 unbound preamble wholesale — each RED against a rebuilt binary.
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
