#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.2 — the libsodium-free C99 Ed25519 (RFC 8032)
# at src/crypto/ed25519/, the EC prerequisite for the v2.10 FROST-Ed25519 threshold
# randomness. Constant-time gf[16] field + cswap-ladder scalar multiplication +
# branchless mod-L reduction; composes the C99 SHA-512. No key-dependent branch,
# index, or precomputed-table lookup -> no cache-timing channel.
#
# 12 assertions (the original 9 below + the 3a6370f anti-malleability
# additions: S>=L reject, non-canonical-y pubkey reject, large-message
# splice): (1) pubkey + (2) signature match the RFC 8032 §7.1 TEST 1 vector
# (empty message) -- an OpenSSL-independent anchor; (3) pubkey + (4) signature
# byte-equal vs OpenSSL EVP_PKEY_ED25519 over a fuzzed (seed,message-length) grid
# -- the §Q9 gate; (5)-(8) verify accepts a valid signature and rejects a tampered
# signature / message / wrong key; (9) our signature verifies under OpenSSL
# EVP_DigestVerify (cross-binary). Additive -- not yet wired into the daemon's
# Ed25519 call sites (which still use OpenSSL EVP_PKEY_ED25519).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Ed25519 (RFC 8032) vs OpenSSL EVP_PKEY_ED25519 + the RFC 8032 §7.1 KAT ==="
OUT=$($DETERM test-ed25519-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ed25519-c99 all cross-validation + RFC 8032 KAT matched"; then
  echo ""
  echo "  PASS: ed25519-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ed25519-c99 had assertion failures"
  exit 1
fi
