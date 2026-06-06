#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.3 — the libsodium-free C99 X25519 (RFC 7748)
# at src/crypto/x25519/, the Curve25519 Diffie-Hellman companion to the C99 Ed25519.
# Same TweetNaCl-derived constant-time Montgomery-ladder provenance; no key-dependent
# branch or memory index -> no cache-timing channel; clamped scalar + field
# intermediates zeroized before return.
#
# 8 assertions: (1)-(3) byte-equal vs OpenSSL EVP_PKEY_X25519 over a fuzzed scalar
# grid -- public-key derivation, ECDH (EVP_PKEY_derive), and DH symmetry (the §Q9
# gate); (4)-(7) the canonical RFC 7748 §6.1 Alice/Bob keypair + shared-secret KAT
# (an OpenSSL-independent anchor); (8) the all-zero low-order point is rejected
# (-1) per RFC 7748's contributory check. Additive -- not yet wired into a call site.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 X25519 (RFC 7748) vs OpenSSL EVP_PKEY_X25519 + the RFC 7748 §6.1 KAT ==="
OUT=$($DETERM test-x25519-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: x25519-c99 all cross-validation + RFC 7748 KATs matched"; then
  echo ""
  echo "  PASS: x25519-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: x25519-c99 had assertion failures"
  exit 1
fi
