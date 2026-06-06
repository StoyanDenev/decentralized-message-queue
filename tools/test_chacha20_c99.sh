#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.4 — the C99 ChaCha20 (RFC 8439) cipher, the
# first half of the ChaCha20-Poly1305 AEAD family at src/crypto/chacha20/.
# ChaCha20 is an ARX cipher (no S-boxes / tables / secret-dependent branches), so
# it is constant-time by construction. Poly1305 + the AEAD combiner land next.
#
# 3 assertions: (1) byte-equal cross-validation against OpenSSL EVP_chacha20 over a
# (counter,length) grid spanning block + partial-block boundaries (the §Q9 gate,
# needing no transcribed vector), (2) the self-inverse property (apply the
# keystream twice -> plaintext), (3) block-counter sensitivity. The module is
# additive -- not wired into any call site yet.
#
# Run from repo root: bash tools/test_chacha20_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 ChaCha20 (RFC 8439) vs OpenSSL EVP_chacha20 ==="
OUT=$($DETERM test-chacha20-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chacha20-c99 all cross-validation matched"; then
  echo ""
  echo "  PASS: chacha20-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chacha20-c99 had assertion failures"
  exit 1
fi
