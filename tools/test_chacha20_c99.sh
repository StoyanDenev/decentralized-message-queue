#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.4 — the complete C99 ChaCha20-Poly1305 AEAD
# family at src/crypto/chacha20/ (ChaCha20 RFC 8439 §2.4 + Poly1305 §2.5 + the
# AEAD combiner §2.8). ChaCha20 is an ARX cipher and Poly1305 is limb arithmetic,
# both with no S-boxes / tables / secret-dependent branches, so the family is
# constant-time by construction (vs AES-GCM's GHASH, the spec's flagged hard part).
#
# 10 assertions: (1) ChaCha20 byte-equal vs OpenSSL EVP_chacha20 over a
# (counter,length) grid; (2) ChaCha20 self-inverse; (3) block-counter sensitivity;
# (4) Poly1305 vs the RFC 8439 §2.5.2 KAT; (5) the full ChaCha20-Poly1305 AEAD
# (ciphertext AND tag) byte-equal vs OpenSSL EVP_chacha20_poly1305 over a
# (plaintext,aad)-length grid -- the §Q9 gate; (6) AEAD decrypt round-trip + tamper
# rejection (tag + ciphertext + the two c9e5cf2 AAD-binding negatives:
# modified AAD and dropped AAD both reject). Additive -- not wired into any
# call site yet.
#
# Run from repo root: bash tools/test_chacha20_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 ChaCha20 (RFC 8439) vs OpenSSL EVP_chacha20 ==="
OUT=$($DETERM test-chacha20-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: chacha20-c99 all cross-validation + KATs matched"; then
  echo ""
  echo "  PASS: chacha20-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: chacha20-c99 had assertion failures"
  exit 1
fi
