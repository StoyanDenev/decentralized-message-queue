#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.4 — the libsodium-free C99 XChaCha20-Poly1305
# (draft-irtf-cfrg-xchacha) at src/crypto/chacha20/xchacha20_poly1305.c: the
# extended-nonce (192-bit) AEAD = HChaCha20 subkey + the already-OpenSSL-validated
# C99 ChaCha20-Poly1305. Constant-time by construction (ChaCha ARX permutation);
# derived subkey zeroized per call.
#
# Assertions: (1) HChaCha20 vs the draft §2.2.1 KAT (an independent from-scratch
# reference); (2) the full AEAD (ciphertext + tag) byte-equal vs OpenSSL's inner
# ChaCha20-Poly1305 on the derived (subkey, 96-bit nonce) over a (pt,aad)-length
# grid -- the §Q9 gate (XChaCha20-Poly1305 is DEFINED as that composition, and (1)
# pins HChaCha20); (3) decrypt round-trip + tamper rejection of tag / ciphertext /
# AAD / nonce. Additive -- not yet wired into a call site.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) vs OpenSSL + HChaCha20 KAT ==="
OUT=$($DETERM test-xchacha-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: xchacha-c99 all cross-validation + KATs matched"; then
  echo ""
  echo "  PASS: xchacha-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: xchacha-c99 had assertion failures"
  exit 1
fi
