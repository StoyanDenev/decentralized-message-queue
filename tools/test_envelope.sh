#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the A2 Phase 2
# AEAD envelope (wallet/envelope.hpp). This is the wrapping primitive
# for Shamir recovery shares + identity keys, used throughout the
# wallet recovery flow (S-004 option 2 keyfile encryption, A2 share
# envelopes).
#
# AES-256-GCM with PBKDF2-HMAC-SHA-256 key derivation (600k iters in
# production; 1000 iters in this test for speed — exercises the same
# code path, just faster). 12-byte nonce + 16-byte GCM tag + AAD
# binding for per-guardian envelope context.
#
# A regression here would silently weaken at-rest security for every
# encrypted wallet artifact:
#   * Encrypted shares could become recoverable without the passphrase
#   * Tampered ciphertexts could decode without an AEAD tag failure
#   * Per-guardian AAD binding could be silently dropped, enabling
#     guardian-substitution attacks (presenting guardian-1's
#     encrypted share as guardian-2's)
#   * Salt/nonce reuse could create distinguishable ciphertexts
#     across encryption calls (would leak that two artifacts
#     encrypt the same plaintext)
#
# 27 assertions covering:
#
#   Encryption + decryption round-trip (8):
#     1-2. encrypt → decrypt with matching pw + AAD
#     3-7. Envelope shape: salt >= 16 bytes, nonce == 12 bytes,
#          ciphertext == pt_size + 16-byte GCM tag, pbkdf2_iters
#          + aad round-trip
#     8.   decrypt rejects wrong passphrase (AEAD tag fail)
#
#   AEAD safety properties (5):
#     9.  rejects empty passphrase against non-empty-encrypted
#     10. rejects mismatched AAD (per-guardian binding)
#     11. rejects tampered ciphertext
#     12. rejects tampered GCM tag
#     13. fresh salt + nonce per encryption → distinct ciphertexts
#         from same plaintext+passphrase (nondeterminism property)
#
#   serialize / deserialize round-trip (9):
#     14-20. Every field preserved through canonical hex
#            serialization + deserialization
#     21.    Full encrypt → serialize → deserialize → decrypt round-trip
#     22.    Garbage input rejected
#     23.    Truncated envelope rejected
#
#   Edge cases (3):
#     24-25. Empty plaintext encrypts (16-byte ct == tag only) +
#            decrypts back to empty
#     26-27. Empty AAD round-trips
#
# Run from repo root: bash tools/test_envelope.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== wallet/envelope.hpp (A2 Phase 2 AES-256-GCM + PBKDF2) ==="
OUT=$($DETERM test-envelope 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: envelope all assertions"; then
  echo ""
  echo "  PASS: envelope unit test"
  exit 0
else
  echo ""
  echo "  FAIL: envelope had assertion failures"
  exit 1
fi
