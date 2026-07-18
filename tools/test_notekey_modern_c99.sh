#!/usr/bin/env bash
# NC-8 recipient note-key derivation — MODERN profile (1a), CRYPTO-C99-SPEC §3.25.
# A DEDICATED note keypair derived from an INDEPENDENT 32-byte note seed (scan/
# spend authority separate from the audit layer): note_sk = hash_to_scalar(
# ikm || len-prefixed chain_id/addr || index, DST="determ-notekey-modern-v1"),
# note_pk = compress(note_sk·G). A sender seals a CONFIDENTIAL_TRANSFER delivery
# ciphertext to note_pk (determ_enote_seal); the recipient trial-decrypts with
# note_sk (determ_enote_open). A composition of shipped P-256 primitives — NO new
# hardness assumption; byte-frozen python-first vs tools/vectors/notekey_modern.json.
#
# Gates (via `determ test-notekey-modern-c99`): determinism, note_pk ==
# compress(note_sk·G), distinctness over index/addr/chain_id/IKM, cross-profile
# domain separation, fail-closed edges, end-to-end seal→open, and the dual-oracle
# KAT corpus byte-for-byte.
#
# Run from repo root: bash tools/test_notekey_modern_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 note-key derivation MODERN (1a) — dedicated note key + dual-oracle ==="
OUT=$($DETERM test-notekey-modern-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: notekey-modern all assertions"; then
  echo ""
  echo "  PASS: notekey-modern unit test"
  exit 0
else
  echo ""
  echo "  FAIL: notekey-modern had assertion failures"
  exit 1
fi
