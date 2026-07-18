#!/usr/bin/env bash
# NC-8 recipient note-key derivation — FIPS profile (1b), CRYPTO-C99-SPEC §3.25.
# The note keypair is derived from the account's A2 view_master_sk (the same
# 32-byte secret src/crypto/viewkey/viewkey.c §3.24 consumes), DST="determ-
# notekey-fips-v1": note_sk = hash_to_scalar(view_master_sk || len-prefixed
# chain_id/addr || index, DST), note_pk = compress(note_sk·G). ONE secret backs
# both audit and note delivery — an auditor disclosed view_master_sk re-derives
# every note_sk and reads all deliveries (closes the "opaque audit key opens
# nothing" gap). A composition of shipped P-256 primitives — NO new hardness
# assumption; byte-frozen python-first vs tools/vectors/notekey_fips.json.
#
# Gates (via `determ test-notekey-fips-c99`): determinism (= auditor re-derive),
# note_pk == compress(note_sk·G), distinctness over index/addr/chain_id/IKM,
# cross-profile domain separation, fail-closed edges, end-to-end seal→open, and
# the dual-oracle KAT corpus byte-for-byte.
#
# Run from repo root: bash tools/test_notekey_fips_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 note-key derivation FIPS (1b) — view-master-derived + dual-oracle ==="
OUT=$($DETERM test-notekey-fips-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: notekey-fips all assertions"; then
  echo ""
  echo "  PASS: notekey-fips unit test"
  exit 0
else
  echo ""
  echo "  FAIL: notekey-fips had assertion failures"
  exit 1
fi
