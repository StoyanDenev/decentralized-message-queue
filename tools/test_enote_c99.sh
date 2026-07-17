#!/usr/bin/env bash
# NC-8 encrypted-note delivery (shielded-pool Option A) — the ephemeral-static
# ECIES over P-256 in src/crypto/enote/enote.c (ECDH + HKDF-SHA256 +
# ChaCha20-Poly1305, no new primitive). Closes ShieldedPoolSoundness NC-8:
# a confidential-tx output can carry an encrypted note so the recipient
# scans + trial-decrypts the note secret on-chain, no out-of-band channel.
#
# Gates (via `determ test-enote-c99`): seal->open roundtrip (empty + a real
# 40-byte v||r note), determinism, wrong-key rejection with output untouched
# (the scan "not mine" signal), tamper rejection on each wire region
# (ephemeral / ciphertext / tag), malformed + off-curve fail-closed, and the
# dual-oracle KAT corpus (tools/vectors/enote.json, produced byte-independently
# by tools/verify_enote.py) reproduced byte-for-byte.
#
# Run from repo root: bash tools/test_enote_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 encrypted-note delivery (ECIES over P-256, dual-oracle) ==="
OUT=$($DETERM test-enote-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: enote (NC-8 encrypted-note delivery) unit test"; then
  echo ""
  echo "  PASS: enote-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: enote-c99 had assertion failures"
  exit 1
fi
