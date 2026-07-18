#!/usr/bin/env bash
# NC-8 wiring inc.3: the read-only enote SCAN (chain::scan_enotes) that backs the
# `scan_enotes` RPC (EncryptedNoteDeliveryDesign §5.3). A wallet pulls the per-
# output encrypted-note delivery ciphertexts that inc.2 carries on CONFIDENTIAL_
# TRANSFER (TxType=14) txs over a height range and trial-decrypts them (a
# verifying AEAD tag = "mine"). It is a pure reader — re-runs the SAME
# ctx_split_enotes mirror the validator/apply use — and is PROFILE-AGNOSTIC (the
# ciphertext rides the tx payload on both MODERN and FIPS chains).
#
# Gates (via `determ test-scan-enotes`): every per-output enote is surfaced as
# (height, tx_hash, output_index, commitment, ciphertext); the commitment keys
# the enote to its output note; the [from,to) range is half-open + clamped (no
# OOB on empty/past-end ranges); a region-free CONFIDENTIAL_TRANSFER yields
# nothing; and a FIPS chain returns the same hits as MODERN.
#
# Run from repo root: bash tools/test_scan_enotes.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 enote scan (per-output ciphertexts over a height range; profile-agnostic) ==="
OUT=$($DETERM test-scan-enotes 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: scan-enotes all assertions"; then
  echo ""
  echo "  PASS: scan-enotes unit test"
  exit 0
else
  echo ""
  echo "  FAIL: scan-enotes had assertion failures"
  exit 1
fi
