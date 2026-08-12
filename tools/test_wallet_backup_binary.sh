#!/usr/bin/env bash
# D2 (binary at-rest) — canonical binary backup / recovery containers gate.
#
# The wallet's backup pair is the DSS1 (Shamir share-set) + DBE1 (per-share
# envelopes) containers (wallet/keyfmt.hpp) and the recovery setup is the
# DRS1 container (wallet/recovery.hpp). This wrapper drives the pure
# in-process falsify gate `selftest-backup-binary`, which pins:
#   * DSS1: round-trip; DISTINCT-x on encode AND decode (mutant: delete the
#     decode-side check in keyfmt.cpp decode_dss1 and case S2 flips RED);
#     y_len 1..=4096 bounds; exact-length in BOTH directions.
#   * DBE1: round-trip; DISTINCT share_index; env_len length-vs-body.
#   * DRS1: version gate; threshold <= share_count; checksum_len 0|32;
#     DISTINCT guardian_x; end-to-end create -> to_bytes -> from_bytes ->
#     recover == secret; wrong password => nullopt; checksum bitflip =>
#     recover nullopt (pins the pubkey-checksum gate).
# Positive controls (S0/B0/R0/R1) prove the negatives are not vacuous.
#
# FAST + OFFLINE (no cluster / no daemon; tiny KDF params).
# Run from repo root: bash tools/test_wallet_backup_binary.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi

set +e
OUT=$("$DETERM_WALLET" selftest-backup-binary 2>&1)
RC=$?
set -e
echo "$OUT" | grep -E "^  ok:|^  FAIL:|^  [0-9]+ pass / |selftest-backup-binary" || true

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-backup-binary"; then
  echo "  PASS: test_wallet_backup_binary"
  exit 0
else
  echo "  FAIL: test_wallet_backup_binary (rc=$RC)"
  exit 1
fi
