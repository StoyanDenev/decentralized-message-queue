#!/usr/bin/env bash
# D2 (binary at-rest) — canonical binary keyfile containers falsify gate.
#
# The wallet's plaintext keyfiles are the DAK1 (single) / DAB1 (batch)
# containers and the encrypted node keyfile is the DNK1 container
# (wallet/keyfmt.hpp). This wrapper drives the pure in-process falsify
# gate `selftest-keyfile-binary`, which pins:
#   * DAK1: round-trip; exact-68-byte length both directions; magic;
#     SHARPEST mutant — delete the derive-equality check (pubkey ==
#     derive(seed), the replacement for the JSON-era S-028 address
#     cross-check) in keyfmt.cpp decode_dak1 and cases K4/K5 flip RED.
#   * DAB1: round-trip; count floor; count-vs-length in BOTH directions;
#     per-record derive-equality.
#   * DNK1: round-trip through the real AEAD legs; env_len exact-EOF in
#     both directions; header-pubkey tamper => AEAD failure (pins AAD =
#     the raw 32-byte pubkey binding); ciphertext bitflip; header
#     truncation sweep.
# Positive controls (K0/B0/N0) prove the negatives are not vacuous.
#
# FAST + OFFLINE (no cluster / no daemon; tiny KDF params).
# Run from repo root: bash tools/test_wallet_keyfile_binary.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi

set +e
OUT=$("$DETERM_WALLET" selftest-keyfile-binary 2>&1)
RC=$?
set -e
echo "$OUT" | grep -E "^  ok:|^  FAIL:|^  [0-9]+ pass / |selftest-keyfile-binary" || true

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-keyfile-binary"; then
  echo "  PASS: test_wallet_keyfile_binary"
  exit 0
else
  echo "  FAIL: test_wallet_keyfile_binary (rc=$RC)"
  exit 1
fi
