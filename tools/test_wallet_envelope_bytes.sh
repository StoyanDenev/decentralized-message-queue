#!/usr/bin/env bash
# D2 (binary at-rest) — canonical BINARY envelope container falsify gate.
#
# The DWE envelope's at-rest form is the binary container in
# wallet/envelope.hpp (magic | salt_len/salt | params | nonce | aad_len/aad
# | ct_len/ct; all integers LE; decode requires the EXACT total length).
# This wrapper drives the pure in-process falsify gate
# `selftest-envelope-bytes`, which pins:
#   * round-trip field equality + decrypt for DWE1 and DWE2;
#   * the truncation sweep (every strict prefix rejects — short direction);
#   * the trailing-byte reject (long direction; SHARPEST mutant: delete the
#     final `off != len` exact-length check in envelope.cpp
#     deserialize_bytes and case X1 flips RED);
#   * one hostile-bytes case per structural bound (magic, salt_len 8..64,
#     MAX_AAD_LEN, aad length-vs-body, ct_len >= TAG, MAX_CT_LEN with a
#     real 1MiB+1 body, ct length-vs-body);
#   * the strict-hex CLI view (odd length / non-hex / legacy dot-form all
#     reject — readers accept ONLY the new form).
# Positive controls (R1/R2, H0, V1) prove the negatives are not vacuous.
#
# FAST + OFFLINE (no cluster / no daemon; tiny KDF params).
# Run from repo root: bash tools/test_wallet_envelope_bytes.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "  SKIP: determ-wallet binary not found; build with"
  echo "        cmake --build build --config Release --target determ-wallet"
  exit 0
fi

set +e
OUT=$("$DETERM_WALLET" selftest-envelope-bytes 2>&1)
RC=$?
set -e
# The selftest prints ONLY its own 2-space-indented `  ok:` / `  FAIL:` markers,
# the `  N pass / M fail` tally, and its `selftest-envelope-bytes` verdict —
# it does not drive another verifier, so nothing here can leak a foreign
# unindented `FAIL:` into run_all.sh's last-lines scan.
echo "$OUT" | grep -E "^  ok:|^  FAIL:|^  [0-9]+ pass / |selftest-envelope-bytes" || true

if [ "$RC" = "0" ] && echo "$OUT" | grep -q "PASS: selftest-envelope-bytes"; then
  echo "  PASS: test_wallet_envelope_bytes"
  exit 0
else
  echo "  FAIL: test_wallet_envelope_bytes (rc=$RC)"
  exit 1
fi
