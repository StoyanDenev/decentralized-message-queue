#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.11 — the determ::c99 C++ ergonomic wrapper
# (include/determ/crypto.hpp) over the C99 layer aggregated by
# include/determ/crypto.h.
#
# 10 assertions: per-primitive wrapper-output == raw-C-API-output (sha2,
# blake2b incl. throw-on-bad-param, hmac/hkdf/pbkdf2, argon2id incl.
# determinism); the error-model contract for all three AEADs (seal/open
# round-trip; tampered tag / AAD / ciphertext each open to std::nullopt — a
# normal adversarial outcome, never an exception); Ed25519 RFC 8032 §7.1
# TEST 1 through the wrapper + tamper rejection; X25519 §6.1 DH both
# directions + all-zero low-order -> nullopt; ct_equal/secure_zero contracts.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== determ::c99 C++ wrapper vs raw C99 API (§3.11) ==="
OUT=$($DETERM test-c99-api 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: c99-api determ::c99 wrapper == raw C API; error-model contracts held"; then
  echo ""
  echo "  PASS: test_c99_api"
  exit 0
else
  echo ""
  echo "  FAIL: test_c99_api (assertion failure or missing summary marker)"
  exit 1
fi
