#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.10 — the constant-time/hygiene primitives
# the libsodium-free C99 crypto stack builds on: determ_ct_memcmp (equality
# compare without short-circuit; consolidates the former per-module ct_eq16 /
# ct_verify_32 local helpers and frost.c's point-compare memcmps into one
# audited site at src/crypto/ct.c) and determ_secure_zero (DSE-proof wipe,
# src/crypto/secure_zero.c).
#
# 6 assertions: (1) equal buffers -> 0 across boundary lengths incl. 0;
# (2) single-byte mismatch at first/middle/last -> -1; (3) 500-case fuzz —
# ct verdict == memcmp equality verdict on every input; (4) return contract
# exactly 0/-1; (5) secure_zero wipes a patterned buffer; (6) secure_zero
# NULL/0-len no-ops + partial wipe stops at len. Functional pins only — the
# TIMING property is §3.12's dudect/ctgrind follow-up.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 constant-time primitives (determ_ct_memcmp + determ_secure_zero) ==="
OUT=$($DETERM test-ct-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: ct-c99 constant-time compare + secure-zero functional contracts held"; then
  echo ""
  echo "  PASS: test_ct_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_ct_c99 (assertion failure or missing summary marker)"
  exit 1
fi
