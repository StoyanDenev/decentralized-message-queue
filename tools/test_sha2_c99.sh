#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.1 — the first vendored primitive of the
# libsodium-free C99 crypto stack: SHA-256 / SHA-512 (FIPS 180-4) in portable C99
# at src/crypto/sha2/. SHA-2 is the foundation the rest of the stack builds on
# (RFC 8032 Ed25519 + RFC 9591 FROST H1..H5 are SHA-512-based), so it unblocks
# the v2.10 work.
#
# 8 assertions: (1) byte-equal cross-validation of the C99 SHA-256 + SHA-512
# against the daemon's OpenSSL backend over EVERY message length 0..300 (single-
# block, multi-block, and both padding edges — the §Q9 cross-validation gate,
# needing no transcribed digest), (2) the canonical NIST FIPS 180-4 KATs for
# SHA-256/512 of "abc" and "" as independent anchors, (3) a 1 MiB multi-block
# message vs OpenSSL. The module is additive — not yet wired into any call site.
#
# Run from repo root: bash tools/test_sha2_c99.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 SHA-2 (FIPS 180-4) vs OpenSSL backend + NIST KATs ==="
OUT=$($DETERM test-sha2-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: sha2-c99 all cross-validation + NIST KATs matched"; then
  echo ""
  echo "  PASS: sha2-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: sha2-c99 had assertion failures"
  exit 1
fi
