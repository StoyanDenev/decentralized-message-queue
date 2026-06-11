#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.13 — the BINARY half of the vector-file gate. The offline
# runner tools/test_c99_vector_files.sh validates tools/vectors/*.json against
# independent python implementations (hashlib / cryptography.hazmat); this
# wrapper runs `determ test-c99-vectors`, which feeds the SAME vetted vectors
# through the shipped C99 implementations (src/crypto/*). Together the two form
# the §3.13 closed loop: file-side green + binary-side red means OUR C99 code
# diverges; both green means files and implementations agree byte-for-byte.
#
# 10 assertions — one per vector file (sha256, sha512, hmac_sha256,
# hkdf_sha256, pbkdf2_sha256, blake2b, chacha20_poly1305 [+ decrypt
# round-trip], aes256_gcm [+ decrypt round-trip], ed25519 [pubkey + sign +
# verify], x25519). A missing file or unknown primitive discriminator is a
# hard FAIL (fail-closed).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 implementations vs tools/vectors/*.json (binary half of §3.13) ==="
OUT=$($DETERM test-c99-vectors 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: c99-vectors all vector files byte-equal through the shipped C99 implementations"; then
  echo ""
  echo "  PASS: test_c99_vectors"
  exit 0
else
  echo ""
  echo "  FAIL: test_c99_vectors (divergence or missing vector file)"
  exit 1
fi
