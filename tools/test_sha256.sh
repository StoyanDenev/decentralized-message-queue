#!/usr/bin/env bash
# S-035 Option 1 seed — in-process unit test for the SHA-256 wrapper
# + SHA256Builder.
#
# Pins NIST FIPS 180-4 test vectors (verifying the cryptographic
# correctness of our libssl-EVP wrapper) AND the protocol-critical
# big-endian uint64_t encoding that every signing_bytes /
# compute_block_digest / merkle_leaf_hash path depends on
# (Preliminaries §1.3: "Multi-byte integers in hash inputs are
# encoded big-endian").
#
# A regression in SHA-256 itself would break literally every
# cryptographic claim in the protocol. A regression in
# SHA256Builder::append(uint64_t)'s big-endian encoding would make
# signing_bytes produce different hashes on little-endian vs
# big-endian machines, silently breaking consensus across platforms
# — which is why the BE convention is in Preliminaries §1.3 as a
# hard requirement.
#
# Assertions covered (10 total):
#   1. NIST FIPS 180-4 §A.1: SHA-256('') vector matches
#   2. NIST FIPS 180-4 §A.1: SHA-256('abc') vector matches
#   3. NIST FIPS 180-4 §A.2: SHA-256 56-byte vector matches
#      (exercises the >55-byte input padding path)
#   4. SHA256Builder one-shot matches sha256()
#   5. SHA256Builder 3-piece append matches concat-one-shot
#   6. SHA256Builder::append(uint64_t) is BIG-ENDIAN
#      (Preliminaries §1.3 convention — cross-platform consensus
#      depends on this)
#   7. SHA256Builder::append(int64_t) is BIG-ENDIAN with
#      two's-complement layout for negative values
#   8. sha256(Hash, Hash) helper matches concat-then-sha256
#   9. sha256(Hash, string) helper matches concat-then-sha256
#  10. sha256 deterministic across instances + one-shot
#
# Run from repo root: bash tools/test_sha256.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== SHA-256 wrapper + Big-Endian encoding ==="
OUT=$($DETERM test-sha256 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: sha256 all assertions"; then
  echo ""
  echo "  PASS: SHA-256 wrapper unit test"
  exit 0
else
  echo ""
  echo "  FAIL: sha256 had assertion failures"
  exit 1
fi
