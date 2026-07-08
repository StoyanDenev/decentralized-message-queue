#!/usr/bin/env bash
# v2.10 Phase 0 / CRYPTO-C99-SPEC §3.6 prerequisite — the libsodium-free C99 BLAKE2b
# (RFC 7693) at src/crypto/blake2/, the hash Argon2id is built on. Keyed (MAC) +
# variable-length-output modes; canonical reference construction. No key-dependent
# branch/index; key material zeroized on final.
#
# Assertions: (1) the unkeyed 64-byte digest byte-equal vs OpenSSL EVP_blake2b512
# over a fuzzed message-length grid (the §Q9 gate — full compression/G/SIGMA/IV/
# finalize); (2) keyed + variable-length outputs match python hashlib.blake2b
# reference vectors (an independent BLAKE2 impl — OpenSSL's EVP exposes only the
# unkeyed 64-byte digest); (3) incremental update == one-shot across the key +
# outlen paths; (4) keyed!=unkeyed, output-length-in-param, and parameter-error
# rejection. Additive -- not yet wired into a call site (Argon2id §3.6 will consume it).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# Minix §6 OpenSSL split: this oracle subcommand lives in the standalone
# determ-cryptotest binary (the daemon links zero OpenSSL).
if [ -z "${DETERM_CRYPTOTEST:-}" ]; then
  echo "  FAIL: determ-cryptotest binary not found (build the determ-cryptotest target or set DETERM_CRYPTOTEST_BIN)"
  exit 1
fi

echo "=== C99 BLAKE2b (RFC 7693) vs OpenSSL EVP_blake2b512 + hashlib.blake2b KATs ==="
OUT=$($DETERM_CRYPTOTEST test-blake2b-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: blake2b-c99 all cross-validation + KATs matched"; then
  echo ""
  echo "  PASS: blake2b-c99 unit test"
  exit 0
else
  echo ""
  echo "  FAIL: blake2b-c99 had assertion failures"
  exit 1
fi
