#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.15 — the OS-entropy shim (src/crypto/rng/) smoke gate.
# determ_rng_bytes replaced OpenSSL RAND_bytes at the daemon's entropy sites
# (per-round dh_secret commit, node keygen, genesis shard salt) in the §3.15
# migration; this wrapper runs `determ test-rng-c99`, which checks the failure
# modes a broken shim would actually exhibit: contract edges (n==0 no-op,
# draws succeed), all-zero output, repeated consecutive draws, a constant
# window inside a 64 KiB chunked fill, and a grossly non-uniform byte
# distribution (loose >4-sigma bounds — catastrophic-breakage detection, not
# a randomness certification; the real guarantee is the OS CSPRNG's).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 OS-entropy shim (determ_rng_bytes) smoke gate ==="
OUT=$($DETERM test-rng-c99 2>&1)
echo "$OUT"

if echo "$OUT" | tail -2 | grep -q "PASS: rng-c99"; then
  echo ""; echo "  PASS: rng-c99 unit test"; exit 0
else
  echo ""; echo "  FAIL: rng-c99 unit test"; exit 1
fi
