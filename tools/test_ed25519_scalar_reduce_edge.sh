#!/usr/bin/env bash
# Edge/boundary coverage for the C99 Ed25519 scalar reduction
# determ_ed25519_sc_reduce64 (64->32 mod L) + determ_ed25519_sc_is_canonical
# (src/crypto/ed25519/ed25519.c). The existing test-ed25519-c99 / test-frost-c99
# exercise sc_reduce64 only on SHA-512 outputs / fuzzed seeds (happy path); this
# pins the PATHOLOGICAL-input contract that load-bears every signature + FROST
# share: the reduced output is ALWAYS canonical (< L) for any 64-byte input,
# with exact identities at the boundaries.
#
# 13 assertions (no external oracle — L is a public constant, sc_is_canonical is
# the witness): reduce(0)=0; reduce(0xff^64) canonical; reduce(L)=0 (exact order
# boundary); reduce(L-1)=L-1 (identity on the largest canonical value);
# reduce(42)=42; reduce(L+7)=7 (modular wrap past the order); reduce(2^256-1)
# canonical; determinism; canonical for 256 patterned inputs; and the
# sc_is_canonical(L)=false / sc_is_canonical(L-1)=true witness sanity.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Ed25519 sc_reduce64 / sc_is_canonical edge + boundary contract ==="
OUT=$($DETERM test-ed25519-scalar-reduce 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ed25519-scalar-reduce all assertions"; then
  echo ""
  echo "  PASS: ed25519-scalar-reduce unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ed25519-scalar-reduce had assertion failures"
  exit 1
fi
