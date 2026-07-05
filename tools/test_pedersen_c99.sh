#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.19 — the C99 Pedersen commitment over NIST P-256
# (src/crypto/pedersen/pedersen.c: C = v*G + r*H, H a nothing-up-my-sleeve
# second generator via RFC 9380 hash_to_curve). Pure composition over the
# §3.8c P-256 primitives already gated byte-equal vs OpenSSL / RFC 9380.
#
# 8 assertions: (1) H is on-curve, deterministic, != G, and matches the pinned
# compressed KAT; (2) commit(v,r) == compress(v*G + r*H) recomputed via the raw
# P-256 API; (3) the v==0 zero-value path C == r*H; (4) the additive
# homomorphism commit(v1,r1)+commit(v2,r2) == commit(v1+v2, r1+r2) — the
# decisive algebraic gate; (5) open/verify accepts a correct (v,r) and rejects a
# wrong value / wrong blinding / tampered commitment; (6) binding sanity
# (distinct values -> distinct commitments); (7) input validation (r==0, v>=n,
# non-decodable add input all rejected). The byte-frozen H + commitment corpus
# is cross-checked file-side (independent python) in tools/test_c99_vector_files.sh
# (pedersen.json), the §3.13 second half.
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== C99 Pedersen commitment over P-256 (§3.19) ==="
OUT=$($DETERM test-pedersen-c99 2>&1)
echo "$OUT"

# Pin the binary's CURRENT terminal summary marker exactly (re-pin this grep
# whenever the summary text changes — a stale pin fails on every run; see the
# test_frost_c99.sh precedent).
if echo "$OUT" | tail -3 | grep -q "PASS: pedersen-c99 unit test"; then
  echo ""
  echo "  PASS: test_pedersen_c99"
  exit 0
else
  echo ""
  echo "  FAIL: test_pedersen_c99 (assertion failure or missing summary marker)"
  exit 1
fi
