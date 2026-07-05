#!/usr/bin/env bash
# CRYPTO-C99-SPEC §3.19 — the C99 Pedersen commitment over NIST P-256
# (src/crypto/pedersen/pedersen.c: C = v*G + r*H, H a nothing-up-my-sleeve
# second generator via RFC 9380 hash_to_curve). Pure composition over the
# §3.8c P-256 primitives already gated byte-equal vs OpenSSL / RFC 9380.
#
# 14 assertions. Increment 1 (single commitment) (1)-(7): H on-curve/
# deterministic/!=G/pinned KAT; commit(v,r)==compress(v*G+r*H) via the raw P-256
# API; the v==0 zero-value path C==r*H; the additive homomorphism
# commit(v1,r1)+commit(v2,r2)==commit(v1+v2,r1+r2); open/verify accept + reject
# (wrong value / wrong blinding / tampered commitment); binding sanity; input
# validation (r==0, v>=n, non-decodable add). Increment 2 (vector commitment)
# (8)-(11): the nothing-up-my-sleeve vector generators gen(i,which) on-curve/
# deterministic/distinct/!=G,H + which>1 reject; vector_commit == r*H +
# Σ(a_i*G_i + b_i*H_i) via the raw API; the vector homomorphism; n==0 => r*H +
# zero-entry skip + r==0 reject. Increment 3 (general MSM) (12)-(14): Σ s_i*P_i
# == recompute + vector_commit is the MSM special case over [H,G_i,H_i];
# canceling terms -> identity (rc 1) + zero-scalar skip + n==0 -> identity;
# scalar>=n / non-decodable point reject. The byte-frozen H / generator /
# commitment / msm corpus (14 vectors) is cross-checked file-side by an
# independent python in tools/test_c99_vector_files.sh (pedersen.json), the §3.13
# second half.
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
