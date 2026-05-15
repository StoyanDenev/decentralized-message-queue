#!/usr/bin/env bash
# A2 Phase 4 — libsodium primitives smoke test.
#
# Verifies the libsodium FetchContent integration is wired correctly
# and the OPAQUE-relevant primitives (ristretto255 scalar / point ops,
# Argon2id password stretching) actually execute.
#
# This does NOT verify OPAQUE itself — that arrives with libopaque in
# Phase 5. This test only confirms the building blocks libopaque will
# need are available.
#
# Run from repo root: bash tools/test_wallet_oprf_smoke.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

WALLET="$DETERM_WALLET"

OUT=$($WALLET oprf-smoke 2>&1)
echo "$OUT"

pass_count=0; fail_count=0
check() {
  if echo "$OUT" | grep -q "$1"; then
    echo "  PASS: contains '$1'"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: missing '$1'"; fail_count=$((fail_count + 1))
  fi
}

echo
echo "=== Assertions ==="
check "scalar_r  (32B):"
check "scalar_k  (32B):"
check "blinded   (32B):"
check "argon2id  (32B):"
check "libsodium primitives OK"

# Each scalar/point output is 32 bytes = 64 hex chars. Verify line widths.
SCAR_LINE=$(echo "$OUT" | grep "scalar_r" | sed 's/.*://;s/ //g' | tr -d '\r')
SCAK_LINE=$(echo "$OUT" | grep "scalar_k" | sed 's/.*://;s/ //g' | tr -d '\r')
BLND_LINE=$(echo "$OUT" | grep "blinded"  | sed 's/.*://;s/ //g' | tr -d '\r')
ARG2_LINE=$(echo "$OUT" | grep "argon2id" | sed 's/.*://;s/ //g' | tr -d '\r')

for name in scalar_r scalar_k blinded argon2id; do
  case $name in
    scalar_r) LINE=$SCAR_LINE;;
    scalar_k) LINE=$SCAK_LINE;;
    blinded)  LINE=$BLND_LINE;;
    argon2id) LINE=$ARG2_LINE;;
  esac
  if [ "${#LINE}" = "64" ]; then
    echo "  PASS: $name = 64 hex chars (32 bytes)"; pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $name = ${#LINE} chars, expected 64"; fail_count=$((fail_count + 1))
  fi
done

# Two independent randoms must differ (proves randombytes_buf is wired).
if [ "$SCAR_LINE" != "$SCAK_LINE" ]; then
  echo "  PASS: two random scalars differ"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: two random scalars identical (RNG broken or stubbed)"; fail_count=$((fail_count + 1))
fi

# Re-run; outputs must differ across invocations (entropy fresh per run).
OUT2=$($WALLET oprf-smoke 2>&1)
SCAR_LINE2=$(echo "$OUT2" | grep "scalar_r" | sed 's/.*://;s/ //g' | tr -d '\r')
if [ "$SCAR_LINE" != "$SCAR_LINE2" ]; then
  echo "  PASS: scalar_r differs across invocations"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: scalar_r identical across runs (RNG not reseeded)"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: libsodium primitives wired"; exit 0
else
  echo "  FAIL"; exit 1
fi
