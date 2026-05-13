#!/usr/bin/env bash
# A2 Phase 1 — determ-wallet shamir split/combine smoke test.
#
# Verifies:
#   1. split produces N distinct shares with non-zero x-coordinates 1..N.
#   2. any T-share subset (chosen multiple ways) reconstructs the secret.
#   3. T-1 shares produce a *different* output (information-theoretic
#      property: any 0..T-1 shares are indistinguishable from a uniform
#      secret).
#   4. Tampering with one share's y-coordinate produces garbage on
#      reconstruction (no false-positive integrity, by SSS design).
#   5. Duplicate-x shares are rejected.
#
# Run from repo root: bash tools/test_wallet_shamir.sh
set -u
cd "$(dirname "$0")/.."

WALLET=build/Release/determ-wallet.exe

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then
    echo "  PASS: $3"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3"
    echo "       expected: $2"
    echo "       got:      $1"
    fail_count=$((fail_count + 1))
  fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then
    echo "  PASS: $3"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: $3 (unexpected equality)"
    fail_count=$((fail_count + 1))
  fi
}

SECRET="deadbeefcafebabe0011223344556677"

echo "=== 1. Split 16-byte secret into 5 shares with threshold 3 ==="
SHARES_RAW=$($WALLET shamir split $SECRET -t 3 -n 5 | tr -d '\r')
mapfile -t SHARES <<< "$SHARES_RAW"
assert_eq "${#SHARES[@]}" "5" "split produced 5 shares"
for i in 0 1 2 3 4; do
  xhex=$(echo "${SHARES[$i]}" | cut -d: -f1)
  expected=$(printf "%02x" $((i + 1)))
  assert_eq "$xhex" "$expected" "share[$i] x-coordinate = $expected"
done

echo
echo "=== 2. Reconstruct from three different 3-share subsets ==="
R1=$($WALLET shamir combine "${SHARES[0]}" "${SHARES[1]}" "${SHARES[2]}")
R2=$($WALLET shamir combine "${SHARES[0]}" "${SHARES[2]}" "${SHARES[4]}")
R3=$($WALLET shamir combine "${SHARES[1]}" "${SHARES[3]}" "${SHARES[4]}")
assert_eq "$R1" "$SECRET" "subset {1,2,3} → original"
assert_eq "$R2" "$SECRET" "subset {1,3,5} → original"
assert_eq "$R3" "$SECRET" "subset {2,4,5} → original"

echo
echo "=== 3. Reconstruct with all 5 shares (over-threshold) ==="
R_ALL=$($WALLET shamir combine "${SHARES[0]}" "${SHARES[1]}" "${SHARES[2]}" "${SHARES[3]}" "${SHARES[4]}")
assert_eq "$R_ALL" "$SECRET" "all 5 shares → original"

echo
echo "=== 4. Two shares (below threshold) → wrong output ==="
R_LOW=$($WALLET shamir combine "${SHARES[0]}" "${SHARES[1]}" 2>/dev/null || echo "rejected")
assert_neq "$R_LOW" "$SECRET" "2 shares != original (information-theoretic security)"

echo
echo "=== 5. Tampered share → garbage reconstruction ==="
# Flip one byte in share[2]'s y component
TAMPERED=$(echo "${SHARES[2]}" | sed 's/\(.\{5\}\)./\1f/')
R_TAMPERED=$($WALLET shamir combine "${SHARES[0]}" "$TAMPERED" "${SHARES[4]}")
assert_neq "$R_TAMPERED" "$SECRET" "tampered share → reconstruction != original"

echo
echo "=== 6. Duplicate-x shares rejected ==="
DUP_OUT=$($WALLET shamir combine "${SHARES[0]}" "${SHARES[0]}" "${SHARES[1]}" 2>&1)
if echo "$DUP_OUT" | grep -q "inconsistent"; then
  echo "  PASS: duplicate x rejected"
  pass_count=$((pass_count + 1))
else
  echo "  FAIL: duplicate x not rejected — got: $DUP_OUT"
  fail_count=$((fail_count + 1))
fi

echo
echo "=== 7. 32-byte secret (Ed25519 seed size) round-trip ==="
SEED="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SEED_SHARES=$($WALLET shamir split $SEED -t 2 -n 3 | tr -d '\r')
mapfile -t SS <<< "$SEED_SHARES"
SEED_R=$($WALLET shamir combine "${SS[0]}" "${SS[2]}")
assert_eq "$SEED_R" "$SEED" "32-byte Ed25519 seed splits + reconstructs"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet shamir end-to-end"
  exit 0
else
  echo "  FAIL"
  exit 1
fi
