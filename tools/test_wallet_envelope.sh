#!/usr/bin/env bash
# A2 Phase 2 — determ-wallet envelope (AES-256-GCM) smoke test.
#
# Verifies:
#   1. encrypt + decrypt round-trip yields the original plaintext.
#   2. Wrong password fails AEAD verification (exit code 2).
#   3. Tampered ciphertext fails AEAD verification.
#   4. Mismatched AAD fails AEAD verification.
#   5. Each encrypt produces a fresh salt + nonce (envelopes differ even
#      with identical inputs).
#   6. Combined flow: split → encrypt each share → decrypt → combine
#      reconstructs the secret.
#
# Run from repo root: bash tools/test_wallet_envelope.sh
set -u
cd "$(dirname "$0")/.."

WALLET=build/Release/determ-wallet.exe
PLAIN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PW="hunter2"
ITERS=10000   # keep low for test speed; production uses 600000

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (unexpected equality)"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Encrypt + decrypt round-trip ==="
ENV=$($WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --iters $ITERS | tr -d '\r')
DEC=$($WALLET envelope decrypt --envelope "$ENV" --password "$PW" | tr -d '\r')
assert_eq "$DEC" "$PLAIN" "round-trip plaintext"

echo
echo "=== 2. Wrong password rejected ==="
DEC_WRONG=$($WALLET envelope decrypt --envelope "$ENV" --password "wrongpw" 2>&1 | tr -d '\r')
if echo "$DEC_WRONG" | grep -q "AEAD tag failure"; then
  echo "  PASS: wrong password rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: wrong password not rejected — got: $DEC_WRONG"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 3. Tampered ciphertext rejected ==="
# Flip the last hex char (inside the GCM tag area)
TAMPERED=$(echo "$ENV" | sed 's/.$/f/')
DEC_T=$($WALLET envelope decrypt --envelope "$TAMPERED" --password "$PW" 2>&1 | tr -d '\r')
if echo "$DEC_T" | grep -q "AEAD tag failure"; then
  echo "  PASS: tampered ciphertext rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: tampered ciphertext not rejected — got: $DEC_T"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. AAD binding ==="
ENV_AAD=$($WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --aad cafebabe --iters $ITERS | tr -d '\r')
DEC_OK=$($WALLET envelope decrypt --envelope "$ENV_AAD" --password "$PW" --aad cafebabe | tr -d '\r')
assert_eq "$DEC_OK" "$PLAIN" "AAD match decrypts correctly"
DEC_BAD=$($WALLET envelope decrypt --envelope "$ENV_AAD" --password "$PW" --aad deadbeef 2>&1 | tr -d '\r')
if echo "$DEC_BAD" | grep -q "AEAD tag failure"; then
  echo "  PASS: AAD mismatch rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: AAD mismatch not rejected"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 5. Each encrypt produces a fresh salt + nonce ==="
ENV_A=$($WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --iters $ITERS | tr -d '\r')
ENV_B=$($WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --iters $ITERS | tr -d '\r')
assert_neq "$ENV_A" "$ENV_B" "two encrypts of same plaintext differ"

echo
echo "=== 6. Split → encrypt-each → decrypt-each → combine ==="
SECRET="00112233445566778899aabbccddeeff"
SHARES=$($WALLET shamir split $SECRET -t 2 -n 3 | tr -d '\r')
mapfile -t S <<< "$SHARES"
# Encrypt each share's hex form (strip "<x>:" so we wrap just the y bytes,
# then re-attach x at recovery).
WRAPPED=()
for share in "${S[@]}"; do
  X=$(echo "$share" | cut -d: -f1)
  Y=$(echo "$share" | cut -d: -f2)
  ENV_S=$($WALLET envelope encrypt --plaintext "$Y" --password "$PW" --iters $ITERS | tr -d '\r')
  WRAPPED+=("$X|$ENV_S")
done

# Decrypt two of the wrapped shares; reattach x; combine.
DEC_SHARES=()
for i in 0 2; do
  W="${WRAPPED[$i]}"
  X=$(echo "$W" | cut -d'|' -f1)
  ENV_S=$(echo "$W" | cut -d'|' -f2)
  Y=$($WALLET envelope decrypt --envelope "$ENV_S" --password "$PW" | tr -d '\r')
  DEC_SHARES+=("$X:$Y")
done
RECOV=$($WALLET shamir combine "${DEC_SHARES[0]}" "${DEC_SHARES[1]}" | tr -d '\r')
assert_eq "$RECOV" "$SECRET" "encrypted-share threshold reconstruction"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet envelope end-to-end"; exit 0
else
  echo "  FAIL"; exit 1
fi
