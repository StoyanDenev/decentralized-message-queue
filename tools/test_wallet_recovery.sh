#!/usr/bin/env bash
# A2 Phase 3 — unchained-wallet create-recovery + recover end-to-end.
#
# Verifies:
#   1. create-recovery writes a self-contained recovery setup.
#   2. recover with the right password + at-or-above-threshold
#      guardian subset reconstructs the original seed.
#   3. recover with below-threshold subset fails.
#   4. recover with wrong password fails (every envelope tag fails).
#   5. Tampering with one envelope still recovers if T others succeed.
#   6. Recovery setup persists across writes (load → recover from disk).
#   7. Pubkey checksum binds: recovery fails on a forged setup whose
#      seed reconstructs but doesn't match the registered pubkey.
#
# Run from repo root: bash tools/test_wallet_recovery.sh
set -u
cd "$(dirname "$0")/.."

WALLET=build/Release/unchained-wallet.exe
T_DIR=test_recovery
SEED="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PW="myp4ssphr4se"

rm -rf $T_DIR; mkdir -p $T_DIR

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (unexpected equality)"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Create 3-of-5 recovery setup ==="
$WALLET create-recovery --seed $SEED --password "$PW" -t 3 -n 5 \
  --out $T_DIR/setup.json 2>&1 | tail -4
if [ -f $T_DIR/setup.json ]; then
  echo "  PASS: setup.json written"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: setup.json missing"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. Recover with 3 guardians (at threshold) ==="
R1=$($WALLET recover --in $T_DIR/setup.json --password "$PW" --guardians 0,1,2 | tr -d '\r')
assert_eq "$R1" "$SEED" "guardians 0,1,2 reconstruct seed"
R2=$($WALLET recover --in $T_DIR/setup.json --password "$PW" --guardians 0,2,4 | tr -d '\r')
assert_eq "$R2" "$SEED" "guardians 0,2,4 reconstruct seed"

echo
echo "=== 3. Recover with all 5 (over-threshold) ==="
R_ALL=$($WALLET recover --in $T_DIR/setup.json --password "$PW" | tr -d '\r')
assert_eq "$R_ALL" "$SEED" "all-guardians default reconstructs seed"

echo
echo "=== 4. Below-threshold fails ==="
R_LOW=$($WALLET recover --in $T_DIR/setup.json --password "$PW" --guardians 0,1 2>&1 | tr -d '\r')
if echo "$R_LOW" | grep -q "reconstruction failed"; then
  echo "  PASS: 2 guardians below threshold rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: 2 guardians not rejected — got: $R_LOW"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 5. Wrong password fails ==="
R_WPW=$($WALLET recover --in $T_DIR/setup.json --password "wrongpw" 2>&1 | tr -d '\r')
if echo "$R_WPW" | grep -q "reconstruction failed"; then
  echo "  PASS: wrong password rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: wrong password not rejected"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 6. Recovery with 4 guardians where 1 is corrupted ==="
# Corrupt one envelope's ciphertext by mutating a byte of guardian 0's
# entry. The other 4 should still satisfy threshold=3.
python -c "
import json
with open('$T_DIR/setup.json') as f: s = json.load(f)
# Flip the last hex char of guardian 0's envelope
parts = s['envelopes'][0].split('.')
ct = parts[-1]
parts[-1] = ct[:-1] + ('f' if ct[-1] != 'f' else 'e')
s['envelopes'][0] = '.'.join(parts)
with open('$T_DIR/setup_corrupted.json','w') as f: json.dump(s,f,indent=2)
"
R_CORRUPT=$($WALLET recover --in $T_DIR/setup_corrupted.json --password "$PW" --guardians 0,1,2,3,4 | tr -d '\r')
assert_eq "$R_CORRUPT" "$SEED" "tampered guardian 0 still recovers via others"

echo
echo "=== 7. Pubkey checksum mismatch fails ==="
# Forge a setup that decrypts successfully but reconstructs a different
# seed. We mutate the stored pubkey_checksum so the gate fires.
python -c "
import json
with open('$T_DIR/setup.json') as f: s = json.load(f)
s['pubkey_checksum'] = 'deadbeef' + s['pubkey_checksum'][8:]
with open('$T_DIR/setup_wrong_checksum.json','w') as f: json.dump(s,f,indent=2)
"
R_CK=$($WALLET recover --in $T_DIR/setup_wrong_checksum.json --password "$PW" 2>&1 | tr -d '\r')
if echo "$R_CK" | grep -q "reconstruction failed"; then
  echo "  PASS: pubkey-checksum mismatch rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: checksum mismatch not rejected — got: $R_CK"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: unchained-wallet recovery end-to-end"; exit 0
else
  echo "  FAIL"; exit 1
fi
