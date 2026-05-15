#!/usr/bin/env bash
# A2 Phase 7 — recovery flow using the OPAQUE adapter (stub) for
# per-guardian key derivation.
#
# This test exercises the create-recovery / recover code paths under
# --scheme opaque. It verifies:
#   1. Setup produced with --scheme opaque is tagged with the correct
#      suite name in its JSON.
#   2. opaque_records[] is populated (size = share_count).
#   3. Recovery with the right password reconstructs the seed.
#   4. Recovery with the wrong password fails.
#   5. Recovery against a setup whose suite tag doesn't match the
#      currently-linked adapter is rejected (forward-compat: a setup
#      created under Phase 6 real-OPAQUE will refuse to recover under
#      the Phase 5 stub adapter, and vice versa).
#   6. The passphrase-scheme path (Phase 3) still works unchanged.
#
# Run from repo root: bash tools/test_wallet_opaque_recovery.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

WALLET="$DETERM_WALLET"
T_DIR=test_opaque_recovery
SEED="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PW="myp4ssphr4se"

rm -rf $T_DIR; mkdir -p $T_DIR

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Create 3-of-5 setup with --scheme opaque ==="
$WALLET create-recovery --seed $SEED --password "$PW" -t 3 -n 5 \
  --scheme opaque --out $T_DIR/opq.json 2>&1 | tail -5
SCHEME=$(python -c "import json; print(json.load(open('$T_DIR/opq.json'))['scheme'])")
RECCOUNT=$(python -c "import json; print(len(json.load(open('$T_DIR/opq.json'))['opaque_records']))")
assert_eq "$SCHEME"   "shamir-aead-opaque-stub-argon2id-v1" "scheme tag matches stub suite"
assert_eq "$RECCOUNT" "5" "opaque_records has share_count entries"

echo
echo "=== 2. Recover with right password (3 guardians) ==="
R1=$($WALLET recover --in $T_DIR/opq.json --password "$PW" --guardians 0,2,4 | tr -d '\r')
assert_eq "$R1" "$SEED" "opaque-scheme recovery (3 of 5) round-trips"

echo
echo "=== 3. Recover with all 5 guardians ==="
R_ALL=$($WALLET recover --in $T_DIR/opq.json --password "$PW" | tr -d '\r')
assert_eq "$R_ALL" "$SEED" "opaque-scheme recovery (all 5) round-trips"

echo
echo "=== 4. Recover with wrong password fails ==="
WRONG=$($WALLET recover --in $T_DIR/opq.json --password "wrongpw" 2>&1 | tr -d '\r')
if echo "$WRONG" | grep -q "reconstruction failed"; then
  echo "  PASS: wrong password rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: wrong password not rejected — got: $WRONG"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 5. Forward-compat: mismatched suite tag rejected ==="
# Forge a setup with a suite tag that doesn't match our linked adapter.
python -c "
import json
with open('$T_DIR/opq.json') as f: s = json.load(f)
s['scheme'] = 'shamir-aead-opaque-fake-suite-v9'
with open('$T_DIR/opq_wrong_suite.json','w') as f: json.dump(s,f,indent=2)
"
WRONG_SUITE=$($WALLET recover --in $T_DIR/opq_wrong_suite.json --password "$PW" 2>&1 | tr -d '\r')
if echo "$WRONG_SUITE" | grep -q "reconstruction failed"; then
  echo "  PASS: mismatched suite rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: mismatched suite not rejected — got: $WRONG_SUITE"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 6. Passphrase scheme (Phase 3) still works ==="
$WALLET create-recovery --seed $SEED --password "$PW" -t 2 -n 3 \
  --out $T_DIR/pp.json 2>&1 | tail -1
PP_SCHEME=$(python -c "import json; print(json.load(open('$T_DIR/pp.json'))['scheme'])")
assert_eq "$PP_SCHEME" "shamir-aead-passphrase" "passphrase scheme tag unchanged"
PP_R=$($WALLET recover --in $T_DIR/pp.json --password "$PW" --guardians 0,2 | tr -d '\r')
assert_eq "$PP_R" "$SEED" "passphrase-scheme recovery still round-trips"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: OPAQUE-scheme recovery end-to-end"; exit 0
else
  echo "  FAIL"; exit 1
fi
