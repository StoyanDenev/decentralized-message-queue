#!/usr/bin/env bash
# determ-light sign-tx — offline TRANSFER/STAKE/UNSTAKE signing.
#
# Pure offline test (no cluster). Uses determ-wallet to mint a fresh
# anon keypair, then exercises determ-light sign-tx and cross-verifies
# the resulting signed envelope via determ-wallet validate-tx —
# i.e., the wallet's verifier accepts a tx signed by the light-client,
# which proves byte-for-byte parity of signing_bytes across binaries.
#
# Assertions:
#   1. sign-tx --type TRANSFER produces a signed JSON.
#   2. signed JSON has type/from/to/amount/fee/nonce/sig/hash fields.
#   3. signature is 128 hex chars; hash is 64 hex chars.
#   4. determ-wallet validate-tx accepts the signed envelope (overall_valid=true).
#   5. Missing required flag → exit 1.
#   6. STAKE type signing also succeeds.
#
# Run from repo root: bash tools/test_light_sign_tx.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"
    exit 0
fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed for parity check)"
    exit 0
fi

TMP="build/test_light_sign_tx.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Mint two anon keypairs ==="
"$DETERM_WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
PRIV_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['privkey_hex'])")
PUB_A="${ADDR_A#0x}"

# Write canonical-shape keyfile for ADDR_A.
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a.json"

echo "  alice address: $ADDR_A"
echo "  bob address:   $ADDR_B"

echo
echo "=== 2. sign-tx --type TRANSFER produces signed JSON ==="
set +e
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount 100 --fee 0 --nonce 0 --out "$TMP/tx.json" \
    > "$TMP/sign.out" 2>&1
RC=$?
set -e
if [ "$RC" = "0" ] && [ -s "$TMP/tx.json" ]; then
    assert "true" "sign-tx TRANSFER produced output"
else
    cat "$TMP/sign.out"
    assert "false" "sign-tx TRANSFER produced output (RC=$RC)"
fi

echo
echo "=== 3. Signed JSON has expected fields ==="
MISSING=$($PY -c "
import json
d = json.load(open('$TMP/tx.json'))
need = ['type','from','to','amount','fee','nonce','sig','hash']
print(','.join([k for k in need if k not in d]))
")
if [ -z "$MISSING" ]; then
    assert "true" "all required fields present"
else
    assert "false" "all required fields present (missing: $MISSING)"
fi

echo
echo "=== 4. signature is 128 hex chars, hash is 64 hex chars ==="
SIG_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/tx.json'))['sig']))")
HASH_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/tx.json'))['hash']))")
if [ "$SIG_LEN" = "128" ] && [ "$HASH_LEN" = "64" ]; then
    assert "true" "sig=$SIG_LEN hex, hash=$HASH_LEN hex"
else
    assert "false" "sig=$SIG_LEN (want 128), hash=$HASH_LEN (want 64)"
fi

echo
echo "=== 5. determ-wallet validate-tx accepts signed envelope ==="
# determ-wallet validate-tx --tx-json --json prints a JSON object
# with valid_structural, signature_verified, overall_valid fields.
VALID_JSON=$("$DETERM_WALLET" validate-tx --tx-json "$TMP/tx.json" --json 2>&1)
OVERALL=$(echo "$VALID_JSON" | $PY -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    print(d.get('overall_valid', False))
except Exception:
    print(False)
")
if [ "$OVERALL" = "True" ] || [ "$OVERALL" = "true" ]; then
    assert "true" "wallet validate-tx accepts light-signed tx"
else
    echo "  validate-tx output:"
    echo "$VALID_JSON"
    assert "false" "wallet validate-tx accepts light-signed tx (overall=$OVERALL)"
fi

echo
echo "=== 6. Missing --to: exit 1 ==="
set +e
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --amount 100 --fee 0 --nonce 0 --out "$TMP/notx.json" \
    >/dev/null 2>&1
RC=$?
set -e
if [ "$RC" = "1" ]; then
    assert "true" "missing --to returns exit 1"
else
    assert "false" "missing --to returns exit 1 (got $RC)"
fi

echo
echo "=== 7. STAKE signing also succeeds ==="
set +e
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type STAKE \
    --to validator-node --amount 1000 --fee 0 --nonce 1 --out "$TMP/stake.json" \
    >/dev/null 2>&1
RC=$?
set -e
if [ "$RC" = "0" ] && [ -s "$TMP/stake.json" ]; then
    assert "true" "STAKE signing succeeds"
else
    assert "false" "STAKE signing succeeds (RC=$RC)"
fi

echo
echo "=== 8. Two signs of the same tx body produce identical sigs (Ed25519 deterministic) ==="
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key_a.json" --type TRANSFER \
    --to "$ADDR_B" --amount 100 --fee 0 --nonce 0 --out "$TMP/tx2.json" >/dev/null 2>&1
SIG1=$($PY -c "import json; print(json.load(open('$TMP/tx.json'))['sig'])")
SIG2=$($PY -c "import json; print(json.load(open('$TMP/tx2.json'))['sig'])")
if [ "$SIG1" = "$SIG2" ]; then
    assert "true" "Ed25519 determinism: sig stable across re-sign"
else
    assert "false" "Ed25519 determinism: sig stable across re-sign"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_sign_tx"; exit 0
else
  echo "  FAIL: test_light_sign_tx"; exit 1
fi
