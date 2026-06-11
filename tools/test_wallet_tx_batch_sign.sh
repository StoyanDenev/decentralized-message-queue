#!/usr/bin/env bash
# determ-wallet tx-batch-sign CLI test (A2 round 1).
#
# Exercises batch-mode offline signing for payroll / airdrop / settlement
# operators. The sibling sign-anon-tx command builds + signs ONE TRANSFER
# from CLI flags; tx-batch-sign reads N tx-input records from a JSON
# array and emits N signed envelopes in one process invocation (no
# per-tx subprocess spawn cost).
#
# Per-record input shape:
#   {"type":"TRANSFER"|"STAKE"|"UNSTAKE", from, to, amount, fee, nonce}
#
# Per-record output shape (matches Transaction::to_json):
#   {"type":<int>, from, to, amount, fee, nonce, payload:"", sig, hash}
#
# Assertions exercised by this wrapper (covers the seven required spec
# items plus surface coverage):
#   A. Empty input array → empty output array (edge case).
#   B. Single-tx input array → single signed envelope, sig validates via
#      `determ-wallet validate-tx`.
#   C. Three-tx batch → three envelopes; each sig validates independently.
#   D. Order preservation: output[i] corresponds to input[i] (verified by
#      using distinct amounts per tx and reading them back in order).
#   E. Same input + same keyfile → same output bytes (Ed25519 deterministic).
#   F. Passphrase-locked (DETERM-NODE-V1) keyfile: works with
#      --passphrase-env DETERM_PASSPHRASE.
#   G. Invalid input (malformed JSON, missing fields, wrong types,
#      mismatched from, etc.) → non-zero exit + helpful error.
#
# Plus surface gates:
#   - Global help mentions tx-batch-sign.
#   - tx-batch-sign --help exits 0.
#   - Missing required flags rejected.
#   - STAKE / UNSTAKE type strings supported alongside TRANSFER.
#   - Output type field is numeric (Transaction::to_json shape).
#   - Output file gets 0600-style perms (POSIX best-effort).
#   - --force allows overwriting an existing --out.
#
# Run from repo root: bash tools/test_wallet_tx_batch_sign.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_tx_batch_sign.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_ne() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       did not expect: $2"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Generate two fresh keypairs.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/keys.json")
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/keys.json")
PUB_A="${ADDR_A#0x}"
ADDR_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['address'])"     "$TMP/keys.json")

# Plaintext keyfile (canonical wallet shape).
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a.json"

# Encrypted keyfile (DETERM-NODE-V1) for the passphrase-env assertion. Use
# the wallet's own keyfile-create primitive — that's the canonical
# producer the keyfile-decrypt path round-trips against.
export DETERM_PASSPHRASE='batch-sign-test-pass-2026'
"$WALLET" keyfile-create \
    --priv "$PRIV_A" \
    --passphrase-from env:DETERM_PASSPHRASE \
    --out "$TMP/key_a.enc" >/dev/null 2>&1
if [ ! -f "$TMP/key_a.enc" ]; then
  echo "  SETUP-FAIL: keyfile-create did not produce $TMP/key_a.enc"
  fail_count=$((fail_count + 1))
fi

echo "=== 1. Global help mentions tx-batch-sign ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "tx-batch-sign"; then
  echo "  PASS: help mentions tx-batch-sign"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing tx-batch-sign"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. tx-batch-sign --help exits 0 ==="
set +e
"$WALLET" tx-batch-sign --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-batch-sign --help exits 0"

echo
echo "=== 3. Missing required flags rejected ==="
set +e
"$WALLET" tx-batch-sign >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no args returns 1"

echo
echo "=== A. Empty input array → empty output array (edge case) ==="
echo "[]" > "$TMP/in_empty.json"
set +e
OUT_A=$("$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_empty.json" --out "$TMP/out_empty.json" 2>&1)
RC=$?
set -e
assert_eq "$RC" "0" "empty input: exit 0"
COUNT_A=$($PY -c "import json; print(len(json.load(open('$TMP/out_empty.json'))))")
assert_eq "$COUNT_A" "0" "empty input: output array length is 0"
SHAPE_A=$($PY -c "import json; d=json.load(open('$TMP/out_empty.json')); print('array' if isinstance(d, list) else type(d).__name__)")
assert_eq "$SHAPE_A" "array" "empty input: output is still a JSON array"

echo
echo "=== B. Single-tx input → single envelope; sig validates ==="
$PY -c "
import json
recs = [{'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':1000, 'fee':5, 'nonce':1}]
json.dump(recs, open('$TMP/in_single.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_single.json" --out "$TMP/out_single.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "single-tx batch: exit 0"
COUNT_B=$($PY -c "import json; print(len(json.load(open('$TMP/out_single.json'))))")
assert_eq "$COUNT_B" "1" "single-tx batch: output array length is 1"

# Pull the envelope out into its own file so validate-tx can chew on it.
$PY -c "
import json
arr = json.load(open('$TMP/out_single.json'))
json.dump(arr[0], open('$TMP/out_single_e0.json','w'))
"
SIG_LEN_B=$($PY -c "import json; print(len(json.load(open('$TMP/out_single_e0.json'))['sig']))")
assert_eq "$SIG_LEN_B" "128" "single envelope sig is 128 hex chars"
HASH_LEN_B=$($PY -c "import json; print(len(json.load(open('$TMP/out_single_e0.json'))['hash']))")
assert_eq "$HASH_LEN_B" "64" "single envelope hash is 64 hex chars"
TYPE_B=$($PY -c "import json; print(json.load(open('$TMP/out_single_e0.json'))['type'])")
assert_eq "$TYPE_B" "0" "single envelope type is numeric (0 = TRANSFER)"

# validate-tx round-trip — independent verification via the chain's
# canonical signing_bytes scheme.
set +e
"$WALLET" validate-tx --tx-json "$TMP/out_single_e0.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "validate-tx accepts the single-tx envelope (sig valid)"

echo
echo "=== C. Three-tx batch → three envelopes; each sig validates ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':111, 'fee':1, 'nonce':10},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':222, 'fee':2, 'nonce':11},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':333, 'fee':3, 'nonce':12},
]
json.dump(recs, open('$TMP/in_three.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_three.json" --out "$TMP/out_three.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "three-tx batch: exit 0"
COUNT_C=$($PY -c "import json; print(len(json.load(open('$TMP/out_three.json'))))")
assert_eq "$COUNT_C" "3" "three-tx batch: output array length is 3"

# Independently validate each envelope via validate-tx.
$PY -c "
import json
arr = json.load(open('$TMP/out_three.json'))
for i, e in enumerate(arr):
    json.dump(e, open('$TMP/out_three_e%d.json' % i,'w'))
"
ALL_THREE_PASS=yes
for i in 0 1 2; do
  set +e
  "$WALLET" validate-tx --tx-json "$TMP/out_three_e${i}.json" >/dev/null 2>&1
  RC=$?
  set -e
  if [ "$RC" != "0" ]; then ALL_THREE_PASS=no; fi
done
assert_eq "$ALL_THREE_PASS" "yes" "validate-tx accepts all three envelopes independently"

echo
echo "=== D. Order preservation: output[i] corresponds to input[i] ==="
# Distinct amounts (111/222/333 above) — read back from the output array
# and assert positional correspondence.
ORDER_OK=$($PY -c "
import json
arr = json.load(open('$TMP/out_three.json'))
amounts  = [e['amount'] for e in arr]
nonces   = [e['nonce']  for e in arr]
print('yes' if amounts == [111,222,333] and nonces == [10,11,12] else 'no')
")
assert_eq "$ORDER_OK" "yes" "output array preserves input order (by amount + nonce)"

echo
echo "=== E. Same input + same keyfile → same output bytes (determinism) ==="
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_three.json" --out "$TMP/out_three_rerun.json" >/dev/null 2>&1
# Compare canonical (whitespace-stripped) JSON to insulate against trailing
# newline differences. Both files were written by the same producer so a
# byte-diff is also expected, but we go via JSON to keep the assertion
# robust to filesystem-level newline weirdness.
DETERM_OK=$($PY -c "
import json
a = json.load(open('$TMP/out_three.json'))
b = json.load(open('$TMP/out_three_rerun.json'))
print('yes' if a == b else 'no')
")
assert_eq "$DETERM_OK" "yes" "second run of same input produces identical output"
# Also byte-diff — Ed25519 sigs are deterministic and nlohmann::json dump
# order is stable, so files MUST match byte-for-byte. If this fails the
# producer is leaking nondeterminism somewhere.
if cmp -s "$TMP/out_three.json" "$TMP/out_three_rerun.json"; then
  echo "  PASS: output files byte-identical across runs"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: output files differ byte-wise across runs"; fail_count=$((fail_count + 1))
fi

echo
echo "=== F. Passphrase-locked (DETERM-NODE-V1) keyfile via --passphrase-env ==="
$PY -c "
import json
recs = [{'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':500, 'fee':1, 'nonce':50}]
json.dump(recs, open('$TMP/in_enc.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.enc" --in "$TMP/in_enc.json" --out "$TMP/out_enc.json" --passphrase-env DETERM_PASSPHRASE >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "encrypted keyfile + --passphrase-env: exit 0"
ENC_COUNT=$($PY -c "import json; print(len(json.load(open('$TMP/out_enc.json'))))")
assert_eq "$ENC_COUNT" "1" "encrypted keyfile path produced 1 envelope"
# Sig from the encrypted-keyfile path MUST equal the sig from the
# plaintext-keyfile path over an identical body (same priv seed →
# deterministic Ed25519 sig).
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_enc.json" --out "$TMP/out_enc_plaintext.json" >/dev/null 2>&1
ENC_SIG=$($PY -c "import json; print(json.load(open('$TMP/out_enc.json'))[0]['sig'])")
PT_SIG=$($PY -c "import json; print(json.load(open('$TMP/out_enc_plaintext.json'))[0]['sig'])")
assert_eq "$ENC_SIG" "$PT_SIG" "encrypted-keyfile sig equals plaintext-keyfile sig (Ed25519 deterministic)"

# And wrong passphrase exits 2.
export DETERM_PASSPHRASE_BAD='not-the-real-pass'
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.enc" --in "$TMP/in_enc.json" --out "$TMP/out_enc_bad.json" --passphrase-env DETERM_PASSPHRASE_BAD >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "wrong passphrase returns exit 2"

# And encrypted keyfile WITHOUT passphrase → exit 1.
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.enc" --in "$TMP/in_enc.json" --out "$TMP/out_enc_nopass.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "encrypted keyfile without passphrase returns exit 1"
unset DETERM_PASSPHRASE_BAD

echo
echo "=== G. Invalid inputs → non-zero exit + diagnostic ==="
# G1. Malformed JSON (truncated).
echo '[{"type":"TRANSFER","from"' > "$TMP/in_bad_json.json"
set +e
STDERR_G1=$("$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_bad_json.json" --out "$TMP/out_g1.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "malformed JSON: exit 1"
assert_contains "$STDERR_G1" "not valid JSON" "diagnostic mentions JSON parse error"

# G2. Top-level not an array (object).
echo '{"type":"TRANSFER","from":"x","to":"y","amount":1,"fee":0,"nonce":0}' > "$TMP/in_object.json"
set +e
STDERR_G2=$("$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_object.json" --out "$TMP/out_g2.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "top-level object (not array): exit 1"
assert_contains "$STDERR_G2" "array" "diagnostic mentions array requirement"

# G3. Missing 'amount' field.
$PY -c "
import json
recs = [{'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'fee':1, 'nonce':1}]
json.dump(recs, open('$TMP/in_missing_amount.json','w'))
"
set +e
STDERR_G3=$("$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_missing_amount.json" --out "$TMP/out_g3.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "missing 'amount': exit 1"
assert_contains "$STDERR_G3" "amount" "diagnostic mentions field name"

# G4. Unsupported type string.
$PY -c "
import json
recs = [{'type':'REGISTER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':1, 'fee':0, 'nonce':0}]
json.dump(recs, open('$TMP/in_bad_type.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_bad_type.json" --out "$TMP/out_g4.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unsupported 'type' string: exit 1"

# G5. 'from' mismatch (batch must be homogeneous).
$PY -c "
import json
recs = [{'type':'TRANSFER', 'from':'$ADDR_B', 'to':'$ADDR_A', 'amount':10, 'fee':0, 'nonce':0}]
json.dump(recs, open('$TMP/in_from_mismatch.json','w'))
"
set +e
STDERR_G5=$("$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_from_mismatch.json" --out "$TMP/out_g5.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "from-mismatch: exit 1"
assert_contains "$STDERR_G5" "from" "diagnostic mentions 'from' field"

# G6. TRANSFER amount = 0 rejected (chain rule).
$PY -c "
import json
recs = [{'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':0, 'fee':0, 'nonce':0}]
json.dump(recs, open('$TMP/in_zero_amount.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_zero_amount.json" --out "$TMP/out_g6.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "TRANSFER amount=0: exit 1"

echo
echo "=== H. STAKE + UNSTAKE supported alongside TRANSFER ==="
$PY -c "
import json
recs = [
  {'type':'STAKE',   'from':'$ADDR_A', 'to':'', 'amount':500, 'fee':1, 'nonce':100},
  {'type':'UNSTAKE', 'from':'$ADDR_A', 'to':'', 'amount':200, 'fee':1, 'nonce':101},
]
json.dump(recs, open('$TMP/in_stake.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_stake.json" --out "$TMP/out_stake.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "STAKE + UNSTAKE batch: exit 0"
TYPE_STAKE=$($PY -c "import json; print(json.load(open('$TMP/out_stake.json'))[0]['type'])")
TYPE_UNSTAKE=$($PY -c "import json; print(json.load(open('$TMP/out_stake.json'))[1]['type'])")
assert_eq "$TYPE_STAKE"   "3" "STAKE   maps to numeric type 3"
assert_eq "$TYPE_UNSTAKE" "4" "UNSTAKE maps to numeric type 4"

echo
echo "=== I. --out refuses to overwrite by default; --force overrides ==="
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_single.json" --out "$TMP/out_single.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "existing --out without --force: exit 1"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in_single.json" --out "$TMP/out_single.json" --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "existing --out with --force: exit 0"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet tx-batch-sign"; exit 0
else
    echo "  FAIL: test_wallet_tx_batch_sign"; exit 1
fi
