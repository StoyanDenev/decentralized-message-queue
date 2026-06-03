#!/usr/bin/env bash
# determ-wallet batch-nonce-assign CLI test (E2 R40).
#
# batch-nonce-assign is the PREP step before tx-batch-sign in the payroll /
# airdrop batch flow. tx-batch-sign signs a batch but does NOT assign
# nonces; this command stamps each record with a distinct sequential
# nonce (start, start+1, ...) so the operator doesn't hand-edit N records.
# It is a PURE DATA TRANSFORM — no keyfile, no signing, no crypto.
#
# Compose chain:
#   determ account nonce ...            (fetch current on-chain nonce)
#   determ-wallet batch-nonce-assign --start <n> ...
#   determ-wallet tx-batch-sign ...     (sign the nonce-assigned array)
#   determ-wallet validate-tx ...       (verify the sigs)
#
# Per-record input shape (unsigned tx records — same as tx-batch-sign --in):
#   {"type":"TRANSFER"|"STAKE"|"UNSTAKE", from, to, amount, fee[, nonce]}
# Per-record output shape: identical to input but with nonce = start + i.
#
# Required spec assertions (>=6) exercised by this wrapper:
#   1. Empty array → empty output, exit 0.
#   2. 3-record array with --start 7 → nonces 7,8,9 in order; other fields
#      untouched.
#   3. Records with pre-existing nonce fields → overwritten sequentially.
#   4. Output composes: pipe the assigned array into tx-batch-sign (test
#      keyfile) → 3 signed envelopes whose nonces are 7,8,9 and whose sigs
#      validate via validate-tx. (No daemon needed — wallet binary only.)
#   5. Determinism: same input + same --start → byte-identical output.
#   6. --out exists without --force → refuse (non-zero); with --force →
#      overwrite.
#   7. Invalid input (non-array, negative --start, non-object element) →
#      clean non-zero exit with diagnostic.
#
# Plus surface gates:
#   - Global help mentions batch-nonce-assign.
#   - batch-nonce-assign --help exits 0.
#   - Missing required flags rejected.
#
# Run from repo root: bash tools/test_wallet_batch_nonce_assign.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_batch_nonce_assign.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# Generate two fresh keypairs (account A signs; B is a recipient).
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])" "$TMP/keys.json")
ADDR_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['address'])" "$TMP/keys.json")

# Plaintext keyfile (canonical wallet shape) for the compose-with-tx-batch-
# sign assertion.
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a.json"

echo "=== Surface 1. Global help mentions batch-nonce-assign ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "batch-nonce-assign"; then
  echo "  PASS: help mentions batch-nonce-assign"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing batch-nonce-assign"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Surface 2. batch-nonce-assign --help exits 0 ==="
set +e
"$WALLET" batch-nonce-assign --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "batch-nonce-assign --help exits 0"

echo
echo "=== Surface 3. Missing required flags rejected ==="
set +e
"$WALLET" batch-nonce-assign >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no args returns 1"
# --in + --out but no --start.
$PY -c "import json; json.dump([], open('$TMP/in_e.json','w'))"
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_e.json" --out "$TMP/out_nostart.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --start returns 1"

echo
echo "=== 1. Empty array → empty output, exit 0 ==="
echo "[]" > "$TMP/in_empty.json"
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_empty.json" --start 0 --out "$TMP/out_empty.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "empty input: exit 0"
COUNT_1=$($PY -c "import json; print(len(json.load(open('$TMP/out_empty.json'))))")
assert_eq "$COUNT_1" "0" "empty input: output array length is 0"
SHAPE_1=$($PY -c "import json; d=json.load(open('$TMP/out_empty.json')); print('array' if isinstance(d, list) else type(d).__name__)")
assert_eq "$SHAPE_1" "array" "empty input: output is still a JSON array"

echo
echo "=== 2. 3-record array --start 7 → nonces 7,8,9; other fields untouched ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':111, 'fee':1},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':222, 'fee':2},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':333, 'fee':3},
]
json.dump(recs, open('$TMP/in_three.json','w'))
"
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 7 --out "$TMP/out_three.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "three-record --start 7: exit 0"
NONCES_2=$($PY -c "import json; print(','.join(str(e['nonce']) for e in json.load(open('$TMP/out_three.json'))))")
assert_eq "$NONCES_2" "7,8,9" "nonces are 7,8,9 in input order"
# Other fields untouched: amounts + fees + type + from + to unchanged.
UNTOUCHED_2=$($PY -c "
import json
out = json.load(open('$TMP/out_three.json'))
amounts = [e['amount'] for e in out]
fees    = [e['fee']    for e in out]
types   = [e['type']   for e in out]
froms   = {e['from']   for e in out}
tos     = {e['to']     for e in out}
ok = (amounts == [111,222,333] and fees == [1,2,3]
      and types == ['TRANSFER','TRANSFER','TRANSFER']
      and froms == {'$ADDR_A'} and tos == {'$ADDR_B'})
print('yes' if ok else 'no')
")
assert_eq "$UNTOUCHED_2" "yes" "all non-nonce fields preserved verbatim"

echo
echo "=== 3. Pre-existing nonce fields overwritten sequentially ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':10, 'fee':0, 'nonce':9999},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':20, 'fee':0, 'nonce':5555},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':30, 'fee':0, 'nonce':1},
]
json.dump(recs, open('$TMP/in_preexist.json','w'))
"
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_preexist.json" --start 100 --out "$TMP/out_preexist.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "pre-existing nonces, --start 100: exit 0"
NONCES_3=$($PY -c "import json; print(','.join(str(e['nonce']) for e in json.load(open('$TMP/out_preexist.json'))))")
assert_eq "$NONCES_3" "100,101,102" "pre-existing nonces overwritten with 100,101,102"

echo
echo "=== 4. Output composes: tx-batch-sign → 3 envelopes nonce 7,8,9; sigs validate ==="
# Feed the --start 7 assigned array (out_three.json) straight into
# tx-batch-sign. No daemon — the wallet binary signs offline.
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/out_three.json" --out "$TMP/signed_three.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-batch-sign accepts the nonce-assigned array: exit 0"
SIGNED_COUNT=$($PY -c "import json; print(len(json.load(open('$TMP/signed_three.json'))))")
assert_eq "$SIGNED_COUNT" "3" "tx-batch-sign emitted 3 signed envelopes"
SIGNED_NONCES=$($PY -c "import json; print(','.join(str(e['nonce']) for e in json.load(open('$TMP/signed_three.json'))))")
assert_eq "$SIGNED_NONCES" "7,8,9" "signed envelopes carry nonces 7,8,9"
# Split each signed envelope out + validate via validate-tx (independent
# verification through the chain's canonical signing_bytes scheme).
$PY -c "
import json
arr = json.load(open('$TMP/signed_three.json'))
for i, e in enumerate(arr):
    json.dump(e, open('$TMP/signed_e%d.json' % i,'w'))
"
ALL_VALID=yes
for i in 0 1 2; do
  set +e
  "$WALLET" validate-tx --tx-json "$TMP/signed_e${i}.json" >/dev/null 2>&1
  RC=$?
  set -e
  if [ "$RC" != "0" ]; then ALL_VALID=no; fi
done
assert_eq "$ALL_VALID" "yes" "validate-tx accepts all 3 signed envelopes (sigs valid)"

echo
echo "=== 5. Determinism: same input + same --start → byte-identical output ==="
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 7 --out "$TMP/out_three_rerun.json" >/dev/null 2>&1
DETERM_OK=$($PY -c "
import json
a = json.load(open('$TMP/out_three.json'))
b = json.load(open('$TMP/out_three_rerun.json'))
print('yes' if a == b else 'no')
")
assert_eq "$DETERM_OK" "yes" "second run of same input produces identical JSON"
if cmp -s "$TMP/out_three.json" "$TMP/out_three_rerun.json"; then
  echo "  PASS: output files byte-identical across runs"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: output files differ byte-wise across runs"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 6. --out refuses to overwrite by default; --force overrides ==="
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 7 --out "$TMP/out_three.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "existing --out without --force: exit 1"
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 7 --out "$TMP/out_three.json" --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "existing --out with --force: exit 0"

echo
echo "=== 7. Invalid inputs → clean non-zero exit + diagnostic ==="
# 7a. Non-array (top-level object).
echo '{"type":"TRANSFER","from":"x","to":"y","amount":1,"fee":0}' > "$TMP/in_object.json"
set +e
STDERR_7A=$("$WALLET" batch-nonce-assign --in "$TMP/in_object.json" --start 0 --out "$TMP/out_7a.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "non-array input: exit 1"
assert_contains "$STDERR_7A" "array" "diagnostic mentions array requirement"

# 7b. Negative --start.
set +e
STDERR_7B=$("$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start -1 --out "$TMP/out_7b.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "negative --start: exit 1"
assert_contains "$STDERR_7B" "non-negative" "diagnostic mentions non-negative requirement"

# 7c. Non-object element.
echo '[42, {"type":"TRANSFER"}]' > "$TMP/in_scalar_elem.json"
set +e
STDERR_7C=$("$WALLET" batch-nonce-assign --in "$TMP/in_scalar_elem.json" --start 0 --out "$TMP/out_7c.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "non-object element: exit 1"
assert_contains "$STDERR_7C" "object" "diagnostic mentions object requirement"

# 7d. Malformed JSON.
echo '[{"type":"TRANSFER"' > "$TMP/in_bad_json.json"
set +e
STDERR_7D=$("$WALLET" batch-nonce-assign --in "$TMP/in_bad_json.json" --start 0 --out "$TMP/out_7d.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "malformed JSON: exit 1"
assert_contains "$STDERR_7D" "not valid JSON" "diagnostic mentions JSON parse error"

# 7e. Non-numeric --start (trailing junk).
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 12abc --out "$TMP/out_7e.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "non-numeric --start (12abc): exit 1"

echo
echo "=== 8. --start 0 boundary → nonces 0,1,2 ==="
set +e
"$WALLET" batch-nonce-assign --in "$TMP/in_three.json" --start 0 --out "$TMP/out_zero.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--start 0: exit 0"
NONCES_8=$($PY -c "import json; print(','.join(str(e['nonce']) for e in json.load(open('$TMP/out_zero.json'))))")
assert_eq "$NONCES_8" "0,1,2" "--start 0 yields nonces 0,1,2"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet batch-nonce-assign"; exit 0
else
    echo "  FAIL"; exit 1
fi
