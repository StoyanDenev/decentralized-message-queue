#!/usr/bin/env bash
# determ-wallet tx-batch-summary CLI test (F2 R40).
#
# tx-batch-summary is the READ-ONLY aggregate-analytics companion to the
# batch-payroll flow:
#
#   batch-nonce-assign -> tx-batch-sign -> verify-batch -> tx-batch-summary
#
# Before broadcasting a 50k-tx payroll batch, an operator wants a
# one-glance sanity summary ("1000 TRANSFERs totaling 5,000,000 + 1,000 in
# fees, 1 distinct sender, 1000 distinct recipients, nonces 7..1006") to
# catch a wrong grand total, duplicate recipients, or a nonce gap. This
# command computes that summary over a JSON array of tx records — SIGNED
# envelopes ({type:int,...,sig}) or UNSIGNED inputs ({type:"TRANSFER",...})
# interchangeably. No keys, no signing, no Ed25519 verify, no daemon.
#
# Assertions exercised (covers the eight required spec items + surface):
#   1. Empty array -> all-zero counts, exit 0.
#   2. 3 TRANSFERs (100/200/300, fees 1/1/1) -> count=3, total_amount=600,
#      total_fee=3, per-type TRANSFER=3.
#   3. Mixed types (TRANSFER + STAKE + UNSTAKE) -> correct per-type
#      breakdown.
#   4. Distinct senders/recipients counted correctly (all from one sender
#      -> distinct_from=1; N distinct recipients -> distinct_to=N).
#   5. Nonce range + gap/duplicate detection: {7,8,9} -> 7..9 contiguous;
#      {7,9} -> gap (contiguous=false); {7,7,8} -> duplicate (false).
#   6. --json output parses with the documented fields.
#   7. Malformed input (non-array / non-object element / bad JSON) -> clean
#      non-zero exit + diagnostic.
#   8. Composes: feed a tx-batch-sign output array (signed envelopes, type
#      as int) into tx-batch-summary -> summary reflects assigned nonces.
#
# Plus surface gates:
#   - Global help mentions tx-batch-summary.
#   - tx-batch-summary --help exits 0.
#   - Missing required --in rejected.
#   - --in `-` reads from stdin.
#   - records_missing_fields counts (not aborts) a row missing a required
#     field.
#   - int-form `type` (signed-envelope shape) accepted alongside mnemonics.
#
# Run from repo root: bash tools/test_wallet_tx_batch_summary.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_tx_batch_summary.$$"
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

# Small helper: read a top-level scalar field out of a --json summary.
jget() { $PY -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
# Read a nested per_type field.
jptype() { $PY -c "import json,sys; print(json.load(open(sys.argv[1]))['per_type'][sys.argv[2]])" "$1" "$2"; }

echo "=== 0a. Global help mentions tx-batch-summary ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "tx-batch-summary"; then
  echo "  PASS: help mentions tx-batch-summary"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing tx-batch-summary"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 0b. tx-batch-summary --help exits 0 ==="
set +e
"$WALLET" tx-batch-summary --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-batch-summary --help exits 0"

echo
echo "=== 0c. Missing required --in rejected ==="
set +e
"$WALLET" tx-batch-summary >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no args returns 1"

echo
echo "=== 1. Empty array -> zero counts, exit 0 ==="
echo "[]" > "$TMP/empty.json"
set +e
"$WALLET" tx-batch-summary --in "$TMP/empty.json" --json > "$TMP/empty_out.json" 2>/dev/null
RC=$?
set -e
assert_eq "$RC" "0" "empty array: exit 0"
assert_eq "$(jget "$TMP/empty_out.json" total_records)"          "0" "empty: total_records=0"
assert_eq "$(jget "$TMP/empty_out.json" counted_records)"        "0" "empty: counted_records=0"
assert_eq "$(jget "$TMP/empty_out.json" total_amount)"           "0" "empty: total_amount=0"
assert_eq "$(jget "$TMP/empty_out.json" total_fee)"              "0" "empty: total_fee=0"
assert_eq "$(jget "$TMP/empty_out.json" distinct_from)"          "0" "empty: distinct_from=0"
assert_eq "$(jget "$TMP/empty_out.json" distinct_to)"            "0" "empty: distinct_to=0"
# nonce_min/max/contiguous are null on empty.
assert_eq "$(jget "$TMP/empty_out.json" nonce_contiguous)"       "None" "empty: nonce_contiguous=null"

echo
echo "=== 2. 3 TRANSFERs (100/200/300, fees 1/1/1) -> totals + per-type ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xb1','amount':100,'fee':1,'nonce':7},
  {'type':'TRANSFER','from':'0xaa','to':'0xb2','amount':200,'fee':1,'nonce':8},
  {'type':'TRANSFER','from':'0xaa','to':'0xb3','amount':300,'fee':1,'nonce':9},
]
json.dump(recs, open('$TMP/three.json','w'))
"
set +e
"$WALLET" tx-batch-summary --in "$TMP/three.json" --json > "$TMP/three_out.json" 2>/dev/null
RC=$?
set -e
assert_eq "$RC" "0" "three TRANSFERs: exit 0"
assert_eq "$(jget "$TMP/three_out.json" counted_records)" "3"   "three: count=3"
assert_eq "$(jget "$TMP/three_out.json" total_amount)"    "600" "three: total_amount=600"
assert_eq "$(jget "$TMP/three_out.json" total_fee)"       "3"   "three: total_fee=3"
assert_eq "$(jptype "$TMP/three_out.json" TRANSFER)"      "3"   "three: per_type.TRANSFER=3"
assert_eq "$(jptype "$TMP/three_out.json" STAKE)"         "0"   "three: per_type.STAKE=0"

echo
echo "=== 3. Mixed types (TRANSFER + STAKE + UNSTAKE) -> per-type breakdown ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xbb','amount':100,'fee':1,'nonce':1},
  {'type':'STAKE',   'from':'0xaa','to':'',    'amount':500,'fee':2,'nonce':2},
  {'type':'STAKE',   'from':'0xaa','to':'',    'amount':500,'fee':2,'nonce':3},
  {'type':'UNSTAKE', 'from':'0xaa','to':'',    'amount':200,'fee':0,'nonce':4},
]
json.dump(recs, open('$TMP/mixed.json','w'))
"
"$WALLET" tx-batch-summary --in "$TMP/mixed.json" --json > "$TMP/mixed_out.json" 2>/dev/null
assert_eq "$(jptype "$TMP/mixed_out.json" TRANSFER)" "1" "mixed: TRANSFER=1"
assert_eq "$(jptype "$TMP/mixed_out.json" STAKE)"    "2" "mixed: STAKE=2"
assert_eq "$(jptype "$TMP/mixed_out.json" UNSTAKE)"  "1" "mixed: UNSTAKE=1"
assert_eq "$(jptype "$TMP/mixed_out.json" other)"    "0" "mixed: other=0"
assert_eq "$(jget  "$TMP/mixed_out.json" total_amount)" "1300" "mixed: total_amount=1300"

echo
echo "=== 3b. Non-TRANSFER/STAKE/UNSTAKE type folds into 'other' ==="
$PY -c "
import json
# REGISTER=1, DAPP_CALL=10 — neither is a payroll type, both fold to other.
recs = [
  {'type':1,  'from':'0xaa','to':'0xbb','amount':0,'fee':0,'nonce':1},
  {'type':10, 'from':'0xaa','to':'0xcc','amount':0,'fee':0,'nonce':2},
]
json.dump(recs, open('$TMP/other.json','w'))
"
"$WALLET" tx-batch-summary --in "$TMP/other.json" --json > "$TMP/other_out.json" 2>/dev/null
assert_eq "$(jptype "$TMP/other_out.json" other)" "2" "other: other=2"
OTHER_TYPES=$($PY -c "import json; d=json.load(open('$TMP/other_out.json')); print(sorted(t['type'] for t in d['other_types']))")
assert_eq "$OTHER_TYPES" "[1, 10]" "other: other_types lists raw ints [1, 10]"

echo
echo "=== 4. Distinct senders / recipients ==="
# One sender, three distinct recipients (reuse the three-TRANSFER batch).
assert_eq "$(jget "$TMP/three_out.json" distinct_from)" "1" "distinct_from=1 (single sender)"
assert_eq "$(jget "$TMP/three_out.json" distinct_to)"   "3" "distinct_to=3 (three recipients)"
# Duplicate recipient collapses the distinct_to count (the fat-finger this
# command is meant to surface).
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xDUP','amount':1,'fee':0,'nonce':1},
  {'type':'TRANSFER','from':'0xaa','to':'0xDUP','amount':1,'fee':0,'nonce':2},
  {'type':'TRANSFER','from':'0xaa','to':'0xUNIQ','amount':1,'fee':0,'nonce':3},
]
json.dump(recs, open('$TMP/duprecip.json','w'))
"
"$WALLET" tx-batch-summary --in "$TMP/duprecip.json" --json > "$TMP/duprecip_out.json" 2>/dev/null
assert_eq "$(jget "$TMP/duprecip_out.json" counted_records)" "3" "dup-recip: counted=3"
assert_eq "$(jget "$TMP/duprecip_out.json" distinct_to)"     "2" "dup-recip: distinct_to=2 (duplicate collapsed)"

echo
echo "=== 5. Nonce range + gap/duplicate detection ==="
# Contiguous {7,8,9}.
assert_eq "$(jget "$TMP/three_out.json" nonce_min)"        "7"    "nonces {7,8,9}: min=7"
assert_eq "$(jget "$TMP/three_out.json" nonce_max)"        "9"    "nonces {7,8,9}: max=9"
assert_eq "$(jget "$TMP/three_out.json" nonce_contiguous)" "True" "nonces {7,8,9}: contiguous=true"
# Gap {7,9}.
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xb1','amount':1,'fee':0,'nonce':7},
  {'type':'TRANSFER','from':'0xaa','to':'0xb2','amount':1,'fee':0,'nonce':9},
]
json.dump(recs, open('$TMP/gap.json','w'))
"
"$WALLET" tx-batch-summary --in "$TMP/gap.json" --json > "$TMP/gap_out.json" 2>/dev/null
assert_eq "$(jget "$TMP/gap_out.json" nonce_min)"        "7"     "nonces {7,9}: min=7"
assert_eq "$(jget "$TMP/gap_out.json" nonce_max)"        "9"     "nonces {7,9}: max=9"
assert_eq "$(jget "$TMP/gap_out.json" nonce_contiguous)" "False" "nonces {7,9}: contiguous=false (gap)"
# Duplicate {7,7,8} — set-collapse would mask this; nonce_dup_seen catches it.
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xb1','amount':1,'fee':0,'nonce':7},
  {'type':'TRANSFER','from':'0xaa','to':'0xb2','amount':1,'fee':0,'nonce':7},
  {'type':'TRANSFER','from':'0xaa','to':'0xb3','amount':1,'fee':0,'nonce':8},
]
json.dump(recs, open('$TMP/dupnonce.json','w'))
"
"$WALLET" tx-batch-summary --in "$TMP/dupnonce.json" --json > "$TMP/dupnonce_out.json" 2>/dev/null
assert_eq "$(jget "$TMP/dupnonce_out.json" nonce_contiguous)" "False" "nonces {7,7,8}: contiguous=false (duplicate)"
# Human-readable output flags the gap inline.
HUMAN_GAP=$("$WALLET" tx-batch-summary --in "$TMP/gap.json" 2>/dev/null | tr -d '\r')
assert_contains "$HUMAN_GAP" "7..9"            "human: nonce_range shows 7..9"
assert_contains "$HUMAN_GAP" "gap or duplicate" "human: gap is flagged inline"

echo
echo "=== 6. --json output parses + carries every documented field ==="
FIELDS_OK=$($PY -c "
import json
d = json.load(open('$TMP/mixed_out.json'))
req = ['total_records','counted_records','records_missing_fields','per_type',
       'other_types','total_amount','total_fee','distinct_from','distinct_to',
       'nonce_min','nonce_max','nonce_contiguous']
pt  = ['TRANSFER','STAKE','UNSTAKE','other']
ok = all(k in d for k in req) and all(k in d['per_type'] for k in pt)
print('yes' if ok else 'no')
")
assert_eq "$FIELDS_OK" "yes" "--json carries all documented top-level + per_type fields"

echo
echo "=== 7. Malformed input -> clean non-zero exit + diagnostic ==="
# 7a. Top-level object (not array).
echo '{"type":0,"from":"0xaa","to":"0xbb","amount":1,"fee":0,"nonce":1}' > "$TMP/obj.json"
set +e
ERR_7A=$("$WALLET" tx-batch-summary --in "$TMP/obj.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "top-level object: exit 1"
assert_contains "$ERR_7A" "array" "diagnostic mentions array requirement"
# 7b. Non-object array element.
echo '[123]' > "$TMP/badel.json"
set +e
ERR_7B=$("$WALLET" tx-batch-summary --in "$TMP/badel.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "non-object element: exit 1"
assert_contains "$ERR_7B" "not a JSON object" "diagnostic mentions non-object element"
# 7c. Malformed JSON (truncated).
echo '[{"type":0' > "$TMP/badjson.json"
set +e
ERR_7C=$("$WALLET" tx-batch-summary --in "$TMP/badjson.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "malformed JSON: exit 1"
assert_contains "$ERR_7C" "not valid JSON" "diagnostic mentions JSON parse error"
# 7d. Unreadable --in (nonexistent path).
set +e
ERR_7D=$("$WALLET" tx-batch-summary --in "$TMP/does_not_exist.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent --in: exit 1"
assert_contains "$ERR_7D" "cannot open" "diagnostic mentions open failure"

echo
echo "=== 7e. Record missing a required field is counted, not fatal ==="
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'0xaa','to':'0xb1','amount':100,'fee':1,'nonce':1},
  {'type':'TRANSFER','from':'0xaa','to':'0xb2','fee':1,'nonce':2},   # no amount
]
json.dump(recs, open('$TMP/miss.json','w'))
"
set +e
"$WALLET" tx-batch-summary --in "$TMP/miss.json" --json > "$TMP/miss_out.json" 2>/dev/null
RC=$?
set -e
assert_eq "$RC" "0" "missing-field row: exit 0 (tolerated)"
assert_eq "$(jget "$TMP/miss_out.json" total_records)"          "2" "missing-field: total_records=2"
assert_eq "$(jget "$TMP/miss_out.json" counted_records)"        "1" "missing-field: counted_records=1"
assert_eq "$(jget "$TMP/miss_out.json" records_missing_fields)" "1" "missing-field: records_missing_fields=1"
# Aggregates reflect ONLY the well-formed record.
assert_eq "$(jget "$TMP/miss_out.json" total_amount)" "100" "missing-field: total_amount excludes bad row"

echo
echo '=== 8. --in - reads from stdin ==='
set +e
STDIN_OUT=$(echo '[{"type":"TRANSFER","from":"0xaa","to":"0xbb","amount":42,"fee":1,"nonce":1}]' | "$WALLET" tx-batch-summary --in - --json 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "0" "stdin (--in -): exit 0"
STDIN_AMT=$(echo "$STDIN_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['total_amount'])")
assert_eq "$STDIN_AMT" "42" "stdin: total_amount=42"

echo
echo "=== 9. Composes with tx-batch-sign output (signed envelopes) ==="
# This is the batch-payroll-flow compose gate: sign a batch, then summarize
# the SIGNED output array (type as int 0, plus sig/hash fields the summary
# ignores). The summary must reflect the assigned nonces end-to-end.
"$WALLET" account-create-batch --count 1 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])" "$TMP/keys.json")
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a.json"
# Build a homogeneous 3-tx input with nonces 7/8/9 (mirrors the use-case).
$PY -c "
import json
recs = [
  {'type':'TRANSFER','from':'$ADDR_A','to':'0xb1','amount':100,'fee':1,'nonce':7},
  {'type':'TRANSFER','from':'$ADDR_A','to':'0xb2','amount':200,'fee':1,'nonce':8},
  {'type':'TRANSFER','from':'$ADDR_A','to':'0xb3','amount':300,'fee':1,'nonce':9},
]
json.dump(recs, open('$TMP/payroll_in.json','w'))
"
set +e
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/payroll_in.json" --out "$TMP/payroll_signed.json" >/dev/null 2>&1
SIGN_RC=$?
set -e
if [ "$SIGN_RC" != "0" ]; then
  echo "  SETUP-FAIL: tx-batch-sign did not produce signed output (rc=$SIGN_RC)"
  fail_count=$((fail_count + 1))
else
  # Confirm the signed array really does carry int types + sig (so we're
  # genuinely exercising the signed-envelope code path).
  SIGNED_TYPE=$($PY -c "import json; print(json.load(open('$TMP/payroll_signed.json'))[0]['type'])")
  assert_eq "$SIGNED_TYPE" "0" "signed envelope type is int 0 (post-sign shape)"
  "$WALLET" tx-batch-summary --in "$TMP/payroll_signed.json" --json > "$TMP/payroll_summary.json" 2>/dev/null
  assert_eq "$(jget "$TMP/payroll_summary.json" counted_records)"  "3"    "compose: counted=3"
  assert_eq "$(jget "$TMP/payroll_summary.json" total_amount)"     "600"  "compose: total_amount=600"
  assert_eq "$(jget "$TMP/payroll_summary.json" total_fee)"        "3"    "compose: total_fee=3"
  assert_eq "$(jptype "$TMP/payroll_summary.json" TRANSFER)"       "3"    "compose: per_type.TRANSFER=3 (int types resolved)"
  assert_eq "$(jget "$TMP/payroll_summary.json" distinct_from)"    "1"    "compose: distinct_from=1"
  assert_eq "$(jget "$TMP/payroll_summary.json" distinct_to)"      "3"    "compose: distinct_to=3"
  assert_eq "$(jget "$TMP/payroll_summary.json" nonce_min)"        "7"    "compose: nonce_min=7 (assigned nonces reflected)"
  assert_eq "$(jget "$TMP/payroll_summary.json" nonce_max)"        "9"    "compose: nonce_max=9"
  assert_eq "$(jget "$TMP/payroll_summary.json" nonce_contiguous)" "True" "compose: nonce_contiguous=true"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet tx-batch-summary"; exit 0
else
    echo "  FAIL: test_wallet_tx_batch_summary"; exit 1
fi
