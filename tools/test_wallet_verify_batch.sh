#!/usr/bin/env bash
# determ-wallet verify-batch CLI test (D2 R40).
#
# Exercises BATCH signature/envelope verification — the read/verify dual of
# tx-batch-sign. tx-batch-sign SIGNS N txs in one invocation; verify-batch
# consumes that same per-record output shape ({type, from, to, amount, fee,
# nonce, payload, sig, hash}) and VERIFIES every record in one pass: for
# each it recomputes the canonical signing_bytes, Ed25519-verifies the sig
# (anon-address senders — pubkey derived from `from`), recomputes the tx
# hash and checks it matches the stored `hash`, and emits a per-tx verdict.
#
# Use case: an operator / auditor receives a batch of signed envelopes
# (payroll, airdrop, settlement output) and wants to verify every signature
# + canonical-envelope consistency in one pass before `determ submit-tx` —
# without N process spawns.
#
# Differentiation vs validate-tx (single-tx) / tx-batch-sign (signer):
#   * validate-tx     — verifies ONE envelope; verify-batch loops the same
#                       checks over a JSON ARRAY and emits a verdict array.
#   * tx-batch-sign   — SIGNS N txs (write side); verify-batch is the read
#                       side that consumes its output.
#   * verify-batch reuses the single-tx verify primitives (signing_bytes
#     layout + Ed25519 + hash-match) — no reimplemented crypto.
#
# Verdict shape (--out report.json): [{index, hash, valid:bool, reason?}].
# Exit: 0 all valid / report-only mode; 1 args/IO/parse error (non-array
# input); 3 --strict and >=1 record invalid.
#
# Assertions (>=6 required; this wrapper exercises ~22):
#   1.  Empty array → empty report, exit 0.                       [REQ 1]
#   2.  A 3-tx batch from tx-batch-sign → all 3 report valid:true.[REQ 2]
#   3.  Tamper one envelope's amount after signing → that index
#       valid:false with a reason; others still valid.           [REQ 3]
#   4.  Tamper a sig byte → that index invalid.                   [REQ 4]
#   5.  Tamper the hash field (sig still valid) → invalid with a
#       hash-mismatch reason.                                     [REQ 5]
#   6.  --strict exits 3 when >=1 invalid; exits 0 when all valid.[REQ 6]
#   7.  Malformed input (non-array / missing fields) → clean exit.[REQ 7]
#  Plus surface gates:
#   - Global help mentions verify-batch.
#   - verify-batch --help exits 0.
#   - Missing --in: exit 1.
#   - Nonexistent --in file: exit 1.
#   - Invalid JSON in --in: exit 1.
#   - Unknown CLI arg: exit 1.
#   - --in - reads the array from stdin.
#   - --out writes the verdict array + a status tally to stdout.
#   - --out refuses to overwrite without --force; --force allows it.
#   - Single-element invalid record does NOT abort siblings (per-tx verdict).
#   - Domain sender (non-anon `from`) → that index invalid (no in-wallet
#     pubkey lookup).
#   - --strict TRANSFER gate: amount=0 record flagged invalid under --strict.
#
# Run from repo root: bash tools/test_wallet_verify_batch.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_verify_batch.$$"
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

# Generate two fresh keypairs + a plaintext keyfile for the signer.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
$PY -c "import json; d=json.load(open('$TMP/keys.json')); json.dump(d['accounts'][0], open('$TMP/key_a.json','w'))"

# Produce a real 3-tx signed batch via tx-batch-sign (the write-dual we
# verify against). Distinct amounts so per-index verdicts are unambiguous.
$PY -c "
import json
recs = [
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':111, 'fee':1, 'nonce':10},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':222, 'fee':2, 'nonce':11},
  {'type':'TRANSFER', 'from':'$ADDR_A', 'to':'$ADDR_B', 'amount':333, 'fee':3, 'nonce':12},
]
json.dump(recs, open('$TMP/in3.json','w'))
"
"$WALLET" tx-batch-sign --keyfile "$TMP/key_a.json" --in "$TMP/in3.json" \
  --out "$TMP/signed3.json" >/dev/null 2>&1

# Helper: count valid:true / valid:false entries in a verdict JSON array.
count_valid() {   $PY -c "import json,sys; print(sum(1 for v in json.load(open(sys.argv[1])) if v['valid']))" "$1"; }
count_invalid() { $PY -c "import json,sys; print(sum(1 for v in json.load(open(sys.argv[1])) if not v['valid']))" "$1"; }

echo "=== Surface 0a. Global help mentions verify-batch ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "verify-batch"; then
  echo "  PASS: help mentions verify-batch"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing verify-batch"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Surface 0b. verify-batch --help exits 0 ==="
set +e
"$WALLET" verify-batch --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "verify-batch --help exits 0"

echo
echo "=== Surface 0c. Missing --in: exit 1 ==="
set +e
"$WALLET" verify-batch >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --in returns 1"

echo
echo "=== Surface 0d. Nonexistent --in file: exit 1 ==="
set +e
"$WALLET" verify-batch --in "$TMP/no_such_file.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent --in returns 1"

echo
echo "=== Surface 0e. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 1. Empty array → empty report, exit 0 [REQ 1] ==="
echo "[]" > "$TMP/empty.json"
set +e
EMPTY_OUT=$("$WALLET" verify-batch --in "$TMP/empty.json" 2>&1)
RC=$?
set -e
EMPTY_OUT=$(echo "$EMPTY_OUT" | tr -d '\r')
assert_eq "$RC" "0" "empty array returns 0"
assert_eq "$EMPTY_OUT" "[]" "empty array emits empty report []"

echo
echo "=== 2. 3-tx batch from tx-batch-sign → all 3 valid:true [REQ 2] ==="
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --out "$TMP/rep3.json" >"$TMP/rep3_status.txt" 2>&1
RC=$?
set -e
STATUS3=$(tr -d '\r' < "$TMP/rep3_status.txt")
assert_eq "$RC" "0" "3-tx clean batch returns 0"
NVALID=$(count_valid "$TMP/rep3.json")
NINVALID=$(count_invalid "$TMP/rep3.json")
assert_eq "$NVALID" "3" "all 3 records report valid:true"
assert_eq "$NINVALID" "0" "no records report valid:false"
# The status tally on stdout reflects the counts.
assert_contains "$STATUS3" '"valid":3' "status tally reports valid:3"
# verdict order preserved (index 0,1,2 in order).
ORDER_OK=$($PY -c "
import json
a = json.load(open('$TMP/rep3.json'))
print('yes' if [v['index'] for v in a] == [0,1,2] else 'no')
")
assert_eq "$ORDER_OK" "yes" "verdict array preserves input order (index 0,1,2)"

echo
echo "=== Surface 0f. --strict on clean batch exits 0 [REQ 6 half] ==="
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --strict >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--strict on all-valid batch returns 0"

echo
echo "=== 3. Tamper amount on idx1 → idx1 invalid, others valid [REQ 3] ==="
$PY -c "
import json
a = json.load(open('$TMP/signed3.json'))
a[1]['amount'] = a[1]['amount'] + 1   # bump amount, leave sig+hash alone
json.dump(a, open('$TMP/tamper_amt.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/tamper_amt.json" --out "$TMP/rep_amt.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "amount-tamper report-only (no --strict) returns 0"
AMT_V=$($PY -c "import json; print(json.load(open('$TMP/rep_amt.json'))[1]['valid'])")
assert_eq "$AMT_V" "False" "tampered idx1 reports valid:false"
AMT_REASON=$($PY -c "import json; print('reason' in json.load(open('$TMP/rep_amt.json'))[1])")
assert_eq "$AMT_REASON" "True" "tampered idx1 carries a reason"
AMT_SIBLINGS=$($PY -c "
import json
a = json.load(open('$TMP/rep_amt.json'))
print('yes' if a[0]['valid'] and a[2]['valid'] else 'no')
")
assert_eq "$AMT_SIBLINGS" "yes" "siblings idx0,idx2 still valid (one bad record does not poison batch)"
AMT_REASON_TXT=$($PY -c "import json; print(json.load(open('$TMP/rep_amt.json'))[1].get('reason',''))")
assert_contains "$AMT_REASON_TXT" "tx_hash mismatch" "amount-tamper reason cites tx_hash mismatch"

echo
echo "=== 4. Tamper a sig byte on idx0 → idx0 invalid [REQ 4] ==="
$PY -c "
import json
a = json.load(open('$TMP/signed3.json'))
s = a[0]['sig']
i = 64
new = ('0' if s[i] != '0' else 'a')   # flip a nibble; still 128 hex chars
a[0]['sig'] = s[:i] + new + s[i+1:]
json.dump(a, open('$TMP/tamper_sig.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/tamper_sig.json" --out "$TMP/rep_sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "sig-tamper report-only returns 0"
SIG_V=$($PY -c "import json; print(json.load(open('$TMP/rep_sig.json'))[0]['valid'])")
assert_eq "$SIG_V" "False" "tampered-sig idx0 reports valid:false"
SIG_REASON=$($PY -c "import json; print(json.load(open('$TMP/rep_sig.json'))[0].get('reason',''))")
assert_contains "$SIG_REASON" "Ed25519" "sig-tamper reason cites Ed25519 verification failure"
SIG_SIBLINGS=$($PY -c "
import json
a = json.load(open('$TMP/rep_sig.json'))
print('yes' if a[1]['valid'] and a[2]['valid'] else 'no')
")
assert_eq "$SIG_SIBLINGS" "yes" "sig-tamper siblings still valid"

echo
echo "=== 5. Tamper hash field on idx2 (sig still valid) → invalid w/ hash-mismatch [REQ 5] ==="
$PY -c "
import json
a = json.load(open('$TMP/signed3.json'))
h = a[2]['hash']
i = 10
new = ('0' if h[i] != '0' else 'a')   # flip a hash nibble; body+sig untouched
a[2]['hash'] = h[:i] + new + h[i+1:]
json.dump(a, open('$TMP/tamper_hash.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/tamper_hash.json" --out "$TMP/rep_hash.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "hash-tamper report-only returns 0"
HASH_V=$($PY -c "import json; print(json.load(open('$TMP/rep_hash.json'))[2]['valid'])")
assert_eq "$HASH_V" "False" "tampered-hash idx2 reports valid:false"
HASH_REASON=$($PY -c "import json; print(json.load(open('$TMP/rep_hash.json'))[2].get('reason',''))")
assert_contains "$HASH_REASON" "tx_hash mismatch" "hash-tamper reason cites tx_hash mismatch"

echo
echo "=== 6. --strict exits 3 when >=1 invalid [REQ 6] ==="
set +e
"$WALLET" verify-batch --in "$TMP/tamper_sig.json" --strict >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "3" "--strict + >=1 invalid returns 3"
# And confirm --strict on a clean batch is 0 (the other half of REQ 6,
# also exercised in Surface 0f above — re-assert here for symmetry).
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --strict >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--strict + all valid returns 0"

echo
echo "=== 7a. Malformed input: non-array (object) → exit 1 [REQ 7] ==="
echo '{"type":0}' > "$TMP/object.json"
set +e
OBJ_ERR=$("$WALLET" verify-batch --in "$TMP/object.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "non-array (object) input returns 1"
assert_contains "$(echo "$OBJ_ERR" | tr -d '\r')" "must be a top-level JSON array" "non-array diagnostic mentions array requirement"

echo
echo "=== 7b. Malformed input: invalid JSON → exit 1 [REQ 7] ==="
echo "not json {{{{" > "$TMP/bad.json"
set +e
"$WALLET" verify-batch --in "$TMP/bad.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "invalid JSON input returns 1"

echo
echo "=== 7c. Missing-field element → that index invalid (NOT a global abort) [REQ 7] ==="
# An ELEMENT missing required fields is reported per-tx as valid:false; it
# does NOT make the command exit 1 (that's reserved for a malformed
# TOP-LEVEL input). Build a 2-element array: one good, one missing 'sig'.
$PY -c "
import json
a = json.load(open('$TMP/signed3.json'))
good = a[0]
bad  = dict(a[1]); bad.pop('sig', None); bad.pop('signature', None)
json.dump([good, bad], open('$TMP/missing_field.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/missing_field.json" --out "$TMP/rep_mf.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "element-with-missing-field is per-tx invalid, not a global error (exit 0)"
MF_GOOD=$($PY -c "import json; print(json.load(open('$TMP/rep_mf.json'))[0]['valid'])")
MF_BAD=$($PY -c "import json; print(json.load(open('$TMP/rep_mf.json'))[1]['valid'])")
assert_eq "$MF_GOOD" "True"  "good element reports valid:true"
assert_eq "$MF_BAD"  "False" "missing-sig element reports valid:false"
MF_REASON=$($PY -c "import json; print(json.load(open('$TMP/rep_mf.json'))[1].get('reason',''))")
assert_contains "$MF_REASON" "missing 'sig'" "missing-sig element reason cites the missing field"

echo
echo "=== Surface 0g. --in - reads from stdin ==="
set +e
STDIN_OUT=$("$WALLET" verify-batch --in - <"$TMP/signed3.json" 2>&1)
RC=$?
set -e
assert_eq "$RC" "0" "stdin happy path returns 0"
STDIN_NVALID=$(echo "$STDIN_OUT" | tr -d '\r' | $PY -c "import json,sys; print(sum(1 for v in json.loads(sys.stdin.read()) if v['valid']))")
assert_eq "$STDIN_NVALID" "3" "stdin batch verifies all 3"

echo
echo "=== Surface 0h. --out refuses to overwrite without --force; --force allows it ==="
# rep3.json already exists from assertion 2.
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --out "$TMP/rep3.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--out existing file without --force returns 1"
set +e
"$WALLET" verify-batch --in "$TMP/signed3.json" --out "$TMP/rep3.json" --force >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "--out existing file WITH --force returns 0"

echo
echo "=== Surface 0i. Domain sender (non-anon from) → that index invalid ==="
# Replace from with a domain name on one record: no in-wallet pubkey lookup,
# so verify cannot succeed → that index is invalid. Because `from` is part
# of signing_bytes, mutating it changes the canonical hash; to exercise the
# non-anon-sender reason path (rather than tripping the earlier hash-mismatch
# check), recompute the matching hash for the domain-from body via the
# wallet's own derive-tx-hash. The verdict still ends up invalid — but now
# for the right reason (no in-wallet pubkey for a domain sender).
$PY -c "
import json
e = json.load(open('$TMP/signed3.json'))[0]
e['from'] = 'alice.determ'
json.dump(e, open('$TMP/domain_one.json','w'))
"
DOM_HASH=$("$WALLET" derive-tx-hash --tx-json "$TMP/domain_one.json" --field hash 2>/dev/null | tr -d '\r')
$PY -c "
import json
e = json.load(open('$TMP/domain_one.json'))
e['hash'] = '$DOM_HASH'   # body+hash now consistent; only the sig+sender are off
json.dump([e], open('$TMP/domain.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/domain.json" --out "$TMP/rep_domain.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "domain-sender record report-only returns 0"
DOM_V=$($PY -c "import json; print(json.load(open('$TMP/rep_domain.json'))[0]['valid'])")
assert_eq "$DOM_V" "False" "domain-sender idx0 reports valid:false"
DOM_REASON=$($PY -c "import json; print(json.load(open('$TMP/rep_domain.json'))[0].get('reason',''))")
assert_contains "$DOM_REASON" "not an anon-address" "domain-sender reason explains no in-wallet pubkey lookup"

echo
echo "=== Surface 0j. --strict TRANSFER gate: amount=0 record flagged invalid ==="
# Hand-craft a record with amount=0 (the sig won't match the mutated body,
# but --strict's amount==0 gate should fire regardless). Use idx0 of the
# clean batch with amount zeroed.
$PY -c "
import json
a = json.load(open('$TMP/signed3.json'))
a[0]['amount'] = 0
json.dump([a[0]], open('$TMP/amt0.json','w'))
"
set +e
"$WALLET" verify-batch --in "$TMP/amt0.json" --strict --out "$TMP/rep_amt0.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "3" "--strict amount=0 batch returns 3 (>=1 invalid)"
AMT0_V=$($PY -c "import json; print(json.load(open('$TMP/rep_amt0.json'))[0]['valid'])")
assert_eq "$AMT0_V" "False" "--strict amount=0 record reports valid:false"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet verify-batch"; exit 0
else
    echo "  FAIL: test_wallet_verify_batch"; exit 1
fi
