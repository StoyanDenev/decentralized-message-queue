#!/usr/bin/env bash
# determ-wallet derive-tx-hash CLI test.
#
# Exercises the focused tx_hash recomputation command: given a signed tx
# envelope, recompute SHA-256(signing_bytes) and optionally compare it
# against the envelope's stored `hash` field. Distinct from validate-tx
# (which composes structural + signature + hash + strict + RPC) — this
# command does ONE thing, with output shaped for downstream pipelines
# (audit logs, receipt-equality checks, tamper-detection cron jobs).
#
# Differentiation vs sibling commands:
#   * cold-sign / sign-anon-tx — PRODUCE a signed envelope (incl. hash)
#   * tx-sign-verify           — verify Ed25519 sig given a pubkey
#   * validate-tx              — full composite gate (structural + sig +
#                                hash + optional strict + RPC)
#   * derive-tx-hash           — recompute hash (and/or signing_bytes),
#                                optionally check stored vs recomputed
#
# Assertions (~26):
#   1.  Global help mentions derive-tx-hash.
#   2.  derive-tx-hash --help exits 0.
#   3.  Missing --tx-json: exit 1.
#   4.  Nonexistent --tx-json file: exit 1.
#   5.  Invalid JSON in --tx-json: exit 1.
#   6.  Unknown CLI arg: exit 1.
#   7.  Invalid --field name: exit 1.
#   8.  --check with no 'hash' field in envelope: exit 1.
#   9.  Happy-path default (--field hash): exit 0, prints 64 hex.
#  10.  Default output matches envelope's stored hash exactly.
#  11.  --field signing_bytes: exit 0, prints valid even-length hex.
#  12.  --field both: exit 0, parses as JSON with recomputed_hash +
#       signing_bytes keys.
#  13.  --check happy: exit 0, "match=true" present.
#  14.  --check happy with --json: JSON.match == true.
#  15.  --check tampered amount: exit 2.
#  16.  --check tampered amount: JSON.match == false.
#  17.  --check tampered amount: stored_hash != recomputed_hash in JSON.
#  18.  --json output is parseable JSON.
#  19.  --json output contains recomputed_hash + signing_bytes keys.
#  20.  --json stored_hash present when envelope has hash field.
#  21.  Stdin happy-path (--tx-json -): exit 0, prints expected hash.
#  22.  Canonical chain shape (numeric type + sig field): exit 0,
#       hash matches sign-anon-tx shape's hash byte-for-byte.
#  23.  Mnemonic type "TRANSFER" (sign-anon-tx shape): exit 0.
#  24.  Upper-case stored hash compared case-insensitively (--check OK).
#  25.  Missing 'type' field: exit 1.
#  26.  Missing 'amount' field: exit 1.
#
# Run from repo root: bash tools/test_wallet_derive_tx_hash.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_derive_tx_hash.$$"
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

# Generate two fresh keypairs.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
$PY -c "import json; d=json.load(open('$TMP/keys.json')); json.dump(d['accounts'][0], open('$TMP/key_a.json','w'))"

# Produce a baseline signed envelope (sign-anon-tx shape).
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
  --amount 1000 --fee 5 --nonce 1 --out "$TMP/signed.json" >/dev/null 2>&1

STORED_HASH=$($PY -c "import json; print(json.load(open('$TMP/signed.json'))['hash'])")

echo "=== 1. Global help mentions derive-tx-hash ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "derive-tx-hash"; then
  echo "  PASS: help mentions derive-tx-hash"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing derive-tx-hash"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. derive-tx-hash --help exits 0 ==="
set +e
"$WALLET" derive-tx-hash --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "derive-tx-hash --help exits 0"

echo
echo "=== 3. Missing --tx-json: exit 1 ==="
set +e
"$WALLET" derive-tx-hash >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --tx-json returns 1"

echo
echo "=== 4. Nonexistent --tx-json file: exit 1 ==="
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/no_such_file.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent file returns 1"

echo
echo "=== 5. Invalid JSON: exit 1 ==="
echo "not json {{{{" > "$TMP/bad.json"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/bad.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "invalid JSON returns 1"

echo
echo "=== 6. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 7. Invalid --field name: exit 1 ==="
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --field bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--field bogus returns 1"

echo
echo "=== 8. --check on envelope without 'hash' field: exit 1 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['hash']
json.dump(d, open('$TMP/signed_nohash.json','w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed_nohash.json" --check >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--check without 'hash' returns 1"

echo
echo "=== 9-10. Happy path default (--field hash): exit 0, prints 64-hex matching stored ==="
set +e
DEFAULT_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" 2>&1 | tr -d '\r' | tr -d '\n')
RC=$?
set -e
assert_eq "$RC" "0" "default field=hash returns 0"
HEX_LEN=${#DEFAULT_OUT}
assert_eq "$HEX_LEN" "64" "default output is 64 hex chars"
assert_eq "$DEFAULT_OUT" "$STORED_HASH" "default output matches envelope's stored hash"

echo
echo "=== 11. --field signing_bytes: exit 0, even-length hex ==="
set +e
SB_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --field signing_bytes 2>&1 | tr -d '\r' | tr -d '\n')
RC=$?
set -e
assert_eq "$RC" "0" "--field signing_bytes returns 0"
SB_LEN=${#SB_OUT}
SB_MOD=$((SB_LEN % 2))
assert_eq "$SB_MOD" "0" "signing_bytes hex has even length"
# Verify it's all hex chars.
HEX_OK=$(echo "$SB_OUT" | $PY -c "
import sys
s = sys.stdin.read().strip()
ok = all(c in '0123456789abcdef' for c in s) and len(s) > 0
print('yes' if ok else 'no')
")
assert_eq "$HEX_OK" "yes" "signing_bytes is valid lowercase hex"

echo
echo "=== 12. --field both: exit 0, parses as JSON with both keys ==="
set +e
BOTH_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --field both 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--field both returns 0"
BOTH_OK=$(echo "$BOTH_OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = ('recomputed_hash' in d) and ('signing_bytes' in d)
print('yes' if ok else 'no')
")
assert_eq "$BOTH_OK" "yes" "--field both emits JSON with recomputed_hash + signing_bytes"

echo
echo "=== 13-14. --check happy ==="
set +e
CHECK_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --check 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--check happy returns 0"
assert_contains "$CHECK_OUT" "match=true" "--check prints match=true"
set +e
CHECK_JSON=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --check --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--check --json happy returns 0"
CJ_MATCH=$(echo "$CHECK_JSON" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['match'])")
assert_eq "$CJ_MATCH" "True" "--check --json: JSON.match is True"

echo
echo "=== 15-17. --check tampered amount → exit 2 + mismatch JSON ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['amount'] = d['amount'] + 1   # bump amount, leave sig + hash alone
json.dump(d, open('$TMP/tampered.json','w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/tampered.json" --check --json >"$TMP/tampered_out.json" 2>&1
RC=$?
set -e
TAMP_JSON=$(tr -d '\r' < "$TMP/tampered_out.json")
assert_eq "$RC" "2" "tampered amount + --check returns 2"
TJ_MATCH=$(echo "$TAMP_JSON" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['match'])")
assert_eq "$TJ_MATCH" "False" "tampered: JSON.match is False"
DIFF_OK=$(echo "$TAMP_JSON" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['stored_hash'] != d['recomputed_hash'] else 'no')
")
assert_eq "$DIFF_OK" "yes" "tampered: stored_hash != recomputed_hash"

echo
echo "=== 18-20. --json (no --check) is parseable + has expected shape ==="
set +e
JSON_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--json (no check) returns 0"
PARSED_OK=$(echo "$JSON_OUT" | $PY -c "import json,sys; json.loads(sys.stdin.read()); print('yes')" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json output is parseable JSON"
KEY_OK=$(echo "$JSON_OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = ('recomputed_hash' in d) and ('signing_bytes' in d)
print('yes' if ok else 'no')
")
assert_eq "$KEY_OK" "yes" "--json has recomputed_hash + signing_bytes keys"
HAS_STORED=$(echo "$JSON_OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if 'stored_hash' in d else 'no')
")
assert_eq "$HAS_STORED" "yes" "--json includes stored_hash (envelope had hash)"

echo
echo "=== 21. Stdin happy-path (--tx-json -) ==="
set +e
STDIN_OUT=$(cat "$TMP/signed.json" | "$WALLET" derive-tx-hash --tx-json - 2>&1 | tr -d '\r' | tr -d '\n')
RC=$?
set -e
assert_eq "$RC" "0" "stdin --tx-json - returns 0"
assert_eq "$STDIN_OUT" "$STORED_HASH" "stdin emits same hash as file mode"

echo
echo "=== 22. Canonical chain shape (numeric type + 'sig' field): byte-for-byte match ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
canon = {
    'type':    0,                # TRANSFER as int
    'from':    d['from'],
    'to':      d['to'],
    'amount':  d['amount'],
    'fee':     d['fee'],
    'nonce':   d['nonce'],
    'payload': d['payload'],
    'sig':     d['signature'],
    'hash':    d['hash'],
}
json.dump(canon, open('$TMP/signed_canon.json','w'))
"
set +e
CANON_OUT=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed_canon.json" 2>&1 | tr -d '\r' | tr -d '\n')
RC=$?
set -e
assert_eq "$RC" "0" "canonical chain shape returns 0"
assert_eq "$CANON_OUT" "$STORED_HASH" "canonical shape produces same hash byte-for-byte"

echo
echo "=== 23. Mnemonic type 'TRANSFER' (sign-anon-tx shape): exit 0 ==="
# The baseline signed.json already uses "TRANSFER"; sanity-check with --check
# happy still passes (covered above), explicit emit also passes.
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "mnemonic TRANSFER shape returns 0"

echo
echo "=== 24. Upper-case stored hash: case-insensitive --check passes ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['hash'] = d['hash'].upper()    # operator tool upper-cased the hash
json.dump(d, open('$TMP/signed_upperhash.json','w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed_upperhash.json" --check >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "upper-case stored hash compares case-insensitively"

echo
echo "=== 25. Missing 'type' field: exit 1 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['type']
json.dump(d, open('$TMP/signed_notype.json','w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed_notype.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing 'type' returns 1"

echo
echo "=== 26. Missing 'amount' field: exit 1 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['amount']
json.dump(d, open('$TMP/signed_noamt.json','w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed_noamt.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing 'amount' returns 1"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
