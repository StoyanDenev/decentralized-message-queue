#!/usr/bin/env bash
# determ-wallet inspect-tx CLI test.
#
# Exercises the READ-ONLY tx-envelope inspector: parse every standard
# envelope field, decode the payload per TxType (TRANSFER / STAKE /
# UNSTAKE / REGISTER / DEREGISTER / PARAM_CHANGE / MERGE_EVENT /
# COMPOSABLE_BATCH / DAPP_REGISTER / DAPP_CALL), and report derived
# fields (signing_bytes hex, computed_hash, hash_match). No validation,
# no Ed25519 verify, no daemon round-trip — distinct from validate-tx
# (composite gate), tx-sign-verify (sig only), derive-tx-hash (hash
# recompute).
#
# Assertions (~25):
#   1.  Global help mentions inspect-tx.
#   2.  inspect-tx --help exits 0.
#   3.  Missing --tx-json: exit 1.
#   4.  Nonexistent --tx-json file: exit 1.
#   5.  Invalid JSON in --tx-json: exit 1.
#   6.  Unknown CLI arg: exit 1.
#   7.  Happy-path TRANSFER (sign-anon-tx shape): exit 0.
#   8.  Default output mentions type 0 + TRANSFER mnemonic.
#   9.  Default output prints amount + fee + nonce.
#  10.  Default output prints computed_hash + hash_match: true.
#  11.  --json output is parseable + has type/from/to/amount/payload_hex.
#  12.  --json includes computed_hash + signing_bytes_hex + hash_match=true.
#  13.  Canonical chain shape (numeric type, 'sig' field): exit 0 + hash_match true.
#  14.  Stdin input (--tx-json -): exit 0 + hash_match true.
#  15.  Tampered amount → hash_match false (exit 0; this is read-only).
#  16.  PARAM_CHANGE payload decode → param_name + effective_height.
#  17.  PARAM_CHANGE param_value_u64 emitted when value is 8 bytes.
#  18.  DAPP_REGISTER op=0 payload → service_pubkey_hex + endpoint_url + topics.
#  19.  DAPP_REGISTER op=1 payload → op_name=deactivate.
#  20.  DAPP_CALL payload → topic + ciphertext_len.
#  21.  STAKE payload → stake_amount.
#  22.  UNSTAKE payload → stake_amount.
#  23.  REGISTER payload → ed_pub_hex + region.
#  24.  MERGE_EVENT payload → event_type BEGIN + shard_id + partner_id.
#  25.  Missing 'type' field: exit 1.
#  26.  Unknown TxType (e.g., 99): exit 0 with payload_decode_known=false.
#
# Run from repo root: bash tools/test_wallet_inspect_tx.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_inspect_tx.$$"
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

# Produce a baseline signed TRANSFER envelope (sign-anon-tx shape).
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
  --amount 1000 --fee 5 --nonce 1 --out "$TMP/signed.json" >/dev/null 2>&1

echo "=== 1. Global help mentions inspect-tx ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "inspect-tx"; then
  echo "  PASS: help mentions inspect-tx"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing inspect-tx"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. inspect-tx --help exits 0 ==="
set +e
"$WALLET" inspect-tx --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "inspect-tx --help exits 0"

echo
echo "=== 3. Missing --tx-json: exit 1 ==="
set +e
"$WALLET" inspect-tx >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --tx-json returns 1"

echo
echo "=== 4. Nonexistent --tx-json file: exit 1 ==="
set +e
"$WALLET" inspect-tx --tx-json "$TMP/no_such_file.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent file returns 1"

echo
echo "=== 5. Invalid JSON: exit 1 ==="
echo "not json {{{{" > "$TMP/bad.json"
set +e
"$WALLET" inspect-tx --tx-json "$TMP/bad.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "invalid JSON returns 1"

echo
echo "=== 6. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" inspect-tx --tx-json "$TMP/signed.json" --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 7-10. Happy-path TRANSFER (sign-anon-tx shape) ==="
set +e
OUT=$("$WALLET" inspect-tx --tx-json "$TMP/signed.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "happy-path TRANSFER returns 0"
assert_contains "$OUT" "TRANSFER" "default output mentions TRANSFER mnemonic"
assert_contains "$OUT" "amount:             1000" "default output prints amount"
assert_contains "$OUT" "fee:                5" "default output prints fee"
assert_contains "$OUT" "hash_match:         true" "default output prints hash_match: true"

echo
echo "=== 11-12. --json output ==="
set +e
JOUT=$("$WALLET" inspect-tx --tx-json "$TMP/signed.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "--json returns 0"
JOK=$(echo "$JOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
need = ('type','from','to','amount','fee','nonce','payload_hex',
        'computed_hash','signing_bytes_hex','hash_match','type_mnemonic')
ok = all(k in d for k in need) and d['type'] == 0 and d['hash_match'] is True
print('yes' if ok else 'no')
")
assert_eq "$JOK" "yes" "--json contains all expected keys + hash_match=true"

echo
echo "=== 13. Canonical chain shape (numeric type, 'sig' field) ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
canon = {
    'type':    0,
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
COUT=$("$WALLET" inspect-tx --tx-json "$TMP/signed_canon.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "canonical chain shape returns 0"
CANON_OK=$(echo "$COUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['hash_match'] is True else 'no')
")
assert_eq "$CANON_OK" "yes" "canonical chain shape: hash_match=true"

echo
echo "=== 14. Stdin input (--tx-json -) ==="
set +e
SOUT=$(cat "$TMP/signed.json" | "$WALLET" inspect-tx --tx-json - --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "stdin input returns 0"
SOK=$(echo "$SOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['hash_match'] is True and d['type_mnemonic'] == 'TRANSFER' else 'no')
")
assert_eq "$SOK" "yes" "stdin emits same decoded envelope"

echo
echo "=== 15. Tampered amount → hash_match=false (exit 0; read-only) ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['amount'] = d['amount'] + 1
json.dump(d, open('$TMP/tampered.json','w'))
"
set +e
TOUT=$("$WALLET" inspect-tx --tx-json "$TMP/tampered.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "tampered envelope still returns 0 (read-only)"
TOK=$(echo "$TOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['hash_match'] is False else 'no')
")
assert_eq "$TOK" "yes" "tampered: hash_match=false"

echo
echo "=== 16-17. PARAM_CHANGE payload decode ==="
# Hand-craft a PARAM_CHANGE payload: name_len(u8)=10 + name="min_stake" wait 9 chars + value_len(u16 LE)=8 +
# value(u64 LE) = 1000 + effective_height(u64 LE) = 999.
# name = "min_stake" (9 chars), so name_len = 9
PAYLOAD_HEX=$($PY -c "
name = b'min_stake'
value = (1000).to_bytes(8, 'little')
eff = (999).to_bytes(8, 'little')
body = bytes([len(name)]) + name + len(value).to_bytes(2, 'little') + value + eff
print(body.hex())
")
$PY -c "
import json
d = {
    'type': 6,
    'from': '$ADDR_A',
    'to': '',
    'amount': 0,
    'fee': 1,
    'nonce': 5,
    'payload': '$PAYLOAD_HEX',
    'sig': '00'*64,
    'hash': '00'*32,
}
json.dump(d, open('$TMP/param_change.json','w'))
"
set +e
POUT=$("$WALLET" inspect-tx --tx-json "$TMP/param_change.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "PARAM_CHANGE inspect returns 0"
PARAM_OK=$(echo "$POUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d.get('payload_decoded', {})
ok = (
    d.get('type_mnemonic') == 'PARAM_CHANGE'
    and pd.get('param_name') == 'min_stake'
    and pd.get('effective_height') == 999
)
print('yes' if ok else 'no')
")
assert_eq "$PARAM_OK" "yes" "PARAM_CHANGE decoded: name + effective_height"
PARAM_U64_OK=$(echo "$POUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d.get('payload_decoded', {})
print('yes' if pd.get('param_value_u64') == 1000 else 'no')
")
assert_eq "$PARAM_U64_OK" "yes" "PARAM_CHANGE param_value_u64 surfaced for 8-byte value"

echo
echo "=== 18-19. DAPP_REGISTER payload decode ==="
# op=0: [op:u8=0][service_pubkey:32B][url_len:u8][url][topic_count:u8]
#       [topic_len:u8][topic][retention:u8][metalen:u16 LE][metadata]
DAPP_REG_HEX=$($PY -c "
svc = bytes(range(32))           # 32 fake bytes
url = b'https://dapp.example/api'
topics = [b'msg']
retention = 7
meta = b'{\"v\":1}'
body = bytes([0]) + svc + bytes([len(url)]) + url + bytes([len(topics)])
for t in topics:
    body += bytes([len(t)]) + t
body += bytes([retention])
body += len(meta).to_bytes(2, 'little') + meta
print(body.hex())
")
$PY -c "
import json
d = {
    'type': 9,
    'from': '$ADDR_A',
    'to': '$ADDR_A',
    'amount': 0,
    'fee': 1,
    'nonce': 7,
    'payload': '$DAPP_REG_HEX',
    'sig': '00'*64,
    'hash': '00'*32,
}
json.dump(d, open('$TMP/dapp_register.json','w'))
"
set +e
DRO=$("$WALLET" inspect-tx --tx-json "$TMP/dapp_register.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "DAPP_REGISTER inspect returns 0"
DR_OK=$(echo "$DRO" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d.get('payload_decoded', {})
ok = (
    d.get('type_mnemonic') == 'DAPP_REGISTER'
    and pd.get('op_name') == 'create_or_update'
    and pd.get('endpoint_url') == 'https://dapp.example/api'
    and 'service_pubkey_hex' in pd
    and pd.get('topics') == ['msg']
)
print('yes' if ok else 'no')
")
assert_eq "$DR_OK" "yes" "DAPP_REGISTER decoded: service_pubkey + endpoint + topics"

# op=1: deactivate
DAPP_DEACT_HEX="01"
$PY -c "
import json
d = {
    'type': 9, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 7,
    'payload': '$DAPP_DEACT_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/dapp_deact.json','w'))
"
set +e
DDO=$("$WALLET" inspect-tx --tx-json "$TMP/dapp_deact.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "DAPP_REGISTER op=1 inspect returns 0"
DD_OK=$(echo "$DDO" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['payload_decoded'].get('op_name') == 'deactivate' else 'no')
")
assert_eq "$DD_OK" "yes" "DAPP_REGISTER op=1: op_name=deactivate"

echo
echo "=== 20. DAPP_CALL payload decode ==="
# [topic_len:u8][topic][ct_len:u32 LE][ciphertext]
DAPP_CALL_HEX=$($PY -c "
topic = b'msg'
ct = b'fakeciphertextbytes'
body = bytes([len(topic)]) + topic + len(ct).to_bytes(4, 'little') + ct
print(body.hex())
")
$PY -c "
import json
d = {
    'type': 10, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 8,
    'payload': '$DAPP_CALL_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/dapp_call.json','w'))
"
set +e
DCO=$("$WALLET" inspect-tx --tx-json "$TMP/dapp_call.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "DAPP_CALL inspect returns 0"
DC_OK=$(echo "$DCO" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d['payload_decoded']
print('yes' if pd.get('topic') == 'msg' and pd.get('ciphertext_len') == 19 else 'no')
")
assert_eq "$DC_OK" "yes" "DAPP_CALL decoded: topic + ciphertext_len"

echo
echo "=== 21. STAKE payload decode ==="
STAKE_HEX=$($PY -c "
amt = (50000).to_bytes(8, 'little')
print(amt.hex())
")
$PY -c "
import json
d = {
    'type': 3, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 2,
    'payload': '$STAKE_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/stake.json','w'))
"
SOUT=$("$WALLET" inspect-tx --tx-json "$TMP/stake.json" --json 2>&1 | tr -d '\r')
STAKE_OK=$(echo "$SOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['payload_decoded'].get('stake_amount') == 50000 else 'no')
")
assert_eq "$STAKE_OK" "yes" "STAKE decoded: stake_amount=50000"

echo
echo "=== 22. UNSTAKE payload decode ==="
UNSTAKE_HEX=$($PY -c "print((25000).to_bytes(8,'little').hex())")
$PY -c "
import json
d = {
    'type': 4, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 3,
    'payload': '$UNSTAKE_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/unstake.json','w'))
"
UOUT=$("$WALLET" inspect-tx --tx-json "$TMP/unstake.json" --json 2>&1 | tr -d '\r')
UNSTAKE_OK=$(echo "$UOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d['payload_decoded'].get('stake_amount') == 25000 else 'no')
")
assert_eq "$UNSTAKE_OK" "yes" "UNSTAKE decoded: stake_amount=25000"

echo
echo "=== 23. REGISTER payload decode ==="
# [pubkey: 32B][region_len: u8][region]
REG_HEX=$($PY -c "
pub = bytes(range(32))
region = b'us-east'
body = pub + bytes([len(region)]) + region
print(body.hex())
")
$PY -c "
import json
d = {
    'type': 1, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 4,
    'payload': '$REG_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/register.json','w'))
"
ROUT=$("$WALLET" inspect-tx --tx-json "$TMP/register.json" --json 2>&1 | tr -d '\r')
REG_OK=$(echo "$ROUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d['payload_decoded']
print('yes' if pd.get('region') == 'us-east' and 'ed_pub_hex' in pd else 'no')
")
assert_eq "$REG_OK" "yes" "REGISTER decoded: ed_pub_hex + region"

echo
echo "=== 24. MERGE_EVENT payload decode ==="
# event_type(u8) + shard_id(u32 LE) + partner_id(u32 LE) + effective_height(u64 LE)
# + evidence_window_start(u64 LE) + region_len(u8) + region — minimum 25 bytes.
ME_HEX=$($PY -c "
body  = bytes([0])                                  # event_type = BEGIN
body += (3).to_bytes(4,'little')                    # shard_id   = 3
body += (4).to_bytes(4,'little')                    # partner_id = 4
body += (1000).to_bytes(8,'little')                 # effective_height
body += (500).to_bytes(8,'little')                  # evidence_window_start
body += bytes([0])                                  # region_len = 0
print(body.hex())
")
$PY -c "
import json
d = {
    'type': 7, 'from': '$ADDR_A', 'to': '$ADDR_A',
    'amount': 0, 'fee': 1, 'nonce': 6,
    'payload': '$ME_HEX', 'sig': '00'*64, 'hash': '00'*32,
}
json.dump(d, open('$TMP/merge_event.json','w'))
"
MEOUT=$("$WALLET" inspect-tx --tx-json "$TMP/merge_event.json" --json 2>&1 | tr -d '\r')
ME_OK=$(echo "$MEOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
pd = d['payload_decoded']
ok = (
    pd.get('event_type') == 'BEGIN'
    and pd.get('shard_id') == 3
    and pd.get('partner_id') == 4
)
print('yes' if ok else 'no')
")
assert_eq "$ME_OK" "yes" "MERGE_EVENT decoded: BEGIN + shard_id + partner_id"

echo
echo "=== 25. Missing 'type' field: exit 1 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['type']
json.dump(d, open('$TMP/notype.json','w'))
"
set +e
"$WALLET" inspect-tx --tx-json "$TMP/notype.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing 'type' returns 1"

echo
echo "=== 26. Unknown TxType (99): exit 0 + payload_decode_known=false ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['type'] = 99
json.dump(d, open('$TMP/unknown_type.json','w'))
"
set +e
UTOUT=$("$WALLET" inspect-tx --tx-json "$TMP/unknown_type.json" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "unknown TxType returns 0 (still parseable at envelope level)"
UT_OK=$(echo "$UTOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
print('yes' if d.get('payload_decode_known') is False else 'no')
")
assert_eq "$UT_OK" "yes" "unknown TxType: payload_decode_known=false"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
