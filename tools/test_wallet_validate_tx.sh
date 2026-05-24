#!/usr/bin/env bash
# determ-wallet validate-tx CLI test.
#
# Exercises offline validation of an already-signed tx envelope. Validate-tx
# is the companion to the signer commands (cold-sign, sign-anon-tx) — it
# takes their output and runs the full structural + crypto + (optional)
# liveness battery an operator wants before `determ submit-tx`.
#
# Differentiation vs tx-sign-verify (Round 17):
#   * tx-sign-verify requires --pubkey (operator-supplied trust anchor)
#   * validate-tx derives the pubkey for anon-address senders from the
#     `from` field (anon_address == "0x"+hex(ed_pub))
#   * validate-tx adds tx_hash_match (recompute SHA-256 of signing_bytes
#     vs the envelope's stored `hash`) — catches body-tamper-after-sign
#   * validate-tx accepts BOTH the canonical chain shape (numeric `type`,
#     `sig` field) AND the sign-anon-tx output shape ("TRANSFER" mnemonic,
#     `signature` field)
#   * --strict adds TRANSFER-specific rule checks
#   * --rpc-port adds liveness warnings (nonce drift, insufficient funds)
#
# Assertions (~28):
#   1.  Global help mentions validate-tx.
#   2.  validate-tx --help exits 0.
#   3.  Missing --tx-json: exit 1.
#   4.  Nonexistent --tx-json file: exit 1.
#   5.  Invalid JSON in --tx-json: exit 1.
#   6.  Unknown CLI arg: exit 1.
#   7.  Out-of-range --rpc-port: exit 1.
#   8.  Happy path on sign-anon-tx output (exit 0, overall_valid=true).
#   9.  --json output is parseable JSON.
#  10.  JSON.overall_valid == true on happy path.
#  11.  JSON.signature_verified == "true".
#  12.  JSON.tx_hash_match == true.
#  13.  JSON.signing_bytes_hex is exactly 64 hex chars.
#  14.  Tampered signature: exit 2 (signature_verified=false).
#  15.  Tampered amount (without re-sign): exit 2 (tx_hash mismatch).
#  16.  Unknown tx-type (99): exit 2 (structural fail).
#  17.  Missing `from` field: exit 2 (structural fail).
#  18.  Missing `sig`/`signature`: exit 2.
#  19.  Canonical chain shape (numeric type + `sig` field): exit 0.
#  20.  Numeric type out of TxType range (e.g. 50): exit 2.
#  21.  --strict on TRANSFER with amount=0: exit 2.
#  22.  --strict on TRANSFER with empty to: exit 2.
#  23.  --strict with uppercase anon address in `from`: exit 2 (S-028).
#  24.  --strict with uppercase anon address in `to`: exit 2 (S-028).
#  25.  --strict reports zero-fee as warning (not fail).
#  26.  Domain sender produces signature_verified="skipped".
#  27.  --rpc-port with daemon down emits rpc_unreachable warning
#       but does NOT flip overall_valid.
#  28.  --tx-json - reads from stdin (happy path).
#  29.  Signed by Alice but `from` field replaced with Bob's address:
#       exit 2 (sig verifies against pubkey-derived-from-from = Bob's,
#       sig was made by Alice — mismatch).
#  30.  Strict mode happy path (clean TRANSFER): exit 0, no strict-FAIL.
#
# Run from repo root: bash tools/test_wallet_validate_tx.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_validate_tx.$$"
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
$PY -c "import json; d=json.load(open('$TMP/keys.json')); json.dump(d['accounts'][1], open('$TMP/key_b.json','w'))"

# Produce a baseline signed envelope.
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
  --amount 1000 --fee 5 --nonce 1 --out "$TMP/signed.json" >/dev/null 2>&1

echo "=== 1. Global help mentions validate-tx ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "validate-tx"; then
  echo "  PASS: help mentions validate-tx"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing validate-tx"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. validate-tx --help exits 0 ==="
set +e
"$WALLET" validate-tx --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "validate-tx --help exits 0"

echo
echo "=== 3. Missing --tx-json: exit 1 ==="
set +e
"$WALLET" validate-tx >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --tx-json returns 1"

echo
echo "=== 4. Nonexistent --tx-json file: exit 1 ==="
set +e
"$WALLET" validate-tx --tx-json "$TMP/no_such_file.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "nonexistent file returns 1"

echo
echo "=== 5. Invalid JSON: exit 1 ==="
echo "not json {{{{" > "$TMP/bad.json"
set +e
"$WALLET" validate-tx --tx-json "$TMP/bad.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "invalid JSON returns 1"

echo
echo "=== 6. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 7. Out-of-range --rpc-port: exit 1 ==="
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --rpc-port 99999 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--rpc-port 99999 returns 1"

echo
echo "=== 8. Happy path on sign-anon-tx output ==="
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" >"$TMP/happy_out.txt" 2>&1
RC=$?
set -e
HOUT=$(tr -d '\r' < "$TMP/happy_out.txt")
assert_eq "$RC" "0" "happy path returns 0"
assert_contains "$HOUT" "overall_valid:           true" "human output shows overall_valid=true"

echo
echo "=== 9-13. --json output parses + has expected shape ==="
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --json >"$TMP/json_out.json" 2>&1
RC=$?
set -e
JOUT=$(tr -d '\r' < "$TMP/json_out.json")
assert_eq "$RC" "0" "--json happy path returns 0"
PARSED_OK=$(echo "$JOUT" | $PY -c "import json,sys; d=json.loads(sys.stdin.read()); print('yes')" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json output is parseable JSON"
OVERALL=$(echo "$JOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['overall_valid'])")
assert_eq "$OVERALL" "True" "JSON overall_valid is True"
SIGVER=$(echo "$JOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['signature_verified'])")
assert_eq "$SIGVER" "true" "JSON signature_verified is true"
HASHMATCH=$(echo "$JOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['tx_hash_match'])")
assert_eq "$HASHMATCH" "True" "JSON tx_hash_match is True"
SBHEX_LEN=$(echo "$JOUT" | $PY -c "import json,sys; print(len(json.loads(sys.stdin.read())['signing_bytes_hex']))")
assert_eq "$SBHEX_LEN" "64" "JSON signing_bytes_hex is 64 hex chars"

echo
echo "=== 14. Tampered signature: exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
sig = d['signature']
# flip one nibble in the middle of the sig (still 128 hex chars).
i = 64
new = ('0' if sig[i] != '0' else 'a')
d['signature'] = sig[:i] + new + sig[i+1:]
json.dump(d, open('$TMP/signed_badsig.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_badsig.json" --json >"$TMP/sig_out.json" 2>&1
RC=$?
set -e
SOUT=$(tr -d '\r' < "$TMP/sig_out.json")
assert_eq "$RC" "2" "tampered sig returns 2"
SV=$(echo "$SOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['signature_verified'])")
assert_eq "$SV" "false" "signature_verified is false on tamper"

echo
echo "=== 15. Tampered amount (without re-sign): exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['amount'] = d['amount'] + 1   # bump amount but leave sig + hash alone
json.dump(d, open('$TMP/signed_badamt.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_badamt.json" --json >"$TMP/amt_out.json" 2>&1
RC=$?
set -e
AOUT=$(tr -d '\r' < "$TMP/amt_out.json")
assert_eq "$RC" "2" "tampered amount returns 2"
HM=$(echo "$AOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['tx_hash_match'])")
assert_eq "$HM" "False" "tx_hash_match is False on amount tamper"

echo
echo "=== 16. Unknown tx-type 99 numeric: exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['type'] = 99       # outside [0,10] TxType range
d['sig']  = d['signature']
json.dump(d, open('$TMP/signed_badtype.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_badtype.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "unknown numeric type returns 2"

echo
echo "=== 17. Missing 'from' field: exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['from']
json.dump(d, open('$TMP/signed_nofrom.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_nofrom.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "missing 'from' returns 2"

echo
echo "=== 18. Missing 'sig'/'signature' field: exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
del d['signature']
json.dump(d, open('$TMP/signed_nosig.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_nosig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "missing sig returns 2"

echo
echo "=== 19. Canonical chain shape (numeric type + 'sig' field): exit 0 ==="
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
    'sig':     d['signature'],   # field rename signature -> sig
    'hash':    d['hash'],
}
json.dump(canon, open('$TMP/signed_canon.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_canon.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "canonical chain shape returns 0"

echo
echo "=== 20. Numeric type 50 (out of range): exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed_canon.json'))
d['type'] = 50
json.dump(d, open('$TMP/signed_type50.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_type50.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "numeric type 50 returns 2"

echo
echo "=== 21. --strict + amount=0: exit 2 ==="
# Build a TRANSFER-shaped envelope with amount=0 (bypassing the sign-anon-tx
# refusal by hand-crafting). Sig won't verify (the body changed) — that's
# fine, the strict gate will fire first.
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['amount'] = 0
json.dump(d, open('$TMP/signed_amt0.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_amt0.json" --strict --json >"$TMP/strict_amt0.json" 2>&1
RC=$?
set -e
S0OUT=$(tr -d '\r' < "$TMP/strict_amt0.json")
assert_eq "$RC" "2" "--strict + amount=0 returns 2"
HAS_AMT_FAIL=$(echo "$S0OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
warnings = d.get('strict_warnings', [])
any_amt = any('amount == 0' in w for w in warnings)
print('yes' if any_amt else 'no')
")
assert_eq "$HAS_AMT_FAIL" "yes" "--strict reports amount==0 warning"

echo
echo "=== 22. --strict + empty 'to': exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['to'] = ''
json.dump(d, open('$TMP/signed_noto.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_noto.json" --strict --json >"$TMP/strict_noto.json" 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "--strict + empty 'to' returns 2"

echo
echo "=== 23. --strict + uppercase anon 'from': exit 2 (S-028) ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['from'] = '0x' + d['from'][2:].upper()
json.dump(d, open('$TMP/signed_upper_from.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_upper_from.json" --strict --json >"$TMP/strict_ufr.json" 2>&1
RC=$?
set -e
UFR_OUT=$(tr -d '\r' < "$TMP/strict_ufr.json")
assert_eq "$RC" "2" "--strict + uppercase 'from' returns 2"
HAS_S028=$(echo "$UFR_OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
warnings = d.get('strict_warnings', [])
print('yes' if any('S-028' in w for w in warnings) else 'no')
")
assert_eq "$HAS_S028" "yes" "--strict cites S-028 on uppercase from"

echo
echo "=== 24. --strict + uppercase anon 'to': exit 2 (S-028) ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['to'] = '0x' + d['to'][2:].upper()
json.dump(d, open('$TMP/signed_upper_to.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_upper_to.json" --strict >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "--strict + uppercase 'to' returns 2"

echo
echo "=== 25. --strict reports zero-fee as WARN (not fail) ==="
# Build a clean valid TRANSFER with fee=0.
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
  --amount 1000 --fee 0 --nonce 2 --out "$TMP/signed_fee0.json" >/dev/null 2>&1
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_fee0.json" --strict --json >"$TMP/strict_fee0.json" 2>&1
RC=$?
set -e
F0OUT=$(tr -d '\r' < "$TMP/strict_fee0.json")
assert_eq "$RC" "0" "--strict + fee=0 (otherwise clean) returns 0"
HAS_FEE_WARN=$(echo "$F0OUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
warnings = d.get('strict_warnings', [])
print('yes' if any('fee == 0' in w for w in warnings) else 'no')
")
assert_eq "$HAS_FEE_WARN" "yes" "--strict emits WARN on fee==0"

echo
echo "=== 26. Domain sender → signature_verified='skipped' ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['from'] = 'alice.determ'        # domain name; no in-wallet pubkey lookup
json.dump(d, open('$TMP/signed_domain.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_domain.json" --json >"$TMP/domain_out.json" 2>&1
RC=$?
set -e
DOUT=$(tr -d '\r' < "$TMP/domain_out.json")
SVD=$(echo "$DOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['signature_verified'])")
assert_eq "$SVD" "skipped" "domain sender produces skipped sig verify"

echo
echo "=== 27. --rpc-port with daemon down: rpc_unreachable warning, no flip ==="
# Pick a port unlikely to be bound. 1 (privileged + unused for IP) is a
# safe sentinel.
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --rpc-port 1 --json >"$TMP/rpc_out.json" 2>&1
RC=$?
set -e
RPCOUT=$(tr -d '\r' < "$TMP/rpc_out.json")
# overall_valid must remain true (RPC failures are advisory only).
OVALL_RPC=$(echo "$RPCOUT" | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['overall_valid'])")
assert_eq "$OVALL_RPC" "True" "--rpc-port unreachable: overall_valid still True"
HAS_UNREACH=$(echo "$RPCOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
warnings = d.get('rpc_warnings', [])
print('yes' if any('rpc_unreachable' in w or 'failed' in w for w in warnings) else 'no')
")
assert_eq "$HAS_UNREACH" "yes" "--rpc-port unreachable emits warning"

echo
echo "=== 28. --tx-json - reads from stdin ==="
set +e
"$WALLET" validate-tx --tx-json - <"$TMP/signed.json" >"$TMP/stdin_out.txt" 2>&1
RC=$?
set -e
STDIN_OUT=$(tr -d '\r' < "$TMP/stdin_out.txt")
assert_eq "$RC" "0" "stdin happy path returns 0"
assert_contains "$STDIN_OUT" "overall_valid:           true" "stdin output reports valid"

echo
echo "=== 29. Signed by Alice + 'from' replaced with Bob: exit 2 ==="
# Body signed by Alice but envelope claims from=Bob ⇒ sig verifies against
# pubkey-derived-from-Bob's-address, sig was made by Alice ⇒ mismatch.
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['from'] = '$ADDR_B'
json.dump(d, open('$TMP/signed_fromswap.json','w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_fromswap.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "from-swap (Alice signed, Bob claimed) returns 2"

echo
echo "=== 30. --strict happy path on clean TRANSFER: exit 0, no FAIL warnings ==="
# Use the original signed.json (fee=5, amount=1000, lowercase anon addresses).
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --strict --json >"$TMP/strict_clean.json" 2>&1
RC=$?
set -e
SHOUT=$(tr -d '\r' < "$TMP/strict_clean.json")
assert_eq "$RC" "0" "--strict on clean TRANSFER returns 0"
NO_FAILS=$(echo "$SHOUT" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
warnings = d.get('strict_warnings', [])
fails = [w for w in warnings if w.startswith('FAIL')]
print('yes' if not fails else 'no')
")
assert_eq "$NO_FAILS" "yes" "--strict on clean TRANSFER has zero FAIL warnings"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet validate-tx"; exit 0
else
    echo "  FAIL"; exit 1
fi
