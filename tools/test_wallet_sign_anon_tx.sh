#!/usr/bin/env bash
# determ-wallet sign-anon-tx CLI test.
#
# Exercises offline TRANSFER signing for an anon-address holder. Where
# cold-sign reads a pre-built unsigned tx JSON and signs it, sign-anon-tx
# BUILDS a canonical TRANSFER from operator-supplied --to/--amount/--fee/
# --nonce flags using the keyfile's anon address as `from`, signs with
# the keyfile's Ed25519 priv_seed, and writes the signed envelope ready
# for hot-machine submission.
#
# Key differences vs cold-sign:
#   * No --tx-json input — the tx body is constructed from CLI flags.
#   * Output uses upper-case mnemonic "TRANSFER" + field name "signature"
#     (cold-sign emits numeric type + field name "sig" matching chain's
#     Transaction::to_json shape).
#   * S-028 normalization is REJECT-ON-INPUT (no silent mutation): both
#     --keyfile address and --to (if anon-shape) must already be
#     canonical lowercase.
#   * Two keyfile shapes accepted: canonical wallet {address,
#     privkey_hex} AND alternate {ed_priv_hex, ed_pub_hex, anon_address}.
#
# Assertions (~25):
#   1.  Global help mentions sign-anon-tx.
#   2.  sign-anon-tx --help exits 0.
#   3.  Missing --keyfile: exit 1.
#   4.  Missing --to: exit 1.
#   5.  Missing --amount: exit 1.
#   6.  Missing --fee: exit 1.
#   7.  Missing --nonce: exit 1.
#   8.  Missing both --out and --allow-stdout: exit 1.
#   9.  --keyfile pointing at nonexistent file: exit 1.
#  10.  --amount 0: exit 1 (validation rejects).
#  11.  --amount negative: exit 1 (parse rejects).
#  12.  Happy path (canonical keyfile shape, --out path): exit 0.
#  13.  Output file created at requested path.
#  14.  Status JSON on stdout has status=ok.
#  15.  Status JSON carries tx_hash_hex (64 hex chars).
#  16.  Signed-tx file is a JSON object with type/from/to/amount/fee/
#       nonce/payload/signature/hash fields.
#  17.  type field is upper-case "TRANSFER" mnemonic.
#  18.  signature field is exactly 128 hex chars.
#  19.  hash field is exactly 64 hex chars.
#  20.  from field matches the keyfile address.
#  21.  amount/fee/nonce echoed verbatim from CLI flags.
#  22.  S-028: --to with uppercase hex digits is rejected (exit 1).
#  23.  S-028: --keyfile with uppercase-hex address is rejected (exit 1).
#  24.  Alternate keyfile shape (ed_priv_hex / ed_pub_hex / anon_address)
#       signs successfully.
#  25.  --allow-stdout opt-in: signed JSON on stdout, exit 0.
#  26.  Stdout-emitted envelope parses and has a 128-hex signature field.
#  27.  Sibling verifier (tx-sign-verify) accepts the produced signature
#       after field-name shim (signature -> sig; "TRANSFER" -> 0).
#  28.  Keyfile-priv-mismatch (corrupted address vs priv): exit 1.
#
# Run from repo root: bash tools/test_wallet_sign_anon_tx.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_sign_anon_tx.$$"
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

# Generate two fresh keypairs via account-create-batch.
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
PRIV_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/keys.json")
ADDR_A=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/keys.json")
PUB_A="${ADDR_A#0x}"
ADDR_B=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][1]['address'])"     "$TMP/keys.json")

# Write per-account keyfile (canonical wallet shape).
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
json.dump(d['accounts'][0], open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a.json"

# Write an alternate-shape keyfile for the same priv.
$PY -c "
import json,sys
d = json.load(open(sys.argv[1]))
acc = d['accounts'][0]
addr = acc['address']
priv = acc['privkey_hex']
# ed_pub_hex == 64-char tail of address (the 32-byte pubkey hex).
pub_hex = addr[2:]
alt = {
    'ed_priv_hex':  priv,
    'ed_pub_hex':   pub_hex,
    'anon_address': addr,
}
json.dump(alt, open(sys.argv[2],'w'))
" "$TMP/keys.json" "$TMP/key_a_alt.json"

echo "=== 1. Global help mentions sign-anon-tx ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "sign-anon-tx"; then
  echo "  PASS: help mentions sign-anon-tx"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing sign-anon-tx"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. sign-anon-tx --help exits 0 ==="
set +e
"$WALLET" sign-anon-tx --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "sign-anon-tx --help exits 0"

echo
echo "=== 3. Missing --keyfile: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --to "$ADDR_B" --amount 100 --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --keyfile returns 1"

echo
echo "=== 4. Missing --to: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --amount 100 --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --to returns 1"

echo
echo "=== 5. Missing --amount: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --amount returns 1"

echo
echo "=== 6. Missing --fee: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 100 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --fee returns 1"

echo
echo "=== 7. Missing --nonce: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 100 --fee 1 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --nonce returns 1"

echo
echo "=== 8. Missing both --out and --allow-stdout: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 100 --fee 1 --nonce 0 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --out without --allow-stdout returns 1"

echo
echo "=== 9. --keyfile nonexistent file: exit 1 ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/nonexistent.json" --to "$ADDR_B" --amount 100 --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--keyfile nonexistent returns 1"

echo
echo "=== 10. --amount 0: exit 1 (validation rejects) ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 0 --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--amount 0 returns 1"

echo
echo "=== 11. --amount negative: exit 1 (parse rejects) ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount -5 --fee 1 --nonce 0 --out "$TMP/sig.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "--amount -5 returns 1"

echo
echo "=== 12. Happy path (canonical keyfile, --out): exit 0 ==="
set +e
OUT=$("$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 1000 --fee 5 --nonce 1 --out "$TMP/signed1.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "happy path returns 0"

echo
echo "=== 13. Output file created at requested path ==="
if [ -f "$TMP/signed1.json" ]; then
  echo "  PASS: signed1.json exists"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: signed1.json missing"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 14. Status JSON on stdout has status=ok ==="
STATUS=$(echo "$OUT" | tail -n 1 | $PY -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "parse_failed")
assert_eq "$STATUS" "ok" "status field is ok"

echo
echo "=== 15. Status JSON carries tx_hash_hex (64 hex chars) ==="
TX_HASH=$(echo "$OUT" | tail -n 1 | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])" 2>/dev/null || echo "")
LEN=${#TX_HASH}
assert_eq "$LEN" "64" "tx_hash_hex is 64 hex chars"

echo
echo "=== 16. Signed JSON has all expected fields ==="
MISSING=$($PY -c "
import json
d = json.load(open('$TMP/signed1.json'))
need = ['type','from','to','amount','fee','nonce','payload','signature','hash']
miss = [k for k in need if k not in d]
print(','.join(miss))
")
assert_eq "$MISSING" "" "all required fields present in signed JSON"

echo
echo "=== 17. type field is upper-case TRANSFER mnemonic ==="
TYPE_FIELD=$($PY -c "import json; print(json.load(open('$TMP/signed1.json'))['type'])")
assert_eq "$TYPE_FIELD" "TRANSFER" "type field is TRANSFER"

echo
echo "=== 18. signature field is exactly 128 hex chars ==="
SIG_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/signed1.json'))['signature']))")
assert_eq "$SIG_LEN" "128" "signature is 128 hex chars"

echo
echo "=== 19. hash field is exactly 64 hex chars ==="
HASH_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/signed1.json'))['hash']))")
assert_eq "$HASH_LEN" "64" "hash is 64 hex chars"

echo
echo "=== 20. from field matches the keyfile address ==="
FROM_FIELD=$($PY -c "import json; print(json.load(open('$TMP/signed1.json'))['from'])")
assert_eq "$FROM_FIELD" "$ADDR_A" "from matches keyfile address"

echo
echo "=== 21. amount/fee/nonce echoed verbatim from CLI flags ==="
ECHO_OK=$($PY -c "
import json
d = json.load(open('$TMP/signed1.json'))
ok = (d['amount']==1000 and d['fee']==5 and d['nonce']==1 and d['to']=='$ADDR_B' and d['payload']=='')
print('yes' if ok else 'no')
")
assert_eq "$ECHO_OK" "yes" "tx body fields echoed verbatim"

echo
echo "=== 22. S-028: --to with uppercase hex digits is rejected ==="
# Build an uppercase version of ADDR_B (preserve the 0x prefix lowercase).
ADDR_B_UPPER=$($PY -c "
addr = '$ADDR_B'
print('0x' + addr[2:].upper())
")
set +e
STDERR_OUT=$("$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B_UPPER" --amount 100 --fee 1 --nonce 2 --out "$TMP/sig_upper.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "S-028: uppercase --to rejected"
assert_contains "$STDERR_OUT" "S-028" "diagnostic cites S-028"

echo
echo "=== 23. S-028: --keyfile with uppercase-hex address is rejected ==="
$PY -c "
import json
d = json.load(open('$TMP/key_a.json'))
d['address'] = '0x' + d['address'][2:].upper()
json.dump(d, open('$TMP/key_a_upper.json','w'))
"
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a_upper.json" --to "$ADDR_B" --amount 100 --fee 1 --nonce 2 --out "$TMP/sig_keyup.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "S-028: uppercase keyfile.address rejected"

echo
echo "=== 24. Alternate keyfile shape (ed_priv_hex/ed_pub_hex/anon_address) signs OK ==="
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a_alt.json" --to "$ADDR_B" --amount 250 --fee 2 --nonce 3 --out "$TMP/signed_alt.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "alternate keyfile shape signs"
# And the alt-shape sig must equal the canonical-shape sig over the same body
# (Ed25519 deterministic): produce canonical-shape sig over an identical body.
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 250 --fee 2 --nonce 3 --out "$TMP/signed_canon.json" >/dev/null 2>&1
SIG_ALT=$($PY -c "import json; print(json.load(open('$TMP/signed_alt.json'))['signature'])")
SIG_CAN=$($PY -c "import json; print(json.load(open('$TMP/signed_canon.json'))['signature'])")
assert_eq "$SIG_ALT" "$SIG_CAN" "alt-shape sig == canonical-shape sig (Ed25519 deterministic)"

echo
echo "=== 25. --allow-stdout opt-in: exit 0 ==="
set +e
STDOUT_BLOB=$("$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" --amount 42 --fee 0 --nonce 7 --allow-stdout 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "0" "--allow-stdout returns 0"

echo
echo "=== 26. Stdout-emitted envelope parses + has 128-hex signature ==="
STDOUT_SIG=$(echo "$STDOUT_BLOB" | $PY -c "
import json, sys
d = json.loads(sys.stdin.read().strip())
print(len(d['signature']))
" 2>/dev/null || echo "parse_failed")
assert_eq "$STDOUT_SIG" "128" "stdout envelope signature is 128 hex chars"

echo
echo "=== 27. Sibling verifier accepts produced signature (shim transform) ==="
# tx-sign-verify expects numeric type=0 + field name 'sig'. Transform.
$PY -c "
import json
d = json.load(open('$TMP/signed1.json'))
out = dict(d)
out['type'] = 0
out['sig'] = d['signature']
json.dump(out, open('$TMP/signed_for_verify.json','w'))
"
set +e
"$WALLET" tx-sign-verify --tx "$TMP/signed_for_verify.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-sign-verify accepts sign-anon-tx envelope"

echo
echo "=== 28. Keyfile priv/address mismatch: exit 1 ==="
# Build a keyfile whose privkey_hex stays valid but address belongs to another
# account — the integrity check (address must derive from priv) must reject.
$PY -c "
import json
d = json.load(open('$TMP/key_a.json'))
d['address'] = '$ADDR_B'
json.dump(d, open('$TMP/key_a_swapaddr.json','w'))
"
set +e
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a_swapaddr.json" --to "$ADDR_B" --amount 100 --fee 1 --nonce 5 --out "$TMP/sig_mismatch.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "keyfile priv/address mismatch returns 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet sign-anon-tx"; exit 0
else
    echo "  FAIL: test_wallet_sign_anon_tx"; exit 1
fi
