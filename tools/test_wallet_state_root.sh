#!/usr/bin/env bash
# determ-wallet param-change-build CLI test.
#
# NOTE on the file name: this wrapper is named test_wallet_state_root.sh for
# orchestration reasons, but it exercises the `param-change-build` subcommand.
# Rationale (recorded in the agent report): the originally-scoped deliverable
# was a wallet `state-root --snapshot` command that recomputes a snapshot's
# committed state_root offline. On survey, the EXISTING `snapshot-verify`
# subcommand already does exactly that (reads a snapshot JSON, drives the
# chain's restore_from_snapshot + compute_state_root via the sanctioned
# `determ snapshot inspect` subprocess, and prints state_root + block_index +
# head_hash in both human and --json form). The wallet binary intentionally
# does NOT link the chain library (TCB separation — see wallet/main.cpp top
# comment + CMakeLists.txt: determ-wallet links only crypto/sodium/json), so a
# direct in-process compute_state_root() is architecturally impossible without
# breaching that boundary. Per the task's explicit fallback, this lane instead
# ships `param-change-build`.
#
# What param-change-build does: OFFLINE constructor for a canonical A5
# governance PARAM_CHANGE transaction body. It assembles the PARAM_CHANGE
# payload + the chain's canonical Transaction::signing_bytes (src/chain/
# block.cpp), computes tx_hash = SHA-256(signing_bytes), and emits the UNSIGNED
# canonical tx JSON (numeric type=6) ready for the K-of-K keyholder multisig to
# be appended out-of-band. Pure offline — no RPC, no secret material.
#
# Assertions (~26):
#   1.  Global help mentions param-change-build.
#   2.  param-change-build --help exits 0.
#   3.  Missing --name: exit 1.
#   4.  Missing --effective-height: exit 1.
#   5.  Missing --nonce: exit 1.
#   6.  Missing --from: exit 1.
#   7.  Missing both --value and --value-hex: exit 1.
#   8.  Both --value and --value-hex: exit 1 (mutually exclusive).
#   9.  Off-whitelist --name: exit 1.
#  10.  Missing both --out and --allow-stdout: exit 1.
#  11.  Happy path (--value, --out): exit 0.
#  12.  Output file created at requested path.
#  13.  Status JSON on stdout has status=ok.
#  14.  Status JSON carries tx_hash_hex (64 hex chars).
#  15.  Tx JSON has all expected fields.
#  16.  type field is numeric 6.
#  17.  type_name is PARAM_CHANGE.
#  18.  sig field is exactly 128 zero-hex chars (unsigned placeholder).
#  19.  hash field is exactly 64 hex chars.
#  20.  to is empty, amount is 0 (governance tx).
#  21.  --value 5000 → 8-byte LE value_hex == "8813000000000000".
#  22.  sig_count is 0; payload last byte (sig_count) is 0x00.
#  23.  Independent cross-check: derive-tx-hash --check reports match
#       (signing_bytes/hash byte-for-byte == chain Transaction encoder).
#  24.  Deterministic: same inputs → identical hash on a second build.
#  25.  --value-hex path produces value_hex verbatim.
#  26.  S-028: anon-shape --from with uppercase hex is rejected (exit 1).
#  27.  --allow-stdout opt-in: tx JSON on stdout, exit 0, parses.
#
# Run from repo root: bash tools/test_wallet_state_root.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="build/test_wallet_state_root.$$"
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

FROM="example-validator.determ"

echo "=== 1. Global help mentions param-change-build ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "param-change-build"; then
  echo "  PASS: help mentions param-change-build"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing param-change-build"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. param-change-build --help exits 0 ==="
set +e
"$WALLET" param-change-build --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "param-change-build --help exits 0"

echo
echo "=== 3. Missing --name: exit 1 ==="
set +e
"$WALLET" param-change-build --value 5000 --effective-height 100 --nonce 1 --from "$FROM" --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --name returns 1"

echo
echo "=== 4. Missing --effective-height: exit 1 ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --nonce 1 --from "$FROM" --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --effective-height returns 1"

echo
echo "=== 5. Missing --nonce: exit 1 ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --from "$FROM" --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --nonce returns 1"

echo
echo "=== 6. Missing --from: exit 1 ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --nonce 1 --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --from returns 1"

echo
echo "=== 7. Missing both --value and --value-hex: exit 1 ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --effective-height 100 --nonce 1 --from "$FROM" --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing value returns 1"

echo
echo "=== 8. Both --value and --value-hex: exit 1 (mutually exclusive) ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --value-hex 8813000000000000 --effective-height 100 --nonce 1 --from "$FROM" --out "$TMP/x.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "value + value-hex returns 1"

echo
echo "=== 9. Off-whitelist --name: exit 1 ==="
set +e
STDERR_OUT=$("$WALLET" param-change-build --name NOT_A_REAL_PARAM --value 5000 --effective-height 100 --nonce 1 --from "$FROM" --out "$TMP/x.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "off-whitelist --name returns 1"
assert_contains "$STDERR_OUT" "whitelist" "diagnostic cites whitelist"

echo
echo "=== 10. Missing both --out and --allow-stdout: exit 1 ==="
set +e
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --nonce 1 --from "$FROM" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "missing --out without --allow-stdout returns 1"

echo
echo "=== 11. Happy path (--value, --out): exit 0 ==="
set +e
OUT=$("$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --nonce 1 --fee 2 --from "$FROM" --out "$TMP/pc1.json" 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "happy path returns 0"

echo
echo "=== 12. Output file created at requested path ==="
if [ -f "$TMP/pc1.json" ]; then
  echo "  PASS: pc1.json exists"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: pc1.json missing"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 13. Status JSON on stdout has status=ok ==="
STATUS=$(echo "$OUT" | tail -n 1 | $PY -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "parse_failed")
assert_eq "$STATUS" "ok" "status field is ok"

echo
echo "=== 14. Status JSON carries tx_hash_hex (64 hex chars) ==="
TX_HASH=$(echo "$OUT" | tail -n 1 | $PY -c "import json,sys; print(json.load(sys.stdin)['tx_hash_hex'])" 2>/dev/null || echo "")
LEN=${#TX_HASH}
assert_eq "$LEN" "64" "tx_hash_hex is 64 hex chars"

echo
echo "=== 15. Tx JSON has all expected fields ==="
MISSING=$($PY -c "
import json
d = json.load(open('$TMP/pc1.json'))
need = ['type','type_name','from','to','amount','fee','nonce','payload','sig','hash','param_name','value_hex','effective_height','sig_count','keyholder_sig_message_hex']
miss = [k for k in need if k not in d]
print(','.join(miss))
")
assert_eq "$MISSING" "" "all required fields present in tx JSON"

echo
echo "=== 16. type field is numeric 6 ==="
TYPE_FIELD=$($PY -c "import json; print(json.load(open('$TMP/pc1.json'))['type'])")
assert_eq "$TYPE_FIELD" "6" "type field is 6"

echo
echo "=== 17. type_name is PARAM_CHANGE ==="
TYPE_NAME=$($PY -c "import json; print(json.load(open('$TMP/pc1.json'))['type_name'])")
assert_eq "$TYPE_NAME" "PARAM_CHANGE" "type_name is PARAM_CHANGE"

echo
echo "=== 18. sig field is exactly 128 zero-hex chars (unsigned placeholder) ==="
SIG_OK=$($PY -c "
import json
s = json.load(open('$TMP/pc1.json'))['sig']
print('yes' if (len(s)==128 and set(s)=={'0'}) else 'no')
")
assert_eq "$SIG_OK" "yes" "sig is 128 zero-hex chars"

echo
echo "=== 19. hash field is exactly 64 hex chars ==="
HASH_LEN=$($PY -c "import json; print(len(json.load(open('$TMP/pc1.json'))['hash']))")
assert_eq "$HASH_LEN" "64" "hash is 64 hex chars"

echo
echo "=== 20. to is empty + amount is 0 (governance tx) ==="
GOV_OK=$($PY -c "
import json
d = json.load(open('$TMP/pc1.json'))
print('yes' if (d['to']=='' and d['amount']==0 and d['fee']==2 and d['nonce']==1) else 'no')
")
assert_eq "$GOV_OK" "yes" "to empty, amount 0, fee/nonce echoed"

echo
echo "=== 21. --value 5000 → 8-byte LE value_hex == 8813000000000000 ==="
VALUE_HEX=$($PY -c "import json; print(json.load(open('$TMP/pc1.json'))['value_hex'])")
assert_eq "$VALUE_HEX" "8813000000000000" "value_hex is 8-byte LE of 5000"

echo
echo "=== 22. sig_count is 0 + payload tail byte is 00 ==="
SIGC_OK=$($PY -c "
import json
d = json.load(open('$TMP/pc1.json'))
pay = d['payload']
print('yes' if (d['sig_count']==0 and pay[-2:]=='00') else 'no')
")
assert_eq "$SIGC_OK" "yes" "sig_count 0 + payload ends in 00"

echo
echo "=== 23. Independent cross-check: derive-tx-hash --check reports match ==="
# derive-tx-hash builds signing_bytes byte-for-byte == chain Transaction
# encoder. Feeding our built tx back through it with --check independently
# validates both the payload encoding and the SHA-256 hash.
set +e
DTH=$("$WALLET" derive-tx-hash --tx-json "$TMP/pc1.json" --check --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "derive-tx-hash --check exits 0 (hash matches)"
MATCH=$(echo "$DTH" | $PY -c "import json,sys; print(json.load(sys.stdin)['match'])" 2>/dev/null || echo "parse_failed")
assert_eq "$MATCH" "True" "derive-tx-hash reports match=true"

echo
echo "=== 24. Deterministic: same inputs → identical hash ==="
"$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --nonce 1 --fee 2 --from "$FROM" --out "$TMP/pc1b.json" >/dev/null 2>&1
HASH_A=$($PY -c "import json; print(json.load(open('$TMP/pc1.json'))['hash'])")
HASH_B=$($PY -c "import json; print(json.load(open('$TMP/pc1b.json'))['hash'])")
assert_eq "$HASH_A" "$HASH_B" "identical inputs produce identical hash"

echo
echo "=== 25. --value-hex path produces value_hex verbatim ==="
"$WALLET" param-change-build --name param_keyholders --value-hex deadbeef --effective-height 200 --nonce 3 --from "$FROM" --out "$TMP/pc_hex.json" >/dev/null 2>&1
VHEX=$($PY -c "import json; print(json.load(open('$TMP/pc_hex.json'))['value_hex'])")
assert_eq "$VHEX" "deadbeef" "value_hex passthrough verbatim"

echo
echo "=== 26. S-028: anon-shape --from with uppercase hex rejected ==="
ANON_UPPER="0x$($PY -c "print('A'*64)")"
set +e
STDERR2=$("$WALLET" param-change-build --name MIN_STAKE --value 5000 --effective-height 100 --nonce 1 --from "$ANON_UPPER" --out "$TMP/pc_anon.json" 2>&1 1>/dev/null)
RC=$?
set -e
assert_eq "$RC" "1" "uppercase anon --from rejected"
assert_contains "$STDERR2" "S-028" "diagnostic cites S-028"

echo
echo "=== 27. --allow-stdout opt-in: tx JSON on stdout, exit 0, parses ==="
set +e
STDOUT_BLOB=$("$WALLET" param-change-build --name UNSTAKE_DELAY --value 50 --effective-height 300 --nonce 7 --from "$FROM" --allow-stdout 2>/dev/null)
RC=$?
set -e
assert_eq "$RC" "0" "--allow-stdout returns 0"
STDOUT_TYPE=$(echo "$STDOUT_BLOB" | $PY -c "import json,sys; print(json.loads(sys.stdin.read().strip())['type'])" 2>/dev/null || echo "parse_failed")
assert_eq "$STDOUT_TYPE" "6" "stdout tx JSON parses with type=6"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet param-change-build"; exit 0
else
    echo "  FAIL: test_wallet_state_root"; exit 1
fi
