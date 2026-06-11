#!/usr/bin/env bash
# determ-wallet account-import operator-workflow CLI test.
#
# Verifies the import workflow that converts a pre-existing Ed25519 private
# key (32-byte seed OR 64-byte seed||pubkey) into the wallet's anon-account
# JSON shape. Companion to account-create-batch (which generates fresh keys);
# account-import accepts keys recovered via Shamir, migrated from another
# wallet, or pinned for deterministic test fixtures.
#
# Assertions:
#   1. Help line mentions account-import.
#   2. 32-byte seed form (64 hex) produces address+privkey_hex on stdout (default).
#   3. 32-byte seed form with --json emits a JSON object {address, privkey_hex}.
#   4. Round-trip via account-create-batch: generate a key, re-import its
#      privkey_hex, verify the imported record's address matches exactly.
#   5. 64-byte form (seed||pubkey, 128 hex) — privkey emitted is the 32-byte
#      seed only (NOT the 128 hex string), address matches the seed-derived one.
#   6. 64-byte form with MISMATCHED pubkey rejected (rc=1), diagnostic mentions
#      "mismatch".
#   7. Determinism: same seed -> same address + privkey_hex (two calls).
#   8. --out file written; stdout shows "imported account: 0x...".
#   9. --out file contents are valid JSON with exactly the expected fields.
#  10. --out parent dir missing -> rc=1, diagnostic mentions parent directory.
#  11. --out file exists without --force -> rc=1, diagnostic mentions --force.
#  12. --out file exists with --force -> succeeds, file overwritten.
#  13. --priv missing -> rc=1 with usage.
#  14. --priv with non-hex chars -> rc=1, diagnostic mentions hex.
#  15. --priv wrong length (e.g., 60 hex) -> rc=1, diagnostic mentions allowed lengths.
#  16. --priv length 0 (--priv "") -> rc=1.
#  17. Unknown argument -> rc=1.
#  18. Output privkey_hex matches the input seed when 32-byte form supplied.
#  19. Output address shape matches anon-address: 0x + 64 lowercase hex.
#  20. JSON output (no --out) does NOT print the "imported account:" line
#      (that's only for --out mode).
#  21. With --out the JSON file content is the single-account object (no
#      "accounts" array wrapper — that's account-create-batch's shape).
#  22. Importing two different seeds produces two different addresses.
#  23. --priv 65 hex chars (odd intermediate length) rejected.
#  24. --priv 130 hex chars (too long) rejected.
#  25. Round-trip from --json -> file -> read back -> address/privkey match
#      the in-memory value.
#  26. With --json AND --out, --out takes priority (matches account-create-batch).
#
# Run from repo root: bash tools/test_wallet_account_import.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch directory so concurrent runs don't collide.
TMP="$(mktemp -d)"
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
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions account-import ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-import"; then
  echo "  PASS: help mentions account-import"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing account-import"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Setup: generate a known keypair via account-create-batch ==="
# Use the existing account-create-batch CLI to mint one fresh keypair we
# can then re-import. This exercises the full round-trip path: generate
# (account-create-batch) -> capture privkey (jq/python) -> import
# (account-import) -> verify address matches.
"$WALLET" account-create-batch --count 1 --out "$TMP/seed_key.json" >/dev/null 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
    echo "  FAIL: account-create-batch setup failed (rc=$RC)"; fail_count=$((fail_count + 1))
fi
SEED_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/seed_key.json")
SEED_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/seed_key.json")
echo "  setup: SEED_ADDR=$SEED_ADDR"
echo "  setup: SEED_PRIV=<64 hex>"

echo
echo "=== 2. 32-byte seed form: default human output ==="
OUT=$("$WALLET" account-import --priv "$SEED_PRIV" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on 32-byte seed import"
assert_contains "$OUT" "address:"     "stdout has address: label"
assert_contains "$OUT" "privkey_hex:" "stdout has privkey_hex: label"
assert_contains "$OUT" "$SEED_ADDR"   "stdout shows the expected anon-address"
assert_contains "$OUT" "$SEED_PRIV"   "stdout shows the expected privkey_hex"

echo
echo "=== 3. --json form: emits single JSON object ==="
JSON_OUT=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on --json import"
JSON_ADDR=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
JSON_PRIV=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['privkey_hex'])")
assert_eq "$JSON_ADDR" "$SEED_ADDR" "JSON address matches batch-generated address"
assert_eq "$JSON_PRIV" "$SEED_PRIV" "JSON privkey_hex matches input seed"

echo
echo "=== 4. Round-trip determinism: same seed -> same address ==="
OUT_A=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
OUT_B=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
if [ "$OUT_A" = "$OUT_B" ]; then
    echo "  PASS: two imports of same seed produce identical JSON"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: identical seeds produced different JSON"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 5. 64-byte form (seed||pubkey): same address, privkey_hex is the seed ==="
# Build the 128-hex form by concatenating the 32-byte seed and the 32-byte
# pubkey (= address minus "0x" prefix).
SEED_PUB_HEX=${SEED_ADDR#0x}
KEYPAIR_HEX="${SEED_PRIV}${SEED_PUB_HEX}"
KP_LEN=${#KEYPAIR_HEX}
assert_eq "$KP_LEN" "128" "constructed keypair hex is 128 chars long"
JSON_OUT=$("$WALLET" account-import --priv "$KEYPAIR_HEX" --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on 64-byte form import"
KP_ADDR=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
KP_PRIV=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['privkey_hex'])")
assert_eq "$KP_ADDR" "$SEED_ADDR" "64-byte form: address matches seed-derived address"
assert_eq "$KP_PRIV" "$SEED_PRIV" "64-byte form: privkey_hex is the 32-byte seed (not 128 hex)"
PRIV_LEN=${#KP_PRIV}
assert_eq "$PRIV_LEN" "64" "64-byte form: emitted privkey_hex is exactly 64 chars"

echo
echo "=== 6. 64-byte form with MISMATCHED pubkey rejected ==="
# Flip a byte in the pubkey portion -> derived pubkey won't match supplied.
# Replace the FIRST hex digit of the pubkey portion with '0' (or '1' if
# already '0'). This guarantees a mismatch without touching the seed.
FIRST_PUB_CHAR="${SEED_PUB_HEX:0:1}"
if [ "$FIRST_PUB_CHAR" = "0" ]; then
    NEW_FIRST="1"
else
    NEW_FIRST="0"
fi
BAD_PUB="${NEW_FIRST}${SEED_PUB_HEX:1}"
BAD_KEYPAIR_HEX="${SEED_PRIV}${BAD_PUB}"
set +e
ERR=$("$WALLET" account-import --priv "$BAD_KEYPAIR_HEX" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on mismatched 64-byte form"
assert_contains "$ERR" "mismatch" "diagnostic mentions 'mismatch'"

echo
echo "=== 7. Determinism (already covered in 4); spot-check across forms ==="
# 32-byte and 64-byte forms of the SAME key should produce identical output.
OUT_32=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
OUT_64=$("$WALLET" account-import --priv "$KEYPAIR_HEX" --json | tr -d '\r')
if [ "$OUT_32" = "$OUT_64" ]; then
    echo "  PASS: 32-byte and 64-byte forms of same key produce identical JSON"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: 32-byte vs 64-byte forms differ"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 8. --out writes file; stdout shows 'imported account: 0x...' ==="
"$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/imported.json" > "$TMP/stdout_imp.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --out"
STDOUT=$(cat "$TMP/stdout_imp.txt" | tr -d '\r')
assert_contains "$STDOUT" "imported account:" "stdout starts with 'imported account:'"
assert_contains "$STDOUT" "$SEED_ADDR"        "stdout shows the imported address"
if [ -s "$TMP/imported.json" ]; then
    echo "  PASS: --out file is non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file empty"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 9. --out file contents: valid JSON, single-account shape ==="
FILE_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])"     "$TMP/imported.json")
FILE_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['privkey_hex'])" "$TMP/imported.json")
assert_eq "$FILE_ADDR" "$SEED_ADDR" "--out file address matches input"
assert_eq "$FILE_PRIV" "$SEED_PRIV" "--out file privkey_hex matches input"

echo
echo "=== 10. --out with missing parent directory fails ==="
set +e
ERR=$("$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/no_such_dir/x.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out with missing parent dir"
assert_contains "$ERR" "parent directory" "diagnostic mentions parent directory"

echo
echo "=== 11. --out with existing file refused without --force ==="
# $TMP/imported.json was written in step 8.
set +e
ERR=$("$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/imported.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out with existing file (no --force)"
assert_contains "$ERR" "already exists" "diagnostic mentions file exists"
assert_contains "$ERR" "--force"        "diagnostic suggests --force"

echo
echo "=== 12. --force overrides existing file ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/other_key.json" >/dev/null 2>&1
OTHER_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/other_key.json")
OTHER_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/other_key.json")
"$WALLET" account-import --priv "$OTHER_PRIV" --out "$TMP/imported.json" --force > "$TMP/force_stdout.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --force overwrite"
NEW_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/imported.json")
assert_eq "$NEW_ADDR" "$OTHER_ADDR" "after --force, file holds the new address"

echo
echo "=== 13. --priv missing fails ==="
set +e
ERR=$("$WALLET" account-import 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --priv"
assert_contains "$ERR" "priv" "diagnostic mentions priv"

echo
echo "=== 14. --priv non-hex chars rejected ==="
# 64 chars but with non-hex characters.
BAD_HEX="zz$(printf '%062s' '' | tr ' ' '0')"
BAD_LEN=${#BAD_HEX}
assert_eq "$BAD_LEN" "64" "constructed non-hex string is 64 chars (length check passes; hex check fails)"
set +e
ERR=$("$WALLET" account-import --priv "$BAD_HEX" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex --priv"
assert_contains "$ERR" "hex" "diagnostic mentions hex"

echo
echo "=== 15. --priv wrong length (60 hex chars) rejected ==="
SHORT_HEX=$(printf '%060s' '' | tr ' ' '0')
set +e
ERR=$("$WALLET" account-import --priv "$SHORT_HEX" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on wrong-length --priv (60 hex)"
assert_contains "$ERR" "64" "diagnostic mentions 64 (the 32-byte form)"
assert_contains "$ERR" "128" "diagnostic mentions 128 (the 64-byte form)"

echo
echo "=== 16. --priv empty string rejected ==="
set +e
ERR=$("$WALLET" account-import --priv "" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty --priv"

echo
echo "=== 17. Unknown argument rejected ==="
set +e
"$WALLET" account-import --priv "$SEED_PRIV" --bogus-flag >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on unknown argument"

echo
echo "=== 18. Output privkey_hex is the 32-byte seed (not derived 64-byte sk) ==="
JSON_OUT=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
EMITTED_PRIV=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['privkey_hex'])")
EMITTED_LEN=${#EMITTED_PRIV}
assert_eq "$EMITTED_LEN" "64" "emitted privkey_hex is 64 hex chars (32 bytes, not 64)"
assert_eq "$EMITTED_PRIV" "$SEED_PRIV" "emitted privkey_hex equals the input seed verbatim"

echo
echo "=== 19. Address shape matches anon-address (0x + 64 lowercase hex) ==="
echo "$JSON_OUT" | $PY -c "
import json, sys, re
addr = json.load(sys.stdin)['address']
if not re.match(r'^0x[0-9a-f]{64}\$', addr):
    print('BAD_SHAPE')
    sys.exit(1)
print('OK')
"
RC=$?
assert_eq "$RC" "0" "address matches /^0x[0-9a-f]{64}$/"

echo
echo "=== 20. --json (no --out) does NOT print 'imported account:' line ==="
JSON_RAW=$("$WALLET" account-import --priv "$SEED_PRIV" --json 2>&1 | tr -d '\r')
assert_not_contains "$JSON_RAW" "imported account:" "--json stdout is pure JSON (no human-mode label)"

echo
echo "=== 21. --out file is the single-account object (no 'accounts' array wrapper) ==="
# account-create-batch wraps in {"accounts":[...]}; account-import does NOT
# because a single account doesn't need a list wrapper.
"$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/single.json" --force >/dev/null 2>&1
HAS_ACCOUNTS_KEY=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print('YES' if 'accounts' in d else 'NO')" "$TMP/single.json")
assert_eq "$HAS_ACCOUNTS_KEY" "NO" "--out file does NOT have an 'accounts' wrapper key"
HAS_ADDR=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print('YES' if 'address' in d else 'NO')" "$TMP/single.json")
assert_eq "$HAS_ADDR" "YES" "--out file has top-level 'address' key"

echo
echo "=== 22. Different seeds produce different addresses ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/k2.json" >/dev/null 2>&1
"$WALLET" account-create-batch --count 1 --out "$TMP/k3.json" >/dev/null 2>&1
PRIV2=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/k2.json")
PRIV3=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/k3.json")
ADDR2=$("$WALLET" account-import --priv "$PRIV2" --json | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
ADDR3=$("$WALLET" account-import --priv "$PRIV3" --json | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
if [ "$ADDR2" != "$ADDR3" ]; then
    echo "  PASS: distinct seeds yield distinct addresses"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: two different seeds produced the same address (collision)"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 23. --priv 65 hex chars (odd intermediate length) rejected ==="
ODD_HEX="${SEED_PRIV}a"
ODD_LEN=${#ODD_HEX}
assert_eq "$ODD_LEN" "65" "constructed odd-length hex is 65 chars"
set +e
"$WALLET" account-import --priv "$ODD_HEX" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on 65-char --priv (must be 64 or 128)"

echo
echo "=== 24. --priv 130 hex chars (over 64-byte form) rejected ==="
LONG_HEX="${KEYPAIR_HEX}aa"
LONG_LEN=${#LONG_HEX}
assert_eq "$LONG_LEN" "130" "constructed too-long hex is 130 chars"
set +e
"$WALLET" account-import --priv "$LONG_HEX" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on 130-char --priv"

echo
echo "=== 25. Round-trip: --json output reparsed equals --out file content ==="
JSON_STDOUT=$("$WALLET" account-import --priv "$SEED_PRIV" --json | tr -d '\r')
"$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/rt.json" --force >/dev/null 2>&1
JSON_FROM_FILE=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d, sort_keys=True))" "$TMP/rt.json")
JSON_FROM_STDOUT=$(echo "$JSON_STDOUT" | $PY -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d, sort_keys=True))")
assert_eq "$JSON_FROM_FILE" "$JSON_FROM_STDOUT" "--json stdout and --out file represent the same JSON object"

echo
echo "=== 26. --json AND --out: --out path wins (no JSON to stdout) ==="
"$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/both.json" --json --force > "$TMP/both_stdout.txt" 2>&1
RC=$?
STDOUT=$(cat "$TMP/both_stdout.txt" | tr -d '\r')
assert_eq "$RC" "0" "exit 0 on --out + --json"
assert_contains "$STDOUT" "imported account:"   "stdout has 'imported account:' (--out path won)"
assert_not_contains "$STDOUT" '"privkey_hex"'   "stdout does NOT contain JSON document (--out won)"
# File is the single-account JSON, valid.
FILE_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/both.json")
assert_eq "$FILE_ADDR" "$SEED_ADDR" "--out file contains the expected address"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-import"; exit 0
else
    echo "  FAIL: test_wallet_account_import"; exit 1
fi
