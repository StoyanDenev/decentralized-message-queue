#!/usr/bin/env bash
# determ-wallet account-export operator-workflow CLI test.
#
# Verifies the export workflow that re-emits a wallet account file in one of
# three external formats: raw-hex (default), json (passthrough), and
# backup-bundle (envelope-ready JSON for backup-create --secret).
#
# Counterpart to account-create-batch / account-import / account-recover: those
# CLIs produce the canonical wallet account shape; account-export converts that
# shape into an external format. The round-trip raw-hex -> account-import is
# the canonical sanity check that the seed-to-address derivation is invariant
# across the export path.
#
# Assertions (~25):
#   1. Help line mentions account-export.
#   2. Setup: account-create-batch generates a known keypair.
#   3. Default format (raw-hex, no --format) emits the 64-hex privkey on stdout.
#   4. --format raw-hex with --json wraps in {"privkey_hex":"..."}.
#   5. --format json passthrough emits valid JSON object with address+privkey_hex.
#   6. --format backup-bundle emits JSON with seed_hex, pubkey_hex, anon_address,
#      derived_at_utc fields.
#   7. backup-bundle: seed_hex equals the input privkey_hex.
#   8. backup-bundle: pubkey_hex equals address minus "0x" prefix.
#   9. backup-bundle: anon_address equals the input address.
#  10. backup-bundle: derived_at_utc matches ISO-8601 pattern.
#  11. Round-trip: account-export raw-hex output, fed to account-import --priv,
#      yields the same address.
#  12. --out writes to file; stdout shows "exported <format>: <path>".
#  13. --out file with raw-hex contains the privkey hex (file integrity).
#  14. --out file with backup-bundle contains valid JSON bundle.
#  15. --out parent dir missing -> rc=1, mentions parent directory.
#  16. --out file exists without --force -> rc=1, mentions --force.
#  17. --out file exists with --force -> succeeds, file overwritten.
#  18. --in missing -> rc=1.
#  19. --in non-existent file -> rc=1.
#  20. --in malformed JSON -> rc=1, diagnostic mentions JSON.
#  21. --in missing 'address' field -> rc=1.
#  22. --in missing 'privkey_hex' field -> rc=1.
#  23. --in address wrong shape (not 0x + 64 hex) -> rc=1.
#  24. --in privkey_hex wrong length -> rc=1.
#  25. Bad --format value -> rc=1, diagnostic mentions raw-hex|json|backup-bundle.
#  26. Unknown argument -> rc=1.
#  27. json passthrough: re-export preserves the canonical fields exactly.
#  28. raw-hex stdout has no trailing whitespace beyond the single LF.
#
# Run from repo root: bash tools/test_wallet_account_export.sh
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. Help text mentions account-export ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-export"; then
  echo "  PASS: help mentions account-export"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: help missing account-export"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 2. Setup: generate a known account via account-create-batch ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/batch.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-create-batch setup succeeded"
# Extract the single account into a standalone single-account JSON file
# (account-create-batch wraps in {"accounts":[...]}; account-export consumes
# the single-account shape that account-import/account-recover emit).
SEED_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/batch.json")
SEED_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/batch.json")
$PY -c "
import json, sys
acc = json.load(open(sys.argv[1]))['accounts'][0]
json.dump({'address': acc['address'], 'privkey_hex': acc['privkey_hex']},
          open(sys.argv[2], 'w'), indent=2)
" "$TMP/batch.json" "$TMP/acc.json"
echo "  setup: SEED_ADDR=$SEED_ADDR"

echo
echo "=== 3. Default format (raw-hex) emits 64-hex privkey on stdout ==="
OUT=$("$WALLET" account-export --in "$TMP/acc.json" | tr -d '\r\n')
RC=$?
assert_eq "$RC" "0" "exit 0 on default-format export"
OUT_LEN=${#OUT}
assert_eq "$OUT_LEN" "64" "raw-hex stdout is exactly 64 chars"
assert_eq "$OUT" "$SEED_PRIV" "raw-hex stdout equals input privkey_hex"

echo
echo "=== 4. --format raw-hex with --json wraps in JSON object ==="
JSON_RAW=$("$WALLET" account-export --in "$TMP/acc.json" --format raw-hex --json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on raw-hex --json"
J_PRIV=$(echo "$JSON_RAW" | $PY -c "import json,sys; print(json.load(sys.stdin)['privkey_hex'])")
assert_eq "$J_PRIV" "$SEED_PRIV" "JSON-wrapped raw-hex contains the same privkey_hex"

echo
echo "=== 5. --format json passthrough emits canonical account JSON ==="
JSON_OUT=$("$WALLET" account-export --in "$TMP/acc.json" --format json | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on --format json"
J_ADDR=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
J_PRIV=$(echo "$JSON_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['privkey_hex'])")
assert_eq "$J_ADDR" "$SEED_ADDR" "json passthrough preserves address"
assert_eq "$J_PRIV" "$SEED_PRIV" "json passthrough preserves privkey_hex"

echo
echo "=== 6. --format backup-bundle emits envelope-ready JSON ==="
BUNDLE=$("$WALLET" account-export --in "$TMP/acc.json" --format backup-bundle | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on --format backup-bundle"
B_SEED=$(echo "$BUNDLE" | $PY -c "import json,sys; print(json.load(sys.stdin)['seed_hex'])")
B_PUB=$( echo "$BUNDLE" | $PY -c "import json,sys; print(json.load(sys.stdin)['pubkey_hex'])")
B_ADDR=$(echo "$BUNDLE" | $PY -c "import json,sys; print(json.load(sys.stdin)['anon_address'])")
B_TS=$(  echo "$BUNDLE" | $PY -c "import json,sys; print(json.load(sys.stdin)['derived_at_utc'])")

echo
echo "=== 7. backup-bundle: seed_hex equals input privkey_hex ==="
assert_eq "$B_SEED" "$SEED_PRIV" "bundle seed_hex equals input privkey_hex"

echo
echo "=== 8. backup-bundle: pubkey_hex equals address minus 0x ==="
SEED_PUB_HEX=${SEED_ADDR#0x}
assert_eq "$B_PUB" "$SEED_PUB_HEX" "bundle pubkey_hex equals address hex body"

echo
echo "=== 9. backup-bundle: anon_address equals input address ==="
assert_eq "$B_ADDR" "$SEED_ADDR" "bundle anon_address equals input address"

echo
echo "=== 10. backup-bundle: derived_at_utc matches ISO-8601 pattern ==="
echo "$B_TS" | $PY -c "
import re, sys
ts = sys.stdin.read().strip()
if not re.match(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\$', ts):
    print('BAD_SHAPE:', ts)
    sys.exit(1)
print('OK')
"
RC=$?
assert_eq "$RC" "0" "derived_at_utc matches /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\$/"

echo
echo "=== 11. Round-trip: account-export raw-hex -> account-import yields same address ==="
EXPORTED_HEX=$("$WALLET" account-export --in "$TMP/acc.json" | tr -d '\r\n')
IMPORTED=$("$WALLET" account-import --priv "$EXPORTED_HEX" --json | tr -d '\r')
ROUND_ADDR=$(echo "$IMPORTED" | $PY -c "import json,sys; print(json.load(sys.stdin)['address'])")
assert_eq "$ROUND_ADDR" "$SEED_ADDR" "round-trip address matches original"

echo
echo "=== 12. --out writes to file; stdout shows 'exported <format>: <path>' ==="
"$WALLET" account-export --in "$TMP/acc.json" --format raw-hex --out "$TMP/exp.hex" > "$TMP/stdout12.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --out raw-hex"
STDOUT=$(cat "$TMP/stdout12.txt" | tr -d '\r')
assert_contains "$STDOUT" "exported raw-hex:" "stdout starts with 'exported raw-hex:'"
if [ -s "$TMP/exp.hex" ]; then
    echo "  PASS: --out file is non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file empty"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 13. --out raw-hex file contains the privkey hex ==="
FILE_HEX=$(cat "$TMP/exp.hex" | tr -d '\r\n')
assert_eq "$FILE_HEX" "$SEED_PRIV" "raw-hex file contents equal input privkey_hex"

echo
echo "=== 14. --out backup-bundle file is valid JSON bundle ==="
"$WALLET" account-export --in "$TMP/acc.json" --format backup-bundle --out "$TMP/bundle.json" > "$TMP/stdout14.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --out backup-bundle"
FILE_SEED=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['seed_hex'])"     "$TMP/bundle.json")
FILE_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['anon_address'])" "$TMP/bundle.json")
assert_eq "$FILE_SEED" "$SEED_PRIV" "--out bundle file seed_hex matches input"
assert_eq "$FILE_ADDR" "$SEED_ADDR" "--out bundle file anon_address matches input"

echo
echo "=== 15. --out with missing parent directory fails ==="
set +e
ERR=$("$WALLET" account-export --in "$TMP/acc.json" --out "$TMP/no_such_dir/x.hex" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out missing parent dir"
assert_contains "$ERR" "parent directory" "diagnostic mentions parent directory"

echo
echo "=== 16. --out with existing file refused without --force ==="
# $TMP/exp.hex was written in step 12.
set +e
ERR=$("$WALLET" account-export --in "$TMP/acc.json" --out "$TMP/exp.hex" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --out existing file (no --force)"
assert_contains "$ERR" "already exists" "diagnostic mentions file exists"
assert_contains "$ERR" "--force"        "diagnostic suggests --force"

echo
echo "=== 17. --force overrides existing file ==="
# Generate a different account, export to the SAME path with --force.
"$WALLET" account-create-batch --count 1 --out "$TMP/other_batch.json" >/dev/null 2>&1
$PY -c "
import json, sys
acc = json.load(open(sys.argv[1]))['accounts'][0]
json.dump({'address': acc['address'], 'privkey_hex': acc['privkey_hex']},
          open(sys.argv[2], 'w'), indent=2)
" "$TMP/other_batch.json" "$TMP/other_acc.json"
OTHER_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['privkey_hex'])" "$TMP/other_acc.json")
"$WALLET" account-export --in "$TMP/other_acc.json" --format raw-hex --out "$TMP/exp.hex" --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --force overwrite"
NEW_FILE_HEX=$(cat "$TMP/exp.hex" | tr -d '\r\n')
assert_eq "$NEW_FILE_HEX" "$OTHER_PRIV" "after --force, file holds the new privkey_hex"

echo
echo "=== 18. --in missing fails ==="
set +e
ERR=$("$WALLET" account-export 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in"
assert_contains "$ERR" "in" "diagnostic mentions --in"

echo
echo "=== 19. --in non-existent file fails ==="
set +e
ERR=$("$WALLET" account-export --in "$TMP/does_not_exist.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in file"
assert_contains "$ERR" "open" "diagnostic mentions cannot open"

echo
echo "=== 20. --in malformed JSON fails ==="
printf 'not-json{{{' > "$TMP/bad.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/bad.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on bad-JSON --in"
assert_contains "$ERR" "JSON" "diagnostic mentions JSON"

echo
echo "=== 21. --in missing 'address' field fails ==="
$PY -c "
import json, sys
json.dump({'privkey_hex': '$SEED_PRIV'}, open(sys.argv[1], 'w'))
" "$TMP/no_addr.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/no_addr.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when 'address' missing"
assert_contains "$ERR" "address" "diagnostic mentions address"

echo
echo "=== 22. --in missing 'privkey_hex' field fails ==="
$PY -c "
import json, sys
json.dump({'address': '$SEED_ADDR'}, open(sys.argv[1], 'w'))
" "$TMP/no_priv.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/no_priv.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when 'privkey_hex' missing"
assert_contains "$ERR" "privkey_hex" "diagnostic mentions privkey_hex"

echo
echo "=== 23. --in address wrong shape (no 0x prefix) fails ==="
$PY -c "
import json, sys
json.dump({'address': 'aabbccdd', 'privkey_hex': '$SEED_PRIV'}, open(sys.argv[1], 'w'))
" "$TMP/bad_addr.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/bad_addr.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed address"
assert_contains "$ERR" "address" "diagnostic mentions address"

echo
echo "=== 24. --in privkey_hex wrong length fails ==="
$PY -c "
import json, sys
json.dump({'address': '$SEED_ADDR', 'privkey_hex': 'aabbcc'}, open(sys.argv[1], 'w'))
" "$TMP/short_priv.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/short_priv.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on short privkey_hex"
assert_contains "$ERR" "privkey_hex" "diagnostic mentions privkey_hex"

echo
echo "=== 25. Bad --format value rejected ==="
set +e
ERR=$("$WALLET" account-export --in "$TMP/acc.json" --format wat 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on bad --format"
assert_contains "$ERR" "raw-hex" "diagnostic mentions raw-hex"
assert_contains "$ERR" "backup-bundle" "diagnostic mentions backup-bundle"

echo
echo "=== 26. Unknown argument rejected ==="
set +e
"$WALLET" account-export --in "$TMP/acc.json" --bogus-flag >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on unknown argument"

echo
echo "=== 27. json passthrough preserves canonical fields exactly ==="
# Re-export the json passthrough and check round-trip via Python JSON-equality.
JSON_OUT=$("$WALLET" account-export --in "$TMP/acc.json" --format json | tr -d '\r')
# Pass the source path as a positional arg so MSYS path translation kicks in
# (inline literals get $TMP-substituted by bash AS-IS, which Python on Windows
# can't open because the path is /tmp/tmp.XXXX-style instead of C:/...).
ROUND_EQ=$(echo "$JSON_OUT" | $PY -c "
import json, sys
out = json.load(sys.stdin)
src = json.load(open(sys.argv[1]))
keys = {'address', 'privkey_hex'}
ok = all(out.get(k) == src.get(k) for k in keys)
print('YES' if ok else 'NO')
" "$TMP/acc.json")
assert_eq "$ROUND_EQ" "YES" "json passthrough preserves address+privkey_hex exactly"

echo
echo "=== 28. raw-hex stdout has no excess whitespace ==="
# 64 hex chars + a single trailing LF == 65 bytes.
"$WALLET" account-export --in "$TMP/acc.json" > "$TMP/raw_stdout.txt" 2>/dev/null
LF_BYTES=$(wc -c < "$TMP/raw_stdout.txt" | tr -d ' \r')
# Allow either 65 (LF) or 66 (CRLF on some Windows shells); accept 65 strictly.
if [ "$LF_BYTES" = "65" ]; then
    echo "  PASS: raw-hex stdout is exactly 65 bytes (64 hex + LF)"; pass_count=$((pass_count + 1))
elif [ "$LF_BYTES" = "66" ]; then
    echo "  PASS: raw-hex stdout is 66 bytes (64 hex + CRLF) — Windows-style"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: raw-hex stdout has unexpected byte count: $LF_BYTES"
    fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-export"; exit 0
else
    echo "  FAIL"; exit 1
fi
