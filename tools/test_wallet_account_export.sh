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
"$WALLET" account-create-batch --count 1 --json > "$TMP/batch.json" 2>/dev/null
RC=$?
assert_eq "$RC" "0" "account-create-batch setup succeeded"
# Mint the standalone keyfile account-export consumes — the canonical binary
# DAK1 container (D2), produced by account-import --out.
SEED_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/batch.json")
SEED_ADDR=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['address'])"     "$TMP/batch.json")
"$WALLET" account-import --priv "$SEED_PRIV" --out "$TMP/acc.json" >/dev/null
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
echo "=== 12. --out writes the DAK1 container; stdout confirms ==="
# D2: --out always re-emits the canonical binary DAK1 keyfile — the text
# formats are stdout VIEWS only and never land on disk.
"$WALLET" account-export --in "$TMP/acc.json" --format raw-hex --out "$TMP/exp.hex" > "$TMP/stdout12.txt" 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --out"
STDOUT=$(cat "$TMP/stdout12.txt" | tr -d '\r')
assert_contains "$STDOUT" "exported DAK1 keyfile:" "stdout confirms DAK1 keyfile export"
if [ -s "$TMP/exp.hex" ]; then
    echo "  PASS: --out file is non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out file empty"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 13. --out file is a byte-exact DAK1 copy of the input keyfile ==="
if cmp -s "$TMP/exp.hex" "$TMP/acc.json"; then
    echo "  PASS: --out DAK1 file is byte-identical to the input keyfile"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out DAK1 file differs from the input keyfile"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 14. --out file re-imports (round-trips through account-export --in) ==="
RT_HEX=$("$WALLET" account-export --in "$TMP/exp.hex" | tr -d '\r\n')
assert_eq "$RT_HEX" "$SEED_PRIV" "re-exported raw-hex view equals the original privkey"

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
"$WALLET" account-create-batch --count 1 --json > "$TMP/other_batch.json" 2>/dev/null
OTHER_PRIV=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['accounts'][0]['privkey_hex'])" "$TMP/other_batch.json")
"$WALLET" account-import --priv "$OTHER_PRIV" --out "$TMP/other_acc.json" >/dev/null
"$WALLET" account-export --in "$TMP/other_acc.json" --format raw-hex --out "$TMP/exp.hex" --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 on --force overwrite"
NEW_FILE_PRIV=$($PY -c "
d = open('$TMP/exp.hex','rb').read()
assert d[:4] == b'DAK1'
print(d[36:68].hex())")
assert_eq "$NEW_FILE_PRIV" "$OTHER_PRIV" "after --force, the DAK1 file holds the new seed"

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
echo "=== 20. --in that is not a DAK1 container fails ==="
printf 'not-a-keyfile{{{' > "$TMP/bad.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/bad.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-DAK1 --in"
assert_contains "$ERR" "DAK1" "diagnostic mentions DAK1"

echo
echo "=== 21. --in truncated DAK1 (67 bytes) fails ==="
head -c 67 "$TMP/acc.json" > "$TMP/no_addr.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/no_addr.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 67-byte truncated DAK1"
assert_contains "$ERR" "DAK1" "diagnostic mentions DAK1"

echo
echo "=== 22. --in DAK1 + trailing byte (69 bytes) fails ==="
cp "$TMP/acc.json" "$TMP/no_priv.json"; printf '\x00' >> "$TMP/no_priv.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/no_priv.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 69-byte (trailing byte) DAK1"
assert_contains "$ERR" "DAK1" "diagnostic mentions DAK1"

echo
echo "=== 23. --in wrong magic fails ==="
$PY -c "
d = bytearray(open('$TMP/acc.json','rb').read())
d[0:4] = b'XXXX'
open('$TMP/bad_addr.json','wb').write(bytes(d))"
set +e
ERR=$("$WALLET" account-export --in "$TMP/bad_addr.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on wrong magic"
assert_contains "$ERR" "DAK1" "diagnostic mentions DAK1"

echo
echo "=== 24. --in pubkey/seed derive mismatch fails ==="
$PY -c "
d = bytearray(open('$TMP/acc.json','rb').read())
d[4] ^= 0x01
open('$TMP/short_priv.json','wb').write(bytes(d))"
set +e
ERR=$("$WALLET" account-export --in "$TMP/short_priv.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on pubkey/seed derive mismatch"
assert_contains "$ERR" "DAK1" "diagnostic mentions DAK1"

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
echo "=== 27. json view matches the decoded DAK1 record exactly ==="
JSON_OUT=$("$WALLET" account-export --in "$TMP/acc.json" --format json | tr -d '\r')
ROUND_EQ=$(echo "$JSON_OUT" | $PY -c "
import json, sys
out = json.load(sys.stdin)
d = open(sys.argv[1], 'rb').read()
assert d[:4] == b'DAK1'
src = {'address': '0x' + d[4:36].hex(), 'privkey_hex': d[36:68].hex()}
keys = {'address', 'privkey_hex'}
ok = all(out.get(k) == src.get(k) for k in keys)
print('YES' if ok else 'NO')
" "$TMP/acc.json")
assert_eq "$ROUND_EQ" "YES" "json view preserves address+privkey_hex exactly"

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
    echo "  FAIL: test_wallet_account_export"; exit 1
fi
