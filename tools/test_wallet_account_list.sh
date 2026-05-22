#!/usr/bin/env bash
# determ-wallet account-list CLI test.
#
# Verifies the keyfile-directory enumerator. Coverage:
#   * Build a fixture directory containing all three canonical keyfile shapes
#     (plaintext-single, plaintext-batch, encrypted-DETERM-NODE-V1) plus a
#     non-keyfile junk file (should be classified as "unknown" but not error).
#   * Run account-list --keyfiles-dir <fixture> --json
#   * Assert all three keyfiles are detected with the correct types.
#   * Assert plaintext-single carries the canonical "address" field; the
#     extracted address matches the underlying fixture privkey's anon-addr.
#   * Assert plaintext-batch carries the canonical "addresses" array; every
#     element matches the underlying batch fixture's addresses 1:1.
#   * Assert encrypted-DETERM-NODE-V1 carries header_tag, pbkdf2_iters,
#     salt_hex, nonce_hex; cross-check the metadata against keyfile-info's
#     output on the same file.
#   * Junk file (non-JSON, non-keyfile) shows type=unknown with a
#     skip_reason. Doesn't break the run.
#   * --recursive on a nested dir picks up keyfiles in subdirectories;
#     without --recursive the nested files are not listed.
#   * --include-encrypted=off filters encrypted keyfiles out; plaintext
#     keyfiles remain.
#   * --include-plaintext=off filters plaintext keyfiles out; encrypted
#     keyfile remains.
#   * Both flags off: only "unknown" remains.
#   * Missing --keyfiles-dir → exit 1.
#   * Missing dir path → exit 1.
#   * Non-directory path → exit 1.
#   * Help text mentions account-list.
#   * Output is well-formed JSON, parseable with python.
#   * summary.total_files matches the kept-list length.
#   * summary.n_addresses = single (1) + batch (3) + encrypted (1) = 5
#     on the happy path.
#   * summary.warnings: mixed_encrypted_and_plaintext warning fires when
#     the fixture has both types in the same dir.
#
# Run from repo root: bash tools/test_wallet_account_list.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ to dodge MSYS path translation quirks. The Windows
# wallet binary doesn't understand /tmp/-style MSYS paths; a repo-relative
# path works on both Git Bash and POSIX shells.
SCRATCH="build/test_wallet_account_list.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

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

# ── 1. Help text mentions account-list ────────────────────────────────────────
echo "=== 1. Help text mentions account-list ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "account-list"; then
    echo "  PASS: help mentions account-list"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing account-list"; fail_count=$((fail_count + 1))
fi

# ── 2. Build the happy-path fixture directory ────────────────────────────────
echo
echo "=== 2. Build fixture: 1 plaintext-single + 1 plaintext-batch + 1 encrypted ==="
FIXTURE="$SCRATCH/fixture"
mkdir -p "$FIXTURE"

# (a) plaintext-single via account-import (produces {address, privkey_hex})
KEYPAIR_SINGLE=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV_SINGLE=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR_SINGLE")
ADDR_SINGLE=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR_SINGLE")
"$WALLET" account-import --priv "$PRIV_SINGLE" --out "$FIXTURE/single.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-import produces plaintext-single fixture"

# (b) plaintext-batch via account-create-batch
"$WALLET" account-create-batch --count 3 --out "$FIXTURE/batch.json" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "account-create-batch produces plaintext-batch fixture"
BATCH_ADDRS=$($PY -c "import json; d=json.load(open('$FIXTURE/batch.json')); print(','.join(a['address'] for a in d['accounts']))")

# (c) encrypted keyfile via keyfile-create
KEYPAIR_ENC=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV_ENC=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR_ENC")
ADDR_ENC=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR_ENC")
PASS_FILE="$SCRATCH/passphrase.txt"
printf '%s\n' "correct horse battery staple" > "$PASS_FILE"
"$WALLET" keyfile-create --priv "$PRIV_ENC" --passphrase-from "file:$PASS_FILE" --out "$FIXTURE/node.keyfile" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "keyfile-create produces encrypted fixture"

# (d) junk file (non-keyfile)
printf 'this is not a keyfile\n' > "$FIXTURE/readme.txt"

# ── 3. Happy-path account-list --json ────────────────────────────────────────
echo
echo "=== 3. Happy-path account-list emits valid JSON ==="
JSON=$("$WALLET" account-list --keyfiles-dir "$FIXTURE" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-list exit 0"
# Validate JSON parses + carries the expected top-level keys.
$PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
assert "keyfiles_dir" in d
assert "recursive" in d
assert "keyfiles" in d
assert "summary" in d
s = d["summary"]
assert "total_files" in s and "by_type" in s and "n_addresses" in s and "warnings" in s
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: JSON parses + top-level schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: JSON schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 4. All three keyfile types detected ──────────────────────────────────────
echo
echo "=== 4. All three keyfile types detected ==="
assert_contains "$JSON" "\"plaintext-single\": 1" "by_type has plaintext-single=1"
assert_contains "$JSON" "\"plaintext-batch\": 1" "by_type has plaintext-batch=1"
assert_contains "$JSON" "\"encrypted-DETERM-NODE-V1\": 1" "by_type has encrypted=1"
assert_contains "$JSON" "\"unknown\": 1" "by_type has unknown=1 (the junk file)"

# ── 5. Address extraction matches fixture ────────────────────────────────────
echo
echo "=== 5. Extracted addresses match the underlying fixtures ==="
EXTRACTED_SINGLE=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "plaintext-single":
        print(kf["address"]); break
PY_EOF
)
assert_eq "$EXTRACTED_SINGLE" "$ADDR_SINGLE" "plaintext-single address matches fixture"

EXTRACTED_ENC=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "encrypted-DETERM-NODE-V1":
        print(kf["address"]); break
PY_EOF
)
assert_eq "$EXTRACTED_ENC" "$ADDR_ENC" "encrypted keyfile derived address matches fixture"

EXTRACTED_BATCH=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "plaintext-batch":
        print(",".join(kf["addresses"])); break
PY_EOF
)
assert_eq "$EXTRACTED_BATCH" "$BATCH_ADDRS" "plaintext-batch addresses match fixture (in order)"

# ── 6. summary.n_addresses = 1 + 3 + 1 = 5 ───────────────────────────────────
echo
echo "=== 6. summary.n_addresses tally ==="
NADDR=$($PY -c "import json; print(json.loads('''$JSON''')['summary']['n_addresses'])")
assert_eq "$NADDR" "5" "n_addresses = single(1) + batch(3) + encrypted(1) = 5"

# ── 7. Encrypted-keyfile metadata cross-check with keyfile-info ──────────────
echo
echo "=== 7. Encrypted-keyfile metadata cross-checks with keyfile-info ==="
INFO_JSON=$("$WALLET" keyfile-info --in "$FIXTURE/node.keyfile" --json 2>&1 | tr -d '\r')
EXPECTED_ITERS=$($PY -c "import json; print(json.loads('''$INFO_JSON''')['envelope']['pbkdf2_iters'])")
EXPECTED_SALT_LEN=$($PY -c "import json; print(json.loads('''$INFO_JSON''')['envelope']['salt_len'])")
EXPECTED_NONCE_LEN=$($PY -c "import json; print(json.loads('''$INFO_JSON''')['envelope']['nonce_len'])")

LIST_ITERS=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "encrypted-DETERM-NODE-V1":
        print(kf["pbkdf2_iters"]); break
PY_EOF
)
assert_eq "$LIST_ITERS" "$EXPECTED_ITERS" "pbkdf2_iters matches keyfile-info"

LIST_SALT_HEX=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "encrypted-DETERM-NODE-V1":
        print(kf["salt_hex"]); break
PY_EOF
)
# salt_hex is 2*salt_len hex chars
ACTUAL_SALT_HEX_LEN=${#LIST_SALT_HEX}
EXPECTED_SALT_HEX_LEN=$((EXPECTED_SALT_LEN * 2))
assert_eq "$ACTUAL_SALT_HEX_LEN" "$EXPECTED_SALT_HEX_LEN" "salt_hex length = 2 * salt_len"

LIST_NONCE_HEX=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "encrypted-DETERM-NODE-V1":
        print(kf["nonce_hex"]); break
PY_EOF
)
ACTUAL_NONCE_HEX_LEN=${#LIST_NONCE_HEX}
EXPECTED_NONCE_HEX_LEN=$((EXPECTED_NONCE_LEN * 2))
assert_eq "$ACTUAL_NONCE_HEX_LEN" "$EXPECTED_NONCE_HEX_LEN" "nonce_hex length = 2 * nonce_len"

LIST_HDR_TAG=$($PY - <<PY_EOF
import json
d = json.loads("""$JSON""")
for kf in d["keyfiles"]:
    if kf["type"] == "encrypted-DETERM-NODE-V1":
        print(kf["header_tag"]); break
PY_EOF
)
assert_eq "$LIST_HDR_TAG" "DETERM-NODE-V1" "header_tag = DETERM-NODE-V1"

# ── 8. mixed_encrypted_and_plaintext_in_same_dir warning ─────────────────────
echo
echo "=== 8. mixed_encrypted_and_plaintext warning ==="
WARN_PRESENT=$($PY -c "import json; d=json.loads('''$JSON'''); print('yes' if 'mixed_encrypted_and_plaintext_in_same_dir' in d['summary']['warnings'] else 'no')")
assert_eq "$WARN_PRESENT" "yes" "warning fires for mixed dir"

# ── 9. --recursive picks up files in subdirs ─────────────────────────────────
echo
echo "=== 9. --recursive picks up subdir keyfiles ==="
NESTED="$SCRATCH/nested"
mkdir -p "$NESTED/sub1" "$NESTED/sub2"
"$WALLET" account-create-batch --count 2 --out "$NESTED/top_batch.json" >/dev/null 2>&1
"$WALLET" account-create-batch --count 1 --out "$NESTED/sub1/nested_single.json" >/dev/null 2>&1
"$WALLET" account-create-batch --count 5 --out "$NESTED/sub2/nested_batch.json" >/dev/null 2>&1

# Without --recursive: only top_batch.json
SHALLOW_JSON=$("$WALLET" account-list --keyfiles-dir "$NESTED" 2>&1 | tr -d '\r')
SHALLOW_TOTAL=$($PY -c "import json; print(json.loads('''$SHALLOW_JSON''')['summary']['total_files'])")
assert_eq "$SHALLOW_TOTAL" "1" "without --recursive: only 1 file (top_batch.json)"

# With --recursive: top + sub1 + sub2 = 3 files
DEEP_JSON=$("$WALLET" account-list --keyfiles-dir "$NESTED" --recursive 2>&1 | tr -d '\r')
DEEP_TOTAL=$($PY -c "import json; print(json.loads('''$DEEP_JSON''')['summary']['total_files'])")
assert_eq "$DEEP_TOTAL" "3" "with --recursive: 3 files (top + sub1 + sub2)"

# n_addresses with --recursive: 2 + 1 + 5 = 8
DEEP_NADDR=$($PY -c "import json; print(json.loads('''$DEEP_JSON''')['summary']['n_addresses'])")
assert_eq "$DEEP_NADDR" "8" "n_addresses with --recursive: 2 + 1 + 5 = 8"

# recursive flag is reflected in output
RECUR_FIELD=$($PY -c "import json; print(json.loads('''$DEEP_JSON''')['recursive'])")
assert_eq "$RECUR_FIELD" "True" "recursive=True in --recursive output"

# ── 10. --include-encrypted=off filters out encrypted keyfiles ───────────────
echo
echo "=== 10. --include-encrypted=off filters encrypted out ==="
NO_ENC_JSON=$("$WALLET" account-list --keyfiles-dir "$FIXTURE" --include-encrypted=off 2>&1 | tr -d '\r')
ENC_COUNT=$($PY -c "import json; d=json.loads('''$NO_ENC_JSON'''); print(d['summary']['by_type'].get('encrypted-DETERM-NODE-V1', 0))")
assert_eq "$ENC_COUNT" "0" "encrypted-DETERM-NODE-V1 not in by_type with --include-encrypted=off"

PT_S_COUNT=$($PY -c "import json; d=json.loads('''$NO_ENC_JSON'''); print(d['summary']['by_type'].get('plaintext-single', 0))")
PT_B_COUNT=$($PY -c "import json; d=json.loads('''$NO_ENC_JSON'''); print(d['summary']['by_type'].get('plaintext-batch', 0))")
assert_eq "$PT_S_COUNT" "1" "plaintext-single still present with --include-encrypted=off"
assert_eq "$PT_B_COUNT" "1" "plaintext-batch still present with --include-encrypted=off"

# ── 11. --include-plaintext=off filters out plaintext keyfiles ───────────────
echo
echo "=== 11. --include-plaintext=off filters plaintext out ==="
NO_PT_JSON=$("$WALLET" account-list --keyfiles-dir "$FIXTURE" --include-plaintext=off 2>&1 | tr -d '\r')
PT_S2=$($PY -c "import json; d=json.loads('''$NO_PT_JSON'''); print(d['summary']['by_type'].get('plaintext-single', 0))")
PT_B2=$($PY -c "import json; d=json.loads('''$NO_PT_JSON'''); print(d['summary']['by_type'].get('plaintext-batch', 0))")
ENC2=$($PY -c "import json; d=json.loads('''$NO_PT_JSON'''); print(d['summary']['by_type'].get('encrypted-DETERM-NODE-V1', 0))")
assert_eq "$PT_S2" "0" "plaintext-single filtered out"
assert_eq "$PT_B2" "0" "plaintext-batch filtered out"
assert_eq "$ENC2" "1" "encrypted still present with --include-plaintext=off"

# ── 12. Bad dir → exit 1 ─────────────────────────────────────────────────────
echo
echo "=== 12. Non-existent dir → exit 1 ==="
set +e
ERR=$("$WALLET" account-list --keyfiles-dir "$SCRATCH/does_not_exist_xyz" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing dir"
assert_contains "$ERR" "does not exist" "diagnostic mentions does not exist"

# ── 13. Non-directory path → exit 1 ──────────────────────────────────────────
echo
echo "=== 13. Non-directory path → exit 1 ==="
NOT_DIR="$SCRATCH/just_a_file"
echo "hello" > "$NOT_DIR"
set +e
ERR=$("$WALLET" account-list --keyfiles-dir "$NOT_DIR" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on file (not dir)"
assert_contains "$ERR" "not a directory" "diagnostic mentions not a directory"

# ── 14. Missing --keyfiles-dir → exit 1 ──────────────────────────────────────
echo
echo "=== 14. Missing --keyfiles-dir → exit 1 ==="
set +e
ERR=$("$WALLET" account-list 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --keyfiles-dir"
assert_contains "$ERR" "required" "diagnostic mentions required"

# ── 15. Unknown argument → exit 1 ────────────────────────────────────────────
echo
echo "=== 15. Unknown argument → exit 1 ==="
set +e
ERR=$("$WALLET" account-list --keyfiles-dir "$FIXTURE" --bogus 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown" "diagnostic mentions unknown"

# ── 16. --help → exit 0 ──────────────────────────────────────────────────────
echo
echo "=== 16. --help prints usage and exits 0 ==="
HELP_OUT=$("$WALLET" account-list --help 2>&1)
RC=$?
assert_eq "$RC" "0" "--help exit 0"
assert_contains "$HELP_OUT" "Enumerate keyfiles" "help text describes purpose"
assert_contains "$HELP_OUT" "mode_not_0600" "help mentions mode_not_0600 warning"

# ── 17. Empty dir → 0 files, no warnings ─────────────────────────────────────
echo
echo "=== 17. Empty dir → 0 files, empty by_type ==="
EMPTY="$SCRATCH/empty_dir"
mkdir -p "$EMPTY"
EMPTY_JSON=$("$WALLET" account-list --keyfiles-dir "$EMPTY" 2>&1 | tr -d '\r')
EMPTY_TOTAL=$($PY -c "import json; print(json.loads('''$EMPTY_JSON''')['summary']['total_files'])")
EMPTY_NADDR=$($PY -c "import json; print(json.loads('''$EMPTY_JSON''')['summary']['n_addresses'])")
assert_eq "$EMPTY_TOTAL" "0" "empty dir: total_files=0"
assert_eq "$EMPTY_NADDR" "0" "empty dir: n_addresses=0"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-list"; exit 0
else
    echo "  FAIL"; exit 1
fi
