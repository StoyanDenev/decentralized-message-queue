#!/usr/bin/env bash
# determ-wallet keyfile-decrypt CLI test.
#
# `keyfile-decrypt` is the inverse of `keyfile-create`: given a
# passphrase-encrypted node_key.json file (2-line canonical format with
# a `DETERM-NODE-V1 <pubkey_hex>` header + a DWE1 envelope blob), it
# writes a plaintext node_key.json matching
# src/crypto/keys.cpp::save_node_key byte-for-byte.
#
# Use case: operator workflows that need the plaintext form — migrating
# a validator to a different node, recovery from a passphrase-protected
# archive, or debugging key-load failures. The daemon already supports
# the encrypted form at runtime; this CLI exists for the offline
# operator paths.
#
# Coverage:
#   - Build a fresh keypair via `account-create-batch --count 1 --json`.
#   - keyfile-create → keyfile-decrypt round-trip (file source). Verify
#     the recovered plaintext matches the original key bytes.
#   - Output file shape: canonical `j.dump(2)`-indented JSON with
#     'pubkey' and 'priv_seed' string fields.
#   - Wrong passphrase exits 2 with the "wrong passphrase or corrupted
#     keyfile" diagnostic and does NOT create --out.
#   - Pubkey-AAD tamper: editing the header pubkey breaks AEAD decrypt
#     (exits 2, no --out leak).
#   - Malformed --in: empty file, single-line, non-DETERM-NODE-V1 header,
#     bad hex pubkey, empty blob line, malformed envelope blob → exit 1.
#   - All 3 passphrase sources (file: / env: / prompt via stdin redirect).
#   - --force overwrite semantics.
#   - --out parent directory missing rejected.
#   - --json summary mode emits {pubkey,out,format,from}.
#   - Help text mentions keyfile-decrypt.
#   - Unknown arg rejected.
#   - Missing required args rejected.
#
# Run from repo root: bash tools/test_wallet_keyfile_decrypt.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_keyfile_decrypt.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
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
assert_not_exists() {
  if [ ! -e "$1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2 (file unexpectedly present: $1)"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

PASSPHRASE="correct horse battery staple"
PASS_FILE="$TMP/passphrase.txt"
printf '%s\n' "$PASSPHRASE" > "$PASS_FILE"

# ── 1. Help text mentions keyfile-decrypt ─────────────────────────────────────
echo "=== 1. Help text mentions keyfile-decrypt ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "keyfile-decrypt"; then
    echo "  PASS: help mentions keyfile-decrypt"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing keyfile-decrypt"; fail_count=$((fail_count + 1))
fi

# ── 2. Generate fresh keypair + encrypted keyfile via keyfile-create ──────────
echo
echo "=== 2. Build keypair + encrypted keyfile ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV_HEX=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR")
EXPECTED_PUB=${ADDR#0x}
assert_eq "${#PRIV_HEX}" "64" "fresh privkey_hex is 64 chars"
assert_eq "${#EXPECTED_PUB}" "64" "fresh pubkey hex is 64 chars"

ENC_FILE="$TMP/node_key.enc"
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$ENC_FILE" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "keyfile-create produces the input fixture"

# ── 3. Happy path: keyfile-decrypt round-trips to plaintext node_key.json ─────
echo
echo "=== 3. Happy path: keyfile-decrypt with --passphrase-from file: ==="
DEC_FILE="$TMP/node_key.json"
SUMMARY=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$DEC_FILE" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-decrypt exit 0"
assert_contains "$SUMMARY" "node_key.json" "summary mentions node_key.json"
assert_contains "$SUMMARY" "$EXPECTED_PUB" "summary echoes pubkey hex"
if [ -s "$DEC_FILE" ]; then
    echo "  PASS: plaintext output file non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: plaintext output file missing or empty"; fail_count=$((fail_count + 1))
fi

# ── 4. Plaintext shape matches src/crypto/keys.cpp::load_node_key byte-for-byte
echo
echo "=== 4. Plaintext shape matches load_node_key schema ==="
$PY - <<PY_EOF
import json, sys
with open("$DEC_FILE") as f:
    blob = f.read()
d = json.loads(blob)
assert set(d.keys()) == {"pubkey","priv_seed"}, f"unexpected keys: {set(d.keys())}"
assert isinstance(d["pubkey"], str) and len(d["pubkey"]) == 64
assert isinstance(d["priv_seed"], str) and len(d["priv_seed"]) == 64
assert all(c in "0123456789abcdef" for c in d["pubkey"])
assert all(c in "0123456789abcdef" for c in d["priv_seed"])
assert d["pubkey"] == "$EXPECTED_PUB", f"pubkey mismatch: {d['pubkey']!r} vs $EXPECTED_PUB"
assert d["priv_seed"] == "$PRIV_HEX", f"priv_seed mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: plaintext JSON has correct schema + values"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: plaintext JSON schema drift"; fail_count=$((fail_count + 1))
fi

# ── 5. Round-trip: re-encrypt the recovered plaintext, compare pubkeys ────────
echo
echo "=== 5. Round-trip: re-encrypt recovered seed; pubkey matches ==="
RECOVERED_SEED=$($PY -c "import json; print(json.load(open('$DEC_FILE'))['priv_seed'])")
assert_eq "$RECOVERED_SEED" "$PRIV_HEX" "round-trip seed equals original"
RE_ENC_FILE="$TMP/round_trip.enc"
"$WALLET" keyfile-create \
    --priv "$RECOVERED_SEED" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$RE_ENC_FILE" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "re-encrypt with recovered seed succeeds"
RE_HEADER=$(head -n 1 "$RE_ENC_FILE" | tr -d '\r')
assert_contains "$RE_HEADER" "$EXPECTED_PUB" "re-encrypted header carries same pubkey"

# ── 6. Wrong passphrase exits 2, no --out file ────────────────────────────────
echo
echo "=== 6. Wrong passphrase exits 2 (no --out leak) ==="
WRONG_PW_FILE="$TMP/wrong_pw.txt"
printf '%s\n' "definitely-not-the-passphrase" > "$WRONG_PW_FILE"
WRONG_OUT="$TMP/wrong_pw_out.json"
rm -f "$WRONG_OUT"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$WRONG_PW_FILE" \
    --out "$WRONG_OUT" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on wrong passphrase"
assert_contains "$ERR" "wrong passphrase or corrupted keyfile" "diagnostic does not leak structural detail"
assert_not_exists "$WRONG_OUT" "--out not created on wrong-passphrase failure"

# ── 7. Pubkey-AAD tamper: edit header pubkey, decrypt fails the same way ──────
echo
echo "=== 7. Pubkey-AAD tamper: edited header pubkey breaks AEAD ==="
TAMPER_FILE="$TMP/tamper.enc"
# Replace the header pubkey hex with all-a's (still 64 hex chars,
# so structural checks pass and AAD mismatch happens at the AEAD layer).
$PY - <<PY_EOF
import sys
with open("$ENC_FILE") as f:
    lines = f.read().split("\n")
# Line 0 is "DETERM-NODE-V1 <64-hex>"; replace with a syntactically-valid
# but different pubkey so we hit the AAD layer, not header parsing.
header_parts = lines[0].split(" ", 1)
lines[0] = header_parts[0] + " " + "a"*64
with open("$TAMPER_FILE", "w") as f:
    f.write("\n".join(lines))
PY_EOF
TAMPER_OUT="$TMP/tamper_out.json"
rm -f "$TAMPER_OUT"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$TAMPER_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TAMPER_OUT" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on AAD tamper"
assert_contains "$ERR" "wrong passphrase or corrupted keyfile" "AAD tamper produces same diagnostic as wrong passphrase"
assert_not_exists "$TAMPER_OUT" "--out not created on AAD tamper"

# ── 8. Malformed --in: empty file ─────────────────────────────────────────────
echo
echo "=== 8. Malformed --in: empty file rejected ==="
EMPTY_IN="$TMP/empty.enc"
: > "$EMPTY_IN"
EMPTY_OUT="$TMP/empty_out.json"
rm -f "$EMPTY_OUT"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$EMPTY_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$EMPTY_OUT" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty --in"
assert_contains "$ERR" "empty" "diagnostic mentions empty"
assert_not_exists "$EMPTY_OUT" "--out not created on empty --in"

# ── 9. Malformed --in: single-line file (missing envelope-blob line) ──────────
echo
echo "=== 9. Malformed --in: single-line (no blob) rejected ==="
SINGLE_IN="$TMP/single_line.enc"
printf 'DETERM-NODE-V1 %s\n' "$EXPECTED_PUB" > "$SINGLE_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$SINGLE_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/single_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on single-line --in"
assert_contains "$ERR" "missing the envelope-blob line" "diagnostic identifies the missing line"

# ── 10. Malformed --in: wrong header magic ────────────────────────────────────
echo
echo "=== 10. Malformed --in: wrong header magic rejected ==="
BAD_HEADER_IN="$TMP/bad_header.enc"
printf 'DETERM-FORK-V99 %s\n' "$EXPECTED_PUB" > "$BAD_HEADER_IN"
echo "dummyblob" >> "$BAD_HEADER_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$BAD_HEADER_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/bad_header_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on wrong header magic"
assert_contains "$ERR" "DETERM-NODE-V1" "diagnostic names the expected magic"

# ── 11. Malformed --in: header pubkey wrong length ────────────────────────────
echo
echo "=== 11. Malformed --in: header pubkey wrong length rejected ==="
SHORT_PUB_IN="$TMP/short_pub.enc"
printf 'DETERM-NODE-V1 abc123\n' > "$SHORT_PUB_IN"
echo "dummyblob" >> "$SHORT_PUB_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$SHORT_PUB_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/short_pub_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on header pubkey wrong length"
assert_contains "$ERR" "64 hex chars" "diagnostic mentions expected length"

# ── 12. Malformed --in: header pubkey non-hex ─────────────────────────────────
echo
echo "=== 12. Malformed --in: header pubkey non-hex rejected ==="
NONHEX_PUB_IN="$TMP/nonhex_pub.enc"
NONHEX_PUB=$($PY -c "print('zz' + 'a'*62)")
printf 'DETERM-NODE-V1 %s\n' "$NONHEX_PUB" > "$NONHEX_PUB_IN"
echo "dummyblob" >> "$NONHEX_PUB_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$NONHEX_PUB_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/nonhex_pub_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex header pubkey"

# ── 13. Malformed --in: empty envelope-blob line ──────────────────────────────
echo
echo "=== 13. Malformed --in: empty blob line rejected ==="
EMPTY_BLOB_IN="$TMP/empty_blob.enc"
printf 'DETERM-NODE-V1 %s\n\n' "$EXPECTED_PUB" > "$EMPTY_BLOB_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$EMPTY_BLOB_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/empty_blob_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty blob line"
assert_contains "$ERR" "blob line is empty" "diagnostic identifies empty blob line"

# ── 14. Malformed --in: garbage envelope-blob line ────────────────────────────
echo
echo "=== 14. Malformed --in: bad envelope blob rejected ==="
BAD_BLOB_IN="$TMP/bad_blob.enc"
printf 'DETERM-NODE-V1 %s\n' "$EXPECTED_PUB" > "$BAD_BLOB_IN"
printf 'this.is.not.a.valid.envelope.blob.at.all\n' >> "$BAD_BLOB_IN"
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$BAD_BLOB_IN" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/bad_blob_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on malformed envelope blob"
assert_contains "$ERR" "malformed" "diagnostic mentions malformed"

# ── 15. --passphrase-from env: source ─────────────────────────────────────────
echo
echo "=== 15. --passphrase-from env:NAME works ==="
ENV_PASSPHRASE="env-passphrase-decrypt-test"
# First produce an env-passphrase-encrypted file.
ENV_ENC="$TMP/env_src.enc"
KEYFILE_DECRYPT_PW="$ENV_PASSPHRASE" "$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "env:KEYFILE_DECRYPT_PW" \
    --out "$ENV_ENC" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "env-sourced keyfile-create"

ENV_DEC="$TMP/env_src_dec.json"
KEYFILE_DECRYPT_PW="$ENV_PASSPHRASE" "$WALLET" keyfile-decrypt \
    --in "$ENV_ENC" \
    --passphrase-from "env:KEYFILE_DECRYPT_PW" \
    --out "$ENV_DEC" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "env-sourced keyfile-decrypt"
RECOVERED_ENV_SEED=$($PY -c "import json; print(json.load(open('$ENV_DEC'))['priv_seed'])")
assert_eq "$RECOVERED_ENV_SEED" "$PRIV_HEX" "env-source round-trip seed matches"

# ── 16. --passphrase-from env: with unset variable rejected ───────────────────
echo
echo "=== 16. --passphrase-from env:UNSET rejected ==="
unset DETERM_WALLET_KFD_TEST_NOPE 2>/dev/null || true
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "env:DETERM_WALLET_KFD_TEST_NOPE" \
    --out "$TMP/env_unset_out.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unset env var"
assert_contains "$ERR" "not set or empty" "diagnostic identifies unset env var"

# ── 17. --passphrase-from prompt source (stdin redirect) ──────────────────────
echo
echo "=== 17. --passphrase-from prompt works via stdin redirect ==="
PROMPT_OUT="$TMP/prompt_out.json"
rm -f "$PROMPT_OUT"
PROMPT_RC=$(printf '%s\n' "$PASSPHRASE" | "$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "prompt" \
    --out "$PROMPT_OUT" >/dev/null 2>&1; echo $?)
assert_eq "$PROMPT_RC" "0" "exit 0 with prompt source"
if [ -s "$PROMPT_OUT" ]; then
    RECOVERED_PROMPT_SEED=$($PY -c "import json; print(json.load(open('$PROMPT_OUT'))['priv_seed'])")
    assert_eq "$RECOVERED_PROMPT_SEED" "$PRIV_HEX" "prompt-source round-trip seed matches"
else
    echo "  FAIL: prompt source did not produce --out"; fail_count=$((fail_count + 1))
fi

# ── 18. --force overwrite refused without --force ─────────────────────────────
echo
echo "=== 18. Overwrite refused without --force ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$DEC_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when --out exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"
assert_contains "$ERR" "--force" "diagnostic mentions --force"

# ── 19. --force proceeds with overwrite ───────────────────────────────────────
echo
echo "=== 19. Overwrite proceeds with --force ==="
"$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$DEC_FILE" \
    --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 with --force on existing file"

# ── 20. --out parent dir missing rejected ─────────────────────────────────────
echo
echo "=== 20. --out parent directory missing rejected ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/no_such_dir/node_key.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing parent dir"
assert_contains "$ERR" "does not exist" "diagnostic mentions does not exist"

# ── 21. --json summary mode ───────────────────────────────────────────────────
echo
echo "=== 21. --json summary mode ==="
JSON_DEC="$TMP/json_dec.json"
rm -f "$JSON_DEC"
JSON_SUMMARY=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$JSON_DEC" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_SUMMARY''')
required = {"pubkey","out","format","from"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["format"] == "node_key.json", f"bad format: {d['format']!r}"
assert d["from"]   == "DETERM-NODE-V1", f"bad from: {d['from']!r}"
assert d["pubkey"] == "$EXPECTED_PUB", "pubkey mismatch in --json summary"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 22. Unknown argument rejected ─────────────────────────────────────────────
echo
echo "=== 22. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/unknown_arg.json" \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown argument" "diagnostic mentions unknown argument"

# ── 23. Missing --in rejected ─────────────────────────────────────────────────
echo
echo "=== 23. Missing --in rejected ==="
set +e
"$WALLET" keyfile-decrypt \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/missing_in.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --in"

# ── 24. Missing --passphrase-from rejected ────────────────────────────────────
echo
echo "=== 24. Missing --passphrase-from rejected ==="
set +e
"$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --out "$TMP/missing_pass.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --passphrase-from"

# ── 25. Missing --out rejected ────────────────────────────────────────────────
echo
echo "=== 25. Missing --out rejected ==="
set +e
"$WALLET" keyfile-decrypt \
    --in "$ENC_FILE" \
    --passphrase-from "file:$PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --out"

# ── 26. --in file does not exist rejected ─────────────────────────────────────
echo
echo "=== 26. --in file does not exist rejected ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$TMP/no_such_file.enc" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/no_in.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in file"
assert_contains "$ERR" "cannot open --in" "diagnostic mentions cannot open --in"

# ── 27. Daemon-loader compatibility: keys.cpp::load_node_key would accept it ──
echo
echo "=== 27. Output file is exactly the canonical save_node_key shape ==="
# The reference shape is json::dump(2): a multi-line indented JSON
# with the two keys 'pubkey' and 'priv_seed', no trailing newline.
$PY - <<PY_EOF
import json
with open("$DEC_FILE") as f:
    text = f.read()
# Parsing succeeds + content matches the input keypair.
d = json.loads(text)
assert d == {"pubkey": "$EXPECTED_PUB", "priv_seed": "$PRIV_HEX"}
# Shape: multi-line (dump(2) emits indented JSON with newlines).
assert "\n" in text, "expected multi-line indented JSON"
# Indented: contains 2-space indentation.
assert "  \"pubkey\":" in text or "  \"priv_seed\":" in text, "expected dump(2) indentation"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: output matches save_node_key (dump(2)) shape"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: output drifted from save_node_key shape"; fail_count=$((fail_count + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-decrypt"; exit 0
else
    echo "  FAIL"; exit 1
fi
