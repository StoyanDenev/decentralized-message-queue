#!/usr/bin/env bash
# determ-wallet keyfile-rotate CLI test.
#
# `keyfile-rotate` is the atomic passphrase-rotation companion to
# `keyfile-create` + `keyfile-decrypt`. It reads an encrypted
# DETERM-NODE-V1 keyfile, decrypts with the OLD passphrase (in-memory
# only — no plaintext-on-disk window), re-encrypts under the NEW
# passphrase with a fresh nonce + fresh salt, and writes --out via
# stage-tmp + fflush + fsync (_commit on Windows) + atomic rename.
#
# Coverage:
#   - Round-trip happy path: rotate to new passphrase, keyfile-decrypt
#     with NEW passphrase succeeds and recovered seed matches original.
#   - Old passphrase fails after rotation (AEAD tag mismatch).
#   - Fresh crypto material: new file's envelope blob differs from
#     original (distinct nonce + salt) even with same passphrase under
#     --force-same-passphrase.
#   - In-place rotation (--in == --out) succeeds atomically.
#   - Wrong old passphrase → exit 2.
#   - Same old + new passphrase rejected without --force-same-passphrase.
#   - --force-same-passphrase allows same-passphrase rotation.
#   - Missing --in / unreadable → exit 1.
#   - --out exists + different + no --force → exit 1.
#   - --force permits overwrite of different --out.
#   - Malformed --in (empty, single-line, wrong header magic) rejected.
#   - --passphrase-from env: + file: + prompt all work.
#   - --json output well-formed.
#   - Unknown arg rejected.
#   - Help text mentions keyfile-rotate.
#
# Run from repo root: bash tools/test_wallet_keyfile_rotate.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_keyfile_rotate.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_ne() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected NOT equal to: $2"; echo "       got:                   $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_exists() {
  if [ ! -e "$1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2 (file unexpectedly present: $1)"; fail_count=$((fail_count + 1)); fi
}
assert_exists() {
  if [ -e "$1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2 (file missing: $1)"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

OLD_PASS="old-correct-horse-battery-staple"
NEW_PASS="new-tower-rooftop-evergreen-2026"
OLD_PASS_FILE="$TMP/old_pass.txt"
NEW_PASS_FILE="$TMP/new_pass.txt"
printf '%s\n' "$OLD_PASS" > "$OLD_PASS_FILE"
printf '%s\n' "$NEW_PASS" > "$NEW_PASS_FILE"

# ── 1. Help text mentions keyfile-rotate ────────────────────────────────────
echo "=== 1. Help text mentions keyfile-rotate ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "keyfile-rotate"; then
    echo "  PASS: help mentions keyfile-rotate"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing keyfile-rotate"; fail_count=$((fail_count + 1))
fi

# ── 2. Generate fresh keypair + encrypted keyfile via keyfile-create ────────
echo
echo "=== 2. Build keypair + encrypted keyfile (under old passphrase) ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV_HEX=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR")
EXPECTED_PUB=${ADDR#0x}
assert_eq "${#PRIV_HEX}" "64" "fresh privkey_hex is 64 chars"
assert_eq "${#EXPECTED_PUB}" "64" "fresh pubkey hex is 64 chars"

ORIG_ENC="$TMP/node_key.enc"
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$OLD_PASS_FILE" \
    --out "$ORIG_ENC" >/dev/null 2>&1
assert_eq "$?" "0" "keyfile-create produces the original-passphrase fixture"
assert_exists "$ORIG_ENC" "original encrypted keyfile exists"

# Capture the original envelope blob (line 2) for later distinctness comparison.
ORIG_BLOB=$(sed -n '2p' "$ORIG_ENC" | tr -d '\r')
assert_ne "$ORIG_BLOB" "" "original envelope blob is non-empty"

# ── 3. Happy path: rotate to new passphrase via file: source ────────────────
echo
echo "=== 3. Happy path: rotate to new passphrase (different --out) ==="
ROT_OUT="$TMP/node_key_new.enc"
SUMMARY=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$ROT_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-rotate exit 0 on happy path"
assert_contains "$SUMMARY" "keyfile_rotated=YES" "summary reports YES"
assert_contains "$SUMMARY" "0x$EXPECTED_PUB" "summary echoes anon address"
assert_exists "$ROT_OUT" "rotated keyfile exists at --out"
assert_exists "$ORIG_ENC" "original --in file still exists (rotate did not consume it)"

# ── 4. NEW passphrase decrypts the rotated file ─────────────────────────────
echo
echo "=== 4. NEW passphrase decrypts rotated file; seed matches original ==="
DEC_NEW="$TMP/recovered_new.json"
"$WALLET" keyfile-decrypt \
    --in "$ROT_OUT" \
    --passphrase-from "file:$NEW_PASS_FILE" \
    --out "$DEC_NEW" >/dev/null 2>&1
assert_eq "$?" "0" "decrypt with NEW passphrase exits 0"
RECOVERED_SEED=$($PY -c "import json; print(json.load(open('$DEC_NEW'))['priv_seed'])")
assert_eq "$RECOVERED_SEED" "$PRIV_HEX" "recovered private seed equals original byte-for-byte"
RECOVERED_PUB=$($PY -c "import json; print(json.load(open('$DEC_NEW'))['pubkey'])")
assert_eq "$RECOVERED_PUB" "$EXPECTED_PUB" "recovered pubkey equals original"

# ── 5. OLD passphrase fails on the rotated file (AEAD tag mismatch) ─────────
echo
echo "=== 5. OLD passphrase fails on the rotated file (AEAD mismatch) ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$ROT_OUT" \
    --passphrase-from "file:$OLD_PASS_FILE" \
    --out "$TMP/should_not_exist.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "OLD passphrase exits 2 on rotated file"
assert_contains "$ERR" "wrong passphrase or corrupted keyfile" "OLD passphrase diagnostic"
assert_not_exists "$TMP/should_not_exist.json" "no --out leak on OLD-passphrase failure"

# ── 6. Fresh crypto material: blob differs even between rotations ───────────
echo
echo "=== 6. Rotated envelope blob differs from original (fresh salt+nonce) ==="
ROT_BLOB=$(sed -n '2p' "$ROT_OUT" | tr -d '\r')
assert_ne "$ORIG_BLOB" "$ROT_BLOB" "rotated envelope blob differs from original"

# Header is preserved byte-for-byte (same pubkey + magic).
ORIG_HEADER=$(sed -n '1p' "$ORIG_ENC" | tr -d '\r')
ROT_HEADER=$(sed -n '1p' "$ROT_OUT" | tr -d '\r')
assert_eq "$ROT_HEADER" "$ORIG_HEADER" "header preserved across rotation"

# ── 7. In-place rotation (--in == --out) ────────────────────────────────────
echo
echo "=== 7. In-place rotation (--in == --out) ==="
INPLACE_FILE="$TMP/inplace.enc"
cp "$ORIG_ENC" "$INPLACE_FILE"
ORIG_INPLACE_BLOB=$(sed -n '2p' "$INPLACE_FILE" | tr -d '\r')
"$WALLET" keyfile-rotate \
    --in "$INPLACE_FILE" \
    --out "$INPLACE_FILE" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "in-place rotation exit 0"
assert_exists "$INPLACE_FILE" "in-place file still exists after rotation"
NEW_INPLACE_BLOB=$(sed -n '2p' "$INPLACE_FILE" | tr -d '\r')
assert_ne "$ORIG_INPLACE_BLOB" "$NEW_INPLACE_BLOB" "in-place blob was actually replaced"
# Verify the in-place rotation produced a NEW-passphrase keyfile.
"$WALLET" keyfile-decrypt \
    --in "$INPLACE_FILE" \
    --passphrase-from "file:$NEW_PASS_FILE" \
    --out "$TMP/inplace_dec.json" >/dev/null 2>&1
assert_eq "$?" "0" "in-place rotated file decrypts with NEW passphrase"
INPLACE_SEED=$($PY -c "import json; print(json.load(open('$TMP/inplace_dec.json'))['priv_seed'])")
assert_eq "$INPLACE_SEED" "$PRIV_HEX" "in-place rotated seed matches original"

# Verify no stale tmp file was left behind.
assert_not_exists "${INPLACE_FILE}_tmp.json" "no tmp file left after successful in-place rotation"

# ── 8. Wrong OLD passphrase exits 2, --out untouched ────────────────────────
echo
echo "=== 8. Wrong OLD passphrase exits 2 ==="
WRONG_OLD_FILE="$TMP/wrong_old.txt"
printf '%s\n' "definitely-not-the-old-passphrase" > "$WRONG_OLD_FILE"
WRONG_ROT_OUT="$TMP/wrong_rot.enc"
rm -f "$WRONG_ROT_OUT" "${WRONG_ROT_OUT}_tmp.json"
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$WRONG_ROT_OUT" \
    --old-passphrase-from "file:$WRONG_OLD_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on wrong OLD passphrase"
assert_contains "$ERR" "old passphrase wrong or corrupted keyfile" "diagnostic mentions wrong OLD passphrase"
assert_not_exists "$WRONG_ROT_OUT" "no --out leak on wrong OLD passphrase"
assert_not_exists "${WRONG_ROT_OUT}_tmp.json" "no tmp file leak on wrong OLD passphrase"

# ── 9. Same OLD + NEW passphrase rejected without --force-same-passphrase ──
echo
echo "=== 9. Same OLD + NEW passphrase rejected without --force-same-passphrase ==="
SAME_ROT_OUT="$TMP/same_rot.enc"
rm -f "$SAME_ROT_OUT"
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$SAME_ROT_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$OLD_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on same OLD+NEW passphrase without override"
assert_contains "$ERR" "old_and_new_passphrase_identical" "diagnostic identifies the same-passphrase reason"
assert_contains "$ERR" "force-same-passphrase" "diagnostic suggests the override"
assert_not_exists "$SAME_ROT_OUT" "no --out leak on same-passphrase rejection"

# ── 10. --force-same-passphrase allows the same-passphrase rotation ────────
echo
echo "=== 10. --force-same-passphrase permits same-passphrase rotation ==="
FORCE_SAME_OUT="$TMP/force_same.enc"
rm -f "$FORCE_SAME_OUT"
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$FORCE_SAME_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$OLD_PASS_FILE" \
    --force-same-passphrase >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "--force-same-passphrase exit 0"
assert_exists "$FORCE_SAME_OUT" "force-same-passphrase --out exists"
FORCE_BLOB=$(sed -n '2p' "$FORCE_SAME_OUT" | tr -d '\r')
assert_ne "$FORCE_BLOB" "$ORIG_BLOB" "force-same-passphrase still produces a fresh blob (fresh nonce+salt)"
# Decrypt with the same passphrase to confirm it's a valid keyfile.
"$WALLET" keyfile-decrypt \
    --in "$FORCE_SAME_OUT" \
    --passphrase-from "file:$OLD_PASS_FILE" \
    --out "$TMP/force_same_dec.json" >/dev/null 2>&1
assert_eq "$?" "0" "force-same-passphrase file decrypts with original passphrase"

# ── 11. --out exists + different file + no --force → exit 1 ────────────────
echo
echo "=== 11. --out exists + no --force rejected ==="
# ROT_OUT exists from step 3.
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$ROT_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when --out exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"
assert_contains "$ERR" "--force" "diagnostic mentions --force"

# ── 12. --force proceeds with overwrite ────────────────────────────────────
echo
echo "=== 12. --force overrides existing --out ==="
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$ROT_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" \
    --force >/dev/null 2>&1
assert_eq "$?" "0" "--force on existing --out exits 0"

# ── 13. Missing --in rejected ──────────────────────────────────────────────
echo
echo "=== 13. Missing --in rejected ==="
set +e
"$WALLET" keyfile-rotate \
    --out "$TMP/no_in.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --in"

# ── 14. Missing --out rejected ─────────────────────────────────────────────
echo
echo "=== 14. Missing --out rejected ==="
set +e
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --out"

# ── 15. Missing --old-passphrase-from rejected ─────────────────────────────
echo
echo "=== 15. Missing --old-passphrase-from rejected ==="
set +e
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$TMP/no_old.enc" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --old-passphrase-from"

# ── 16. Missing --new-passphrase-from rejected ─────────────────────────────
echo
echo "=== 16. Missing --new-passphrase-from rejected ==="
set +e
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$TMP/no_new.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --new-passphrase-from"

# ── 17. --in file does not exist → exit 1 ──────────────────────────────────
echo
echo "=== 17. --in file does not exist rejected ==="
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$TMP/no_such_file.enc" \
    --out "$TMP/no_in_file_out.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in file"
assert_contains "$ERR" "cannot open --in" "diagnostic mentions cannot open --in"

# ── 18. Malformed --in: empty file ─────────────────────────────────────────
echo
echo "=== 18. Malformed --in: empty file rejected ==="
EMPTY_IN="$TMP/empty.enc"
: > "$EMPTY_IN"
EMPTY_OUT="$TMP/empty_out.enc"
rm -f "$EMPTY_OUT"
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$EMPTY_IN" \
    --out "$EMPTY_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty --in"
assert_contains "$ERR" "empty" "empty-file diagnostic"
assert_not_exists "$EMPTY_OUT" "no --out leak on empty --in"

# ── 19. Malformed --in: wrong header magic ────────────────────────────────
echo
echo "=== 19. Malformed --in: wrong header magic rejected ==="
BAD_HEADER_IN="$TMP/bad_header.enc"
printf 'DETERM-FORK-V99 %s\n' "$EXPECTED_PUB" > "$BAD_HEADER_IN"
echo "dummyblob" >> "$BAD_HEADER_IN"
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$BAD_HEADER_IN" \
    --out "$TMP/bad_header_out.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on wrong header magic"
assert_contains "$ERR" "DETERM-NODE-V1" "diagnostic names the expected magic"

# ── 20. --json output well-formed ──────────────────────────────────────────
echo
echo "=== 20. --json summary mode ==="
JSON_OUT="$TMP/json_rot.enc"
rm -f "$JSON_OUT"
JSON_SUMMARY=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$JSON_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_SUMMARY''')
required = {"rotated","anon_address","ed_pub_hex","in","out",
            "old_passphrase_source","new_passphrase_source"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["rotated"] is True, f"rotated should be True; got {d['rotated']!r}"
assert d["ed_pub_hex"] == "$EXPECTED_PUB", f"ed_pub_hex mismatch"
assert d["anon_address"] == "0x$EXPECTED_PUB", f"anon_address mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 21. --json same-passphrase-rejection schema ─────────────────────────────
echo
echo "=== 21. --json same-passphrase-rejection schema ==="
set +e
JSON_REJ=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$TMP/json_rej.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$OLD_PASS_FILE" \
    --json 2>&1)
RC=$?
set -e
JSON_REJ=$(echo "$JSON_REJ" | tr -d '\r')
assert_eq "$RC" "1" "--json same-passphrase rejection exits 1"
$PY - <<PY_EOF
import json
d = json.loads('''$JSON_REJ''')
assert d.get("rotated") is False, f"rotated should be False on same-passphrase rejection"
assert d.get("reason") == "old_and_new_passphrase_identical", f"reason: {d.get('reason')!r}"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json same-passphrase rejection schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json same-passphrase rejection schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 22. env: passphrase source for both old and new ────────────────────────
echo
echo "=== 22. env: passphrase source for both old and new ==="
ENV_ROT_OUT="$TMP/env_rot.enc"
rm -f "$ENV_ROT_OUT"
KFR_TEST_OLD="$OLD_PASS" KFR_TEST_NEW="$NEW_PASS" \
    "$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$ENV_ROT_OUT" \
    --old-passphrase-from "env:KFR_TEST_OLD" \
    --new-passphrase-from "env:KFR_TEST_NEW" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "env: source rotation exit 0"
assert_exists "$ENV_ROT_OUT" "env: source rotation produced --out"
KFR_TEST_NEW="$NEW_PASS" "$WALLET" keyfile-decrypt \
    --in "$ENV_ROT_OUT" \
    --passphrase-from "env:KFR_TEST_NEW" \
    --out "$TMP/env_dec.json" >/dev/null 2>&1
assert_eq "$?" "0" "env: rotated file decrypts under new passphrase"

# ── 23. env: unset variable rejected ───────────────────────────────────────
echo
echo "=== 23. env: unset old-passphrase var rejected ==="
unset DETERM_KFR_UNSET_OLD 2>/dev/null || true
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$TMP/env_unset_out.enc" \
    --old-passphrase-from "env:DETERM_KFR_UNSET_OLD" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unset env: variable"
assert_contains "$ERR" "not set or empty" "diagnostic identifies unset env var"

# ── 24. --passphrase-from prompt (stdin redirect) ──────────────────────────
echo
echo "=== 24. prompt source (stdin redirect) ==="
PROMPT_OUT="$TMP/prompt_rot.enc"
rm -f "$PROMPT_OUT"
# Feed two lines: old passphrase then new passphrase.
PROMPT_RC=$(printf '%s\n%s\n' "$OLD_PASS" "$NEW_PASS" | "$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$PROMPT_OUT" \
    --old-passphrase-from "prompt" \
    --new-passphrase-from "prompt" >/dev/null 2>&1; echo $?)
assert_eq "$PROMPT_RC" "0" "prompt source rotation exit 0"
if [ -s "$PROMPT_OUT" ]; then
    "$WALLET" keyfile-decrypt \
        --in "$PROMPT_OUT" \
        --passphrase-from "file:$NEW_PASS_FILE" \
        --out "$TMP/prompt_dec.json" >/dev/null 2>&1
    assert_eq "$?" "0" "prompt-rotated file decrypts with new passphrase"
else
    echo "  FAIL: prompt source did not produce --out"; fail_count=$((fail_count + 1))
fi

# ── 25. Unknown argument rejected ──────────────────────────────────────────
echo
echo "=== 25. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$TMP/unknown.enc" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown argument" "diagnostic mentions unknown argument"

# ── 26. Cross-rotation: rotate file produced by prior rotation ─────────────
echo
echo "=== 26. Chained rotation: rotate twice with three distinct passphrases ==="
PASS3_FILE="$TMP/pass3.txt"
printf '%s\n' "third-passphrase-evergreen-2027" > "$PASS3_FILE"
CHAIN_OUT="$TMP/chain.enc"
"$WALLET" keyfile-rotate \
    --in "$ROT_OUT" \
    --out "$CHAIN_OUT" \
    --old-passphrase-from "file:$NEW_PASS_FILE" \
    --new-passphrase-from "file:$PASS3_FILE" >/dev/null 2>&1
assert_eq "$?" "0" "chained rotation exit 0"
"$WALLET" keyfile-decrypt \
    --in "$CHAIN_OUT" \
    --passphrase-from "file:$PASS3_FILE" \
    --out "$TMP/chain_dec.json" >/dev/null 2>&1
assert_eq "$?" "0" "chain-rotated file decrypts under third passphrase"
CHAIN_SEED=$($PY -c "import json; print(json.load(open('$TMP/chain_dec.json'))['priv_seed'])")
assert_eq "$CHAIN_SEED" "$PRIV_HEX" "chain-rotated seed still matches original"

# Old passphrases on the chain output must all fail.
set +e
"$WALLET" keyfile-decrypt \
    --in "$CHAIN_OUT" \
    --passphrase-from "file:$NEW_PASS_FILE" \
    --out "$TMP/chain_fail_new.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "second-stage passphrase no longer decrypts after third rotation"

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-rotate"; exit 0
else
    echo "  FAIL"; exit 1
fi
