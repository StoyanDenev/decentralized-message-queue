#!/usr/bin/env bash
# determ-wallet keyfile-create CLI test.
#
# `keyfile-create` is the S-004 operator workflow: produce a passphrase-
# encrypted node_key.json file from a raw Ed25519 private key. The
# output is a 2-line file:
#   line 1: "DETERM-NODE-V1 <pubkey_hex>"
#   line 2: "<DWE1 envelope blob>"
# whose decrypted plaintext is the canonical daemon-side node_key.json
# shape: {"pubkey": "...", "priv_seed": "..."} (matches
# src/crypto/keys.cpp::load_node_key).
#
# Coverage:
#   - Build a fresh keypair via `account-create-batch --count 1 --json`,
#     extract the privkey hex.
#   - Generate the encrypted file with --passphrase-from file:...
#   - Verify file shape (DETERM-NODE-V1 header + valid envelope blob).
#   - Round-trip via `envelope decrypt` to recover {pubkey, priv_seed}
#     and assert it matches the original key.
#   - Verify wrong passphrase fails decrypt (AEAD tag failure).
#   - Verify AAD-tamper resistance (mutated header pubkey fails decrypt).
#   - --force overwrite semantics.
#   - Missing --out parent dir rejected.
#   - --priv length validation: too short / too long / odd / non-hex.
#   - 64-byte (seed||pubkey) form accepted when consistent; rejected on
#     pubkey mismatch.
#   - Missing required args rejected.
#   - --passphrase-from sources: file: / env: / unknown spec / empty file.
#   - --passphrase-from env: with empty env var rejected.
#   - --json summary mode emits the expected fields.
#   - Help text mentions keyfile-create.
#
# Run from repo root: bash tools/test_wallet_keyfile_create.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ to dodge MSYS path translation quirks (Python
# under Windows subprocess.run can't see /tmp paths the way the bash
# layer does).
SCRATCH="build/test_wallet_keyfile_create.$$"
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

PASSPHRASE="correct horse battery staple"
PASS_FILE="$TMP/passphrase.txt"
printf '%s\n' "$PASSPHRASE" > "$PASS_FILE"

# ── 1. Help text mentions keyfile-create ──────────────────────────────────────
echo "=== 1. Help text mentions keyfile-create ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "keyfile-create"; then
    echo "  PASS: help mentions keyfile-create"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing keyfile-create"; fail_count=$((fail_count + 1))
fi

# ── 2. Generate a fresh keypair via account-create-batch --json ───────────────
echo
echo "=== 2. Generate fresh keypair via account-create-batch ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-create-batch produces a keypair"
PRIV_HEX=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR")
assert_eq "${#PRIV_HEX}" "64" "privkey_hex is 64 hex chars (32-byte seed)"
# Address is 0x + 64 hex chars from anon-addressing.
if [ "${#ADDR}" = "66" ] && [ "${ADDR:0:2}" = "0x" ]; then
    echo "  PASS: address is 0x-prefixed 32-byte hex"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: address shape unexpected: $ADDR"; fail_count=$((fail_count + 1))
fi
EXPECTED_PUB=${ADDR#0x}

# ── 3. Happy path: keyfile-create with --passphrase-from file: ───────────────
echo
echo "=== 3. Happy path: keyfile-create with --passphrase-from file: ==="
OUT_FILE="$TMP/node_key.enc"
SUMMARY=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$OUT_FILE" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-create exit 0"
assert_contains "$SUMMARY" "DETERM-NODE-V1" "summary mentions DETERM-NODE-V1"
assert_contains "$SUMMARY" "$EXPECTED_PUB" "summary echoes pubkey hex"
if [ -s "$OUT_FILE" ]; then
    echo "  PASS: output file non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: output file missing or empty"; fail_count=$((fail_count + 1))
fi

# ── 4. Output file shape: line 1 = magic + pubkey; line 2 = envelope blob ─────
echo
echo "=== 4. File shape: DETERM-NODE-V1 header + envelope blob ==="
HEADER=$(head -n 1 "$OUT_FILE" | tr -d '\r')
BLOB=$(sed -n '2p' "$OUT_FILE" | tr -d '\r')
assert_contains "$HEADER" "DETERM-NODE-V1 " "header starts with DETERM-NODE-V1"
assert_contains "$HEADER" "$EXPECTED_PUB" "header carries pubkey hex"
# Canonical envelope blob is dot-separated lowercase hex with >= 6 parts.
N_PARTS=$(echo "$BLOB" | awk -F. '{print NF}')
if [ "$N_PARTS" -ge 6 ]; then
    echo "  PASS: envelope blob has $N_PARTS dot-separated parts (>=6)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: envelope blob has only $N_PARTS parts"; fail_count=$((fail_count + 1))
fi

# ── 5. Round-trip via `envelope decrypt`: recover {pubkey, priv_seed} ─────────
echo
echo "=== 5. Round-trip: envelope decrypt recovers canonical keyfile JSON ==="
# AAD = ASCII bytes of pubkey hex (64 chars). hex-encode as 128 chars.
AAD_HEX=$($PY -c "import sys; print(sys.argv[1].encode().hex())" "$EXPECTED_PUB")
DEC_HEX=$("$WALLET" envelope decrypt \
    --envelope "$BLOB" \
    --password "$PASSPHRASE" \
    --aad "$AAD_HEX" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "envelope decrypt succeeds with correct passphrase + AAD"
DEC_JSON=$($PY -c "import sys; print(bytes.fromhex(sys.argv[1]).decode())" "$DEC_HEX")
RECOVERED_PUB=$($PY -c "import json,sys; print(json.loads(sys.stdin.read())['pubkey'])" <<< "$DEC_JSON")
RECOVERED_SEED=$($PY -c "import json,sys; print(json.loads(sys.stdin.read())['priv_seed'])" <<< "$DEC_JSON")
assert_eq "$RECOVERED_PUB"  "$EXPECTED_PUB" "decrypted pubkey matches"
assert_eq "$RECOVERED_SEED" "$PRIV_HEX"     "decrypted priv_seed matches"

# ── 6. Wrong passphrase fails decrypt ─────────────────────────────────────────
echo
echo "=== 6. Wrong passphrase fails decrypt ==="
set +e
"$WALLET" envelope decrypt \
    --envelope "$BLOB" \
    --password "wrong-passphrase-xyz" \
    --aad "$AAD_HEX" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "envelope decrypt exit 2 with wrong passphrase"

# ── 7. AAD tamper fails decrypt (wrong pubkey in AAD) ─────────────────────────
echo
echo "=== 7. AAD tamper (different pubkey) fails decrypt ==="
TAMPER_AAD=$($PY -c "print('a'*128)")
set +e
"$WALLET" envelope decrypt \
    --envelope "$BLOB" \
    --password "$PASSPHRASE" \
    --aad "$TAMPER_AAD" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "envelope decrypt exit 2 with tampered AAD"

# ── 8. --force overwrite refused without --force ──────────────────────────────
echo
echo "=== 8. Overwrite refused without --force ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$OUT_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when --out exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"
assert_contains "$ERR" "--force" "diagnostic mentions --force"

# ── 9. --force proceeds with overwrite ────────────────────────────────────────
echo
echo "=== 9. Overwrite proceeds with --force ==="
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$OUT_FILE" \
    --force >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 with --force on existing file"

# ── 10. --out parent dir missing rejected ─────────────────────────────────────
echo
echo "=== 10. --out parent directory missing rejected ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/no_such_dir/node_key.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing parent dir"
assert_contains "$ERR" "does not exist" "diagnostic mentions does not exist"

# ── 11. --priv too short (62 chars) rejected ──────────────────────────────────
echo
echo "=== 11. --priv too short rejected ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "abc123" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/short.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --priv too short"
assert_contains "$ERR" "64 hex chars" "diagnostic mentions length expectations"

# ── 12. --priv too long (130 chars) rejected ──────────────────────────────────
echo
echo "=== 12. --priv too long rejected ==="
# 130 chars = exactly 65 bytes — neither 32 nor 64.
LONG_PRIV=$($PY -c "print('a'*130)")
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$LONG_PRIV" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/long.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --priv too long"

# ── 13. --priv odd length rejected ────────────────────────────────────────────
echo
echo "=== 13. --priv odd length rejected ==="
ODD_PRIV=$($PY -c "print('a'*65)")
set +e
"$WALLET" keyfile-create \
    --priv "$ODD_PRIV" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/odd.enc" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on --priv odd length"

# ── 14. --priv non-hex char rejected ──────────────────────────────────────────
echo
echo "=== 14. --priv non-hex char rejected ==="
NONHEX_PRIV=$($PY -c "print('zz' + 'a'*62)")
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$NONHEX_PRIV" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/nonhex.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on --priv non-hex"

# ── 15. 64-byte (seed||pubkey) form accepted when pubkey matches ──────────────
echo
echo "=== 15. 64-byte (seed||pubkey) form accepted on match ==="
FULL_PRIV="${PRIV_HEX}${EXPECTED_PUB}"
"$WALLET" keyfile-create \
    --priv "$FULL_PRIV" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/full.enc" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 with 64-byte form (seed||pubkey)"
HEADER2=$(head -n 1 "$TMP/full.enc" | tr -d '\r')
assert_contains "$HEADER2" "$EXPECTED_PUB" "64-byte form derives same pubkey"

# ── 16. 64-byte form rejected when pubkey tail does not match seed-derived ────
echo
echo "=== 16. 64-byte form rejected on pubkey mismatch ==="
WRONG_PUB=$($PY -c "print('00'*32)")
BAD_FULL_PRIV="${PRIV_HEX}${WRONG_PUB}"
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$BAD_FULL_PRIV" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/badfull.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 64-byte form pubkey mismatch"
assert_contains "$ERR" "mismatch" "diagnostic mentions mismatch"

# ── 17. Missing --priv rejected ───────────────────────────────────────────────
echo
echo "=== 17. Missing --priv rejected ==="
set +e
"$WALLET" keyfile-create \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/missing_priv.enc" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --priv"

# ── 18. Missing --passphrase-from rejected ────────────────────────────────────
echo
echo "=== 18. Missing --passphrase-from rejected ==="
set +e
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --out "$TMP/missing_pass.enc" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --passphrase-from"

# ── 19. Missing --out rejected ────────────────────────────────────────────────
echo
echo "=== 19. Missing --out rejected ==="
set +e
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --out"

# ── 20. Unknown --passphrase-from spec rejected ───────────────────────────────
echo
echo "=== 20. Unknown --passphrase-from spec rejected ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "bogus:thing" \
    --out "$TMP/bogus_src.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown --passphrase-from spec"
assert_contains "$ERR" "unknown passphrase source" "diagnostic mentions unknown source"

# ── 21. Empty passphrase file rejected ────────────────────────────────────────
echo
echo "=== 21. Empty passphrase file rejected ==="
EMPTY_PASS="$TMP/empty_pw.txt"
: > "$EMPTY_PASS"
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$EMPTY_PASS" \
    --out "$TMP/empty_pw.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty passphrase file"
assert_contains "$ERR" "empty" "diagnostic mentions empty"

# ── 22. Missing passphrase file rejected ──────────────────────────────────────
echo
echo "=== 22. Missing passphrase file rejected ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$TMP/nonexistent_pass.txt" \
    --out "$TMP/missing_file.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing passphrase file"
assert_contains "$ERR" "cannot open" "diagnostic mentions cannot open"

# ── 23. --passphrase-from env: works ──────────────────────────────────────────
echo
echo "=== 23. --passphrase-from env:NAME works ==="
rm -f "$TMP/env_src.enc"
ENV_OUT="$TMP/env_src.enc"
KEYFILE_TEST_PW="env-passphrase-correct" "$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "env:KEYFILE_TEST_PW" \
    --out "$ENV_OUT" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "exit 0 with env: source"
HEADER3=$(head -n 1 "$ENV_OUT" | tr -d '\r')
assert_contains "$HEADER3" "DETERM-NODE-V1" "env: source produces valid header"
# Round-trip the env-sourced file with the env passphrase to confirm.
ENV_BLOB=$(sed -n '2p' "$ENV_OUT" | tr -d '\r')
DEC_ENV=$("$WALLET" envelope decrypt \
    --envelope "$ENV_BLOB" \
    --password "env-passphrase-correct" \
    --aad "$AAD_HEX" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "env-sourced envelope decrypts cleanly"

# ── 24. --passphrase-from env: with unset variable rejected ───────────────────
echo
echo "=== 24. --passphrase-from env:UNSET rejected ==="
# Use a variable name almost certainly not in the shell env.
unset DETERM_WALLET_KEYFILE_TEST_NOPE 2>/dev/null || true
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "env:DETERM_WALLET_KEYFILE_TEST_NOPE" \
    --out "$TMP/env_unset.enc" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unset env var"
assert_contains "$ERR" "not set or empty" "diagnostic mentions not set or empty"

# ── 25. --json summary mode ───────────────────────────────────────────────────
echo
echo "=== 25. --json summary mode ==="
rm -f "$TMP/json_out.enc"
JSON_SUMMARY=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/json_out.enc" \
    --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
$PY - <<PY_EOF
import json, sys
d = json.loads('''$JSON_SUMMARY''')
required = {"pubkey","out","format","envelope"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["format"] == "DETERM-NODE-V1", f"bad format: {d['format']!r}"
assert d["envelope"] == "DWE1", f"bad envelope: {d['envelope']!r}"
assert d["pubkey"] == "$EXPECTED_PUB", "pubkey mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 26. Unknown argument rejected ─────────────────────────────────────────────
echo
echo "=== 26. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$TMP/unknown.enc" \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown" "diagnostic mentions unknown"

# ── 27. Plaintext inside envelope matches load_node_key schema (S-018 check) ──
echo
echo "=== 27. Decrypted plaintext is canonical node_key.json shape ==="
$PY - <<PY_EOF
import json
plaintext = bytes.fromhex("$DEC_HEX").decode()
d = json.loads(plaintext)
required = {"pubkey","priv_seed"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert isinstance(d["pubkey"], str) and len(d["pubkey"]) == 64
assert isinstance(d["priv_seed"], str) and len(d["priv_seed"]) == 64
assert all(c in "0123456789abcdef" for c in d["pubkey"])
assert all(c in "0123456789abcdef" for c in d["priv_seed"])
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: plaintext matches src/crypto/keys.cpp::load_node_key schema"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: plaintext schema drift"; fail_count=$((fail_count + 1))
fi

# ── 28. Output file is NOT created when validation fails (no leak) ────────────
echo
echo "=== 28. Output file NOT created on validation failure ==="
LEAK_OUT="$TMP/no_leak.enc"
rm -f "$LEAK_OUT"
set +e
"$WALLET" keyfile-create \
    --priv "deadbeef" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$LEAK_OUT" >/dev/null 2>&1
set -e
if [ ! -e "$LEAK_OUT" ]; then
    echo "  PASS: --out not created on validation failure"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --out leaked on validation failure"; fail_count=$((fail_count + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-create"; exit 0
else
    echo "  FAIL: test_wallet_keyfile_create"; exit 1
fi
