#!/usr/bin/env bash
# determ-wallet keyfile-rotate — AAD pubkey-substitution edge.
#
# EDGE UNDER TEST (genuinely uncovered):
#   `keyfile-rotate` binds the header pubkey hex into the GCM AAD when it
#   decrypts --in under the OLD passphrase (wallet/main.cpp around line
#   4194-4202: `aad = bytes(header_pubkey_hex); envelope::decrypt(...)`).
#   If an attacker substitutes the header's 64-hex pubkey with a DIFFERENT
#   but still STRUCTURALLY VALID 64-hex pubkey, every cheap structural guard
#   (magic prefix, 64-char length, valid-hex, non-empty blob, DWE1
#   deserialization) still passes — so the rejection MUST come from the AEAD
#   layer itself, NOT from a header parse error. Even with the CORRECT old
#   passphrase, decryption fails closed: exit 2 with the indistinguishable
#   "old passphrase wrong or corrupted keyfile" diagnostic, and NO --out /
#   NO staging tmp file is created (the --out write happens only after a
#   successful decrypt + re-encrypt, much later in the flow).
#
#   This is the anti-substitution / tamper-evidence property of the AAD
#   binding, exercised on the ROTATE path specifically.
#
# WHY THIS IS NOT A DUPLICATE:
#   - test_wallet_keyfile_rotate.sh step 8 ("Wrong OLD passphrase") feeds the
#     ORIGINAL header with a WRONG passphrase file. That tests passphrase
#     correctness, NOT header-AAD binding. It never substitutes the header
#     pubkey.
#   - test_wallet_keyfile_decrypt.sh step 7 tests pubkey-AAD tamper but on
#     the `keyfile-decrypt` subcommand, not `keyfile-rotate` (different code
#     path: rotate has the two-passphrase read, same-passphrase guard, and
#     the stage->tmp->rename writer — all of which must be proven to be
#     skipped on AAD failure).
#   - test_wallet_keyfile_lifecycle_fuzz.sh P5 XOR-flips the CIPHERTEXT and
#     feeds it to `keyfile-decrypt`; its hdr-check only confirms the header
#     is PRESERVED across a SUCCESSFUL rotation. Neither feeds a substituted
#     header into `keyfile-rotate`.
#   grep evidence:
#     grep -n 'keyfile-rotate' tools/test_wallet_keyfile_rotate.sh
#       -> step 8 uses --old-passphrase-from file:$WRONG_OLD_FILE with the
#          original --in (header untouched). No header-pubkey substitution.
#     grep -rn 'rotate' tools/test_wallet_keyfile_lifecycle_fuzz.sh
#       -> P3 rotate happy-path + hdr-preserved check only; P5 tamper hits
#          keyfile-decrypt, not rotate.
#
# CONTROLS (prove the layers are distinct):
#   A. Happy-path control: the SAME OLD passphrase rotates the UNTAMPERED
#      file successfully (exit 0). This proves the exit-2 above is caused by
#      the header substitution, not by a bad passphrase or a broken fixture.
#   B. Indistinguishability control: rotating the SUBSTITUTED-header file
#      with a WRONG old passphrase ALSO exits 2 with the SAME diagnostic —
#      so an attacker probing cannot tell "tampered header" from "wrong
#      passphrase".
#
# Run from repo root: bash tools/test_wallet_keyfile_rotate_aad_pubkey_substitution_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_keyfile_rotate_aad_sub.$$"
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
assert_exists() {
  if [ -e "$1" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2 (file missing: $1)"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

OLD_PASS="old-correct-horse-battery-staple-2026"
NEW_PASS="new-tower-rooftop-evergreen-2027"
WRONG_PASS="definitely-not-the-old-passphrase"
OLD_PASS_FILE="$TMP/old_pass.txt"
NEW_PASS_FILE="$TMP/new_pass.txt"
WRONG_PASS_FILE="$TMP/wrong_pass.txt"
printf '%s\n' "$OLD_PASS"   > "$OLD_PASS_FILE"
printf '%s\n' "$NEW_PASS"   > "$NEW_PASS_FILE"
printf '%s\n' "$WRONG_PASS" > "$WRONG_PASS_FILE"

# ── 1. Build the encrypted fixture (header pubkey is AAD-bound) ─────────────
echo "=== 1. Build encrypted keyfile fixture via keyfile-create ==="
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
assert_eq "$?" "0" "keyfile-create produces the fixture"
assert_exists "$ORIG_ENC" "original encrypted keyfile exists"

HEADER_LINE=$(sed -n '1p' "$ORIG_ENC" | tr -d '\r')
BLOB_LINE=$(sed -n '2p' "$ORIG_ENC" | tr -d '\r')
assert_contains "$HEADER_LINE" "DETERM-NODE-V1 $EXPECTED_PUB" "header carries the AAD-bound pubkey"

# ── 2. CONTROL A: happy-path rotate on the UNTAMPERED file (exit 0) ─────────
# Proves the exit-2 below is caused by the header substitution, not by the
# passphrase or a broken fixture. Uses the SAME OLD passphrase.
echo
echo "=== 2. CONTROL A: untampered rotate with correct OLD passphrase → exit 0 ==="
CTRL_OUT="$TMP/control_rotated.enc"
rm -f "$CTRL_OUT" "${CTRL_OUT}_tmp.json"
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$CTRL_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
assert_eq "$?" "0" "control rotate exits 0 on untampered file"
assert_exists "$CTRL_OUT" "control rotate produced --out"
# The new passphrase decrypts the control output → fixture + passphrases good.
"$WALLET" keyfile-decrypt \
    --in "$CTRL_OUT" \
    --passphrase-from "file:$NEW_PASS_FILE" \
    --out "$TMP/control_dec.json" >/dev/null 2>&1
assert_eq "$?" "0" "control: NEW passphrase decrypts the rotated file"
CTRL_SEED=$($PY -c "import json; print(json.load(open('$TMP/control_dec.json'))['priv_seed'])")
assert_eq "$CTRL_SEED" "$PRIV_HEX" "control: recovered seed matches original"

# ── 3. Build the SUBSTITUTED-header file ───────────────────────────────────
# Replace the 64-hex header pubkey with a DIFFERENT but structurally-valid
# 64-hex pubkey. The envelope blob (line 2) is preserved byte-for-byte, so
# every cheap structural guard passes; only the AAD differs.
echo
echo "=== 3. Substitute header pubkey with a valid-but-different 64-hex value ==="
# Flip the first hex nibble of the real pubkey deterministically so the
# result is guaranteed-different yet still valid hex (and not all-identical,
# which would be a weaker test).
SUB_PUB=$($PY -c "
p='$EXPECTED_PUB'
first='%x' % (int(p[0],16) ^ 1)   # XOR nibble -> different hex digit
print(first + p[1:])
")
assert_eq "${#SUB_PUB}" "64" "substituted pubkey is 64 hex chars"
if [ "$SUB_PUB" = "$EXPECTED_PUB" ]; then
    echo "  FAIL: substituted pubkey equals original (no substitution happened)"; fail_count=$((fail_count + 1))
else
    echo "  PASS: substituted pubkey differs from the AAD-bound original"; pass_count=$((pass_count + 1))
fi
SUB_ENC="$TMP/substituted_header.enc"
printf 'DETERM-NODE-V1 %s\n%s\n' "$SUB_PUB" "$BLOB_LINE" > "$SUB_ENC"

# Sanity: keyfile-info accepts the substituted file structurally (proves the
# substitution is NOT caught by any cheap structural guard — the rejection
# in step 4 therefore comes from the AEAD/AAD layer, not header parsing).
INFO_OUT=$("$WALLET" keyfile-info --in "$SUB_ENC" 2>&1 | tr -d '\r')
assert_eq "$?" "0" "keyfile-info accepts substituted file structurally (exit 0)"
assert_contains "$INFO_OUT" "pubkey_hex:        $SUB_PUB" "keyfile-info echoes the substituted pubkey (no AEAD performed)"

# ── 4. EDGE: rotate substituted-header file w/ CORRECT old passphrase → 2 ──
echo
echo "=== 4. EDGE: rotate substituted header + CORRECT old passphrase → exit 2, no leak ==="
EDGE_OUT="$TMP/edge_rotated.enc"
rm -f "$EDGE_OUT" "${EDGE_OUT}_tmp.json"
set +e
ERR=$("$WALLET" keyfile-rotate \
    --in "$SUB_ENC" \
    --out "$EDGE_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on AAD pubkey-substitution despite correct passphrase"
assert_contains "$ERR" "old passphrase wrong or corrupted keyfile" "fail-closed diagnostic (indistinguishable from wrong passphrase)"
assert_not_exists "$EDGE_OUT" "no --out leak on AAD-substitution rejection"
assert_not_exists "${EDGE_OUT}_tmp.json" "no staging tmp file leak on AAD-substitution rejection"

# ── 5. CONTROL B: substituted header + WRONG passphrase → same exit 2 ──────
# Indistinguishability: an attacker probing cannot separate "tampered header"
# from "wrong passphrase" — both produce exit 2 with the identical message.
echo
echo "=== 5. CONTROL B: substituted header + WRONG old passphrase → same exit 2 ==="
EDGE_OUT2="$TMP/edge_rotated_wrongpw.enc"
rm -f "$EDGE_OUT2" "${EDGE_OUT2}_tmp.json"
set +e
ERR2=$("$WALLET" keyfile-rotate \
    --in "$SUB_ENC" \
    --out "$EDGE_OUT2" \
    --old-passphrase-from "file:$WRONG_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" 2>&1)
RC2=$?
set -e
ERR2=$(echo "$ERR2" | tr -d '\r')
assert_eq "$RC2" "2" "wrong passphrase on substituted header also exits 2"
assert_contains "$ERR2" "old passphrase wrong or corrupted keyfile" "same diagnostic → indistinguishable"
assert_not_exists "$EDGE_OUT2" "no --out leak on wrong-passphrase + substituted header"

# ── 6. The original (untampered) file STILL rotates fine afterward ─────────
# Proves the substitution attack did not perturb the genuine fixture and the
# rejection was specific to the substituted input.
echo
echo "=== 6. Original untampered file still rotates after the edge attempts ==="
FINAL_OUT="$TMP/final_rotated.enc"
rm -f "$FINAL_OUT"
"$WALLET" keyfile-rotate \
    --in "$ORIG_ENC" \
    --out "$FINAL_OUT" \
    --old-passphrase-from "file:$OLD_PASS_FILE" \
    --new-passphrase-from "file:$NEW_PASS_FILE" >/dev/null 2>&1
assert_eq "$?" "0" "untampered original still rotates (exit 0)"
assert_exists "$FINAL_OUT" "final rotate produced --out"

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-rotate AAD pubkey-substitution edge"; exit 0
else
    echo "  FAIL"; exit 1
fi
