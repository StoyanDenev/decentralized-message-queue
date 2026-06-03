#!/usr/bin/env bash
# determ-wallet keyfile-reencrypt CLI test.
#
# `keyfile-reencrypt` rotates the passphrase on an encrypted DETERM-NODE-V1
# keyfile WITHOUT changing the keypair (on-chain identity is preserved). It
# decrypts --in under the OLD passphrase (read from a named env var), then
# re-encrypts the recovered plaintext under the NEW passphrase (named env
# var) with a FRESH random salt + nonce, and writes --out. The decrypted
# Ed25519 seed lives only in process memory — never on disk — and is zeroed
# via sodium_memzero on every exit path.
#
# Command shape:
#   determ-wallet keyfile-reencrypt --in <kf> --out <kf>
#       --old-passphrase-env OLD_VAR --new-passphrase-env NEW_VAR [--force]
#
# Required-assertion coverage (≥6 groups, per the task spec):
#   1. Create under P1; reencrypt to P2; keyfile-info on --out succeeds;
#      keyfile-decrypt with P2 recovers the SAME address as the original.
#   2. After reencrypt, decrypt with the OLD passphrase P1 → FAILS.
#   3. Wrong OLD passphrase on reencrypt → non-zero exit, no --out written.
#   4. Fresh-salt property: reencrypt twice to two outputs with the SAME new
#      passphrase → the two outputs differ byte-wise (fresh salt+nonce).
#   5. Address invariance: pubkey/address recovered post-reencrypt ==
#      original (printed by the command + asserted here).
#   6. --out exists without --force → refuse + non-zero; with --force →
#      overwrite.
#   7. Missing/empty new passphrase env → reject with a helpful diagnostic.
# Plus auxiliary coverage: help text mention, --json schema, missing flags,
# missing --in file, malformed --in, unknown argument.
#
# Run from repo root: bash tools/test_wallet_keyfile_reencrypt.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_keyfile_reencrypt.$$"
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

P1="old-correct-horse-battery-staple"
P2="new-tower-rooftop-evergreen-2026"
# Passphrases are injected via env vars (the command takes bare var NAMES).
export KFRE_OLD="$P1"
export KFRE_NEW="$P2"

# ── 0. Help text mentions keyfile-reencrypt ─────────────────────────────────
echo "=== 0. Help text mentions keyfile-reencrypt ==="
H=$("$WALLET" help 2>&1)
assert_contains "$H" "keyfile-reencrypt" "help mentions keyfile-reencrypt"

# ── Build a fresh keypair + encrypted keyfile under P1 ──────────────────────
echo
echo "=== setup: build keypair + encrypted keyfile (under P1) ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
PRIV_HEX=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR")
EXPECTED_PUB=${ADDR#0x}
assert_eq "${#PRIV_HEX}" "64" "fresh privkey_hex is 64 chars"
assert_eq "${#EXPECTED_PUB}" "64" "fresh pubkey hex is 64 chars"

# keyfile-create reads the passphrase via --passphrase-from; we feed it the
# OLD passphrase from the same env var the reencrypt path will use.
ORIG_ENC="$TMP/node_key.enc"
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "env:KFRE_OLD" \
    --out "$ORIG_ENC" >/dev/null 2>&1
assert_eq "$?" "0" "keyfile-create produces the P1 fixture"
assert_exists "$ORIG_ENC" "original encrypted keyfile exists"
ORIG_BLOB=$(sed -n '2p' "$ORIG_ENC" | tr -d '\r')
ORIG_HEADER=$(sed -n '1p' "$ORIG_ENC" | tr -d '\r')
assert_ne "$ORIG_BLOB" "" "original envelope blob is non-empty"

# ── ASSERTION 1: reencrypt P1→P2; keyfile-info OK; decrypt P2 same address ──
echo
echo "=== 1. reencrypt P1->P2; keyfile-info OK; decrypt(P2) recovers same addr ==="
OUT1="$TMP/reenc_p2.enc"
SUMMARY=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" \
    --out "$OUT1" \
    --old-passphrase-env KFRE_OLD \
    --new-passphrase-env KFRE_NEW 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-reencrypt exit 0 on happy path"
assert_contains "$SUMMARY" "keyfile_reencrypted=YES" "summary reports YES"
assert_exists "$OUT1" "reencrypted keyfile exists at --out"
assert_exists "$ORIG_ENC" "original --in still exists (reencrypt did not consume it)"

# keyfile-info on the output must succeed and report the SAME pubkey.
INFO=$("$WALLET" keyfile-info --in "$OUT1" --json 2>&1 | tr -d '\r')
assert_eq "$?" "0" "keyfile-info on reencrypted output succeeds"
INFO_PUB=$($PY -c "import json,sys; print(json.loads(sys.stdin.read())['pubkey_hex'])" <<< "$INFO")
assert_eq "$INFO_PUB" "$EXPECTED_PUB" "keyfile-info reports the original pubkey"

# keyfile-decrypt with P2 recovers the same address (pubkey) + same seed.
DEC_P2="$TMP/recovered_p2.json"
"$WALLET" keyfile-decrypt \
    --in "$OUT1" \
    --passphrase-from "env:KFRE_NEW" \
    --out "$DEC_P2" >/dev/null 2>&1
assert_eq "$?" "0" "decrypt with P2 exits 0"
REC_PUB=$($PY -c "import json; print(json.load(open('$DEC_P2'))['pubkey'])")
REC_SEED=$($PY -c "import json; print(json.load(open('$DEC_P2'))['priv_seed'])")
assert_eq "$REC_PUB" "$EXPECTED_PUB" "decrypt(P2) recovers the SAME address as original"
assert_eq "$REC_SEED" "$PRIV_HEX" "decrypt(P2) recovers the SAME private seed as original"

# ── ASSERTION 2: OLD passphrase P1 no longer decrypts the new file ──────────
echo
echo "=== 2. After reencrypt, decrypt with OLD passphrase P1 FAILS ==="
set +e
ERR=$("$WALLET" keyfile-decrypt \
    --in "$OUT1" \
    --passphrase-from "env:KFRE_OLD" \
    --out "$TMP/should_not_exist.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "OLD passphrase P1 exits 2 on the reencrypted file"
assert_contains "$ERR" "wrong passphrase or corrupted keyfile" "OLD-passphrase diagnostic"
assert_not_exists "$TMP/should_not_exist.json" "no --out leak when OLD passphrase fails"

# ── ASSERTION 3: wrong OLD passphrase on reencrypt → non-zero, no output ────
echo
echo "=== 3. Wrong OLD passphrase on reencrypt -> exit 2, no --out written ==="
export KFRE_WRONG="definitely-not-the-old-passphrase"
WRONG_OUT="$TMP/wrong_reenc.enc"
rm -f "$WRONG_OUT"
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" \
    --out "$WRONG_OUT" \
    --old-passphrase-env KFRE_WRONG \
    --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on wrong OLD passphrase"
assert_contains "$ERR" "old passphrase wrong or corrupted keyfile" "wrong-OLD-passphrase diagnostic"
assert_not_exists "$WRONG_OUT" "no --out written on wrong OLD passphrase"

# ── ASSERTION 4: fresh salt — two reencrypts to two outputs differ ──────────
echo
echo "=== 4. Fresh-salt: reencrypt twice (same new passphrase) -> outputs differ ==="
OUT_A="$TMP/fresh_a.enc"
OUT_B="$TMP/fresh_b.enc"
rm -f "$OUT_A" "$OUT_B"
"$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$OUT_A" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW >/dev/null 2>&1
assert_eq "$?" "0" "first fresh-salt reencrypt exit 0"
"$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$OUT_B" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW >/dev/null 2>&1
assert_eq "$?" "0" "second fresh-salt reencrypt exit 0"
BLOB_A=$(sed -n '2p' "$OUT_A" | tr -d '\r')
BLOB_B=$(sed -n '2p' "$OUT_B" | tr -d '\r')
assert_ne "$BLOB_A" "$BLOB_B" "two reencrypt outputs differ byte-wise (fresh salt+nonce)"
assert_ne "$BLOB_A" "$ORIG_BLOB" "reencrypt output differs from the original blob too"
# Both must still decrypt under P2 to the SAME seed (distinct envelope, same key).
"$WALLET" keyfile-decrypt --in "$OUT_A" --passphrase-from "env:KFRE_NEW" --out "$TMP/fa.json" >/dev/null 2>&1
"$WALLET" keyfile-decrypt --in "$OUT_B" --passphrase-from "env:KFRE_NEW" --out "$TMP/fb.json" >/dev/null 2>&1
SEED_A=$($PY -c "import json; print(json.load(open('$TMP/fa.json'))['priv_seed'])")
SEED_B=$($PY -c "import json; print(json.load(open('$TMP/fb.json'))['priv_seed'])")
assert_eq "$SEED_A" "$PRIV_HEX" "first  distinct-salt output decrypts to original seed"
assert_eq "$SEED_B" "$PRIV_HEX" "second distinct-salt output decrypts to original seed"

# ── ASSERTION 5: address invariance (printed + asserted) ────────────────────
echo
echo "=== 5. Address invariance: printed pubkey/address == original ==="
# The human summary echoes the ed_pub_hex + anon address; the --json mode
# carries them as fields. Assert both.
assert_contains "$SUMMARY" "$EXPECTED_PUB" "human summary echoes the original pubkey hex"
assert_contains "$SUMMARY" "0x$EXPECTED_PUB" "human summary echoes the original anon address"
JSUM=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$TMP/json_inv.enc" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW \
    --json 2>&1 | tr -d '\r')
assert_eq "$?" "0" "--json reencrypt exit 0"
J_PUB=$($PY -c "import json,sys; print(json.loads(sys.stdin.read())['ed_pub_hex'])" <<< "$JSUM")
J_ADDR=$($PY -c "import json,sys; print(json.loads(sys.stdin.read())['anon_address'])" <<< "$JSUM")
assert_eq "$J_PUB" "$EXPECTED_PUB" "--json ed_pub_hex == original pubkey"
assert_eq "$J_ADDR" "0x$EXPECTED_PUB" "--json anon_address == original address"
# Header preserved byte-for-byte across the rotation.
OUT1_HEADER=$(sed -n '1p' "$OUT1" | tr -d '\r')
assert_eq "$OUT1_HEADER" "$ORIG_HEADER" "header (pubkey) preserved byte-for-byte across reencrypt"

# ── ASSERTION 6: --out overwrite guard (refuse w/o --force; allow w/ --force)─
echo
echo "=== 6. --out exists: refuse without --force, overwrite with --force ==="
# OUT1 already exists from assertion 1.
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$OUT1" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when --out exists without --force"
assert_contains "$ERR" "already exists" "diagnostic mentions already exists"
assert_contains "$ERR" "--force" "diagnostic mentions --force"
# Capture the pre-overwrite blob so we can prove --force actually replaced it.
PRE_FORCE_BLOB=$(sed -n '2p' "$OUT1" | tr -d '\r')
"$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$OUT1" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW \
    --force >/dev/null 2>&1
assert_eq "$?" "0" "--force on existing --out exits 0"
POST_FORCE_BLOB=$(sed -n '2p' "$OUT1" | tr -d '\r')
assert_ne "$PRE_FORCE_BLOB" "$POST_FORCE_BLOB" "--force actually overwrote the file (fresh blob)"

# ── ASSERTION 7: missing / empty NEW passphrase env → reject ────────────────
echo
echo "=== 7. Missing/empty new passphrase env -> reject with diagnostic ==="
# 7a: NEW env var unset.
unset KFRE_UNSET_NEW 2>/dev/null || true
NO_NEW_OUT="$TMP/no_new_env.enc"
rm -f "$NO_NEW_OUT"
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$NO_NEW_OUT" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_UNSET_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when NEW passphrase env var is unset"
assert_contains "$ERR" "not set or empty" "diagnostic identifies the unset NEW env var"
assert_contains "$ERR" "new passphrase" "diagnostic attributes failure to the NEW passphrase"
assert_not_exists "$NO_NEW_OUT" "no --out written when NEW env var unset"
# 7b: NEW env var set but empty.
export KFRE_EMPTY_NEW=""
EMPTY_NEW_OUT="$TMP/empty_new_env.enc"
rm -f "$EMPTY_NEW_OUT"
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$EMPTY_NEW_OUT" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_EMPTY_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when NEW passphrase env var is empty"
assert_not_exists "$EMPTY_NEW_OUT" "no --out written when NEW env var empty"
# 7c: OLD env var unset is likewise rejected (symmetry).
unset KFRE_UNSET_OLD 2>/dev/null || true
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$TMP/no_old_env.enc" \
    --old-passphrase-env KFRE_UNSET_OLD --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when OLD passphrase env var is unset"
assert_contains "$ERR" "old passphrase" "diagnostic attributes failure to the OLD passphrase"

# ── 8. Missing required flags rejected ──────────────────────────────────────
echo
echo "=== 8. Missing required flags rejected ==="
set +e
"$WALLET" keyfile-reencrypt --out "$TMP/x.enc" --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW >/dev/null 2>&1
assert_eq "$?" "1" "exit 1 on missing --in"
"$WALLET" keyfile-reencrypt --in "$ORIG_ENC" --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW >/dev/null 2>&1
assert_eq "$?" "1" "exit 1 on missing --out"
"$WALLET" keyfile-reencrypt --in "$ORIG_ENC" --out "$TMP/x.enc" --new-passphrase-env KFRE_NEW >/dev/null 2>&1
assert_eq "$?" "1" "exit 1 on missing --old-passphrase-env"
"$WALLET" keyfile-reencrypt --in "$ORIG_ENC" --out "$TMP/x.enc" --old-passphrase-env KFRE_OLD >/dev/null 2>&1
assert_eq "$?" "1" "exit 1 on missing --new-passphrase-env"
set -e

# ── 9. --in file does not exist → exit 1 ────────────────────────────────────
echo
echo "=== 9. --in file does not exist rejected ==="
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$TMP/no_such_file.enc" --out "$TMP/ne_out.enc" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in file"
assert_contains "$ERR" "cannot open --in" "diagnostic mentions cannot open --in"

# ── 10. Malformed --in: wrong header magic ──────────────────────────────────
echo
echo "=== 10. Malformed --in: wrong header magic rejected ==="
BAD_HEADER_IN="$TMP/bad_header.enc"
printf 'DETERM-FORK-V99 %s\n' "$EXPECTED_PUB" > "$BAD_HEADER_IN"
echo "dummyblob" >> "$BAD_HEADER_IN"
BAD_OUT="$TMP/bad_header_out.enc"
rm -f "$BAD_OUT"
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$BAD_HEADER_IN" --out "$BAD_OUT" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on wrong header magic"
assert_contains "$ERR" "DETERM-NODE-V1" "diagnostic names the expected magic"
assert_not_exists "$BAD_OUT" "no --out written on malformed --in"

# ── 11. Malformed --in: empty file ──────────────────────────────────────────
echo
echo "=== 11. Malformed --in: empty file rejected ==="
EMPTY_IN="$TMP/empty.enc"
: > "$EMPTY_IN"
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$EMPTY_IN" --out "$TMP/empty_out.enc" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on empty --in"
assert_contains "$ERR" "empty" "empty-file diagnostic"

# ── 12. Unknown argument rejected ───────────────────────────────────────────
echo
echo "=== 12. Unknown argument rejected ==="
set +e
ERR=$("$WALLET" keyfile-reencrypt \
    --in "$ORIG_ENC" --out "$TMP/u.enc" \
    --old-passphrase-env KFRE_OLD --new-passphrase-env KFRE_NEW \
    --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown argument" "diagnostic mentions unknown argument"

# ── 13. --json schema well-formed ───────────────────────────────────────────
echo
echo "=== 13. --json summary schema ==="
$PY - <<PY_EOF
import json
d = json.loads('''$JSUM''')
required = {"reencrypted","anon_address","ed_pub_hex","in","out",
            "old_passphrase_env","new_passphrase_env"}
missing = required - set(d.keys())
assert not missing, f"missing fields: {missing}"
assert d["reencrypted"] is True, f"reencrypted should be True; got {d['reencrypted']!r}"
assert d["ed_pub_hex"] == "$EXPECTED_PUB", "ed_pub_hex mismatch"
assert d["anon_address"] == "0x$EXPECTED_PUB", "anon_address mismatch"
assert d["old_passphrase_env"] == "KFRE_OLD", "old_passphrase_env mismatch"
assert d["new_passphrase_env"] == "KFRE_NEW", "new_passphrase_env mismatch"
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: --json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-reencrypt"; exit 0
else
    echo "  FAIL"; exit 1
fi
