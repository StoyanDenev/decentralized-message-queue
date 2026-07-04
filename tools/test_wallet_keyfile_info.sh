#!/usr/bin/env bash
# determ-wallet keyfile-info passive diagnostic CLI test.
#
# `keyfile-info` is the S-004 passive complement to `inspect-envelope`:
# it parses a 2-line encrypted node keyfile (DETERM-NODE-V1 header + a
# DWE1/DWE2 envelope blob) and dumps the metadata WITHOUT decrypting (no
# passphrase, no plaintext recovery). R58: fresh keyfiles are Argon2id
# (DWE2); the DWE1 (PBKDF2) read path stays covered by the envelope
# format-freeze guard's pinned blobs.
#
# Coverage:
#   - Build a fresh encrypted keyfile via the existing `keyfile-create` CLI.
#   - Verify the diagnostic emits header_version, pubkey_hex, anon-address,
#     and envelope metadata (pbkdf2_iters, salt_len, nonce_len, ct_len,
#     aad_present) — both human and --json forms.
#   - Pubkey in output matches the pubkey baked into the keyfile (echoed
#     from account-create-batch).
#   - Anon-address is "0x" + pubkey_hex (matches the daemon-side
#     make_anon_address contract).
#   - --json is well-formed and parses with python json.loads, and the
#     nested `envelope` sub-object carries the expected fields.
#   - Tamper scenarios:
#       * Header magic tampered → exit 2 ("not a canonical encrypted node keyfile").
#       * Header pubkey truncated → exit 2.
#       * Header pubkey non-hex → exit 2.
#       * Envelope-blob tampered → exit 2.
#       * Missing envelope-blob line (1-line file) → exit 2.
#       * Empty file → exit 2.
#       * Missing --in file → exit 1.
#       * Missing --in argument → exit 1.
#       * Unknown argument → exit 1.
#   - Round-trip: a keyfile that passes keyfile-info STILL decrypts via
#     keyfile-decrypt (the diagnostic doesn't perturb the file).
#   - Help text mentions keyfile-info.
#
# Exit-code contract (encoded into the test asserts):
#   0 — valid keyfile shape, metadata emitted.
#   1 — file-system / argparse error (missing file, no --in).
#   2 — structural malformation (wrong header, bad pubkey hex, bad envelope).
#
# Run from repo root: bash tools/test_wallet_keyfile_info.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ to dodge MSYS path translation quirks.
SCRATCH="build/test_wallet_keyfile_info.$$"
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
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

PASSPHRASE="correct horse battery staple"
PASS_FILE="$TMP/passphrase.txt"
printf '%s\n' "$PASSPHRASE" > "$PASS_FILE"

# ── 1. Help text mentions keyfile-info ────────────────────────────────────────
echo "=== 1. Help text mentions keyfile-info ==="
H=$("$WALLET" help 2>&1)
if echo "$H" | grep -q "keyfile-info"; then
    echo "  PASS: help mentions keyfile-info"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing keyfile-info"; fail_count=$((fail_count + 1))
fi

# ── 2. Fixture: generate a fresh keypair + keyfile via existing CLIs ──────────
echo
echo "=== 2. Fixture: generate fresh keyfile via keyfile-create ==="
KEYPAIR=$("$WALLET" account-create-batch --count 1 --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "account-create-batch produces a keypair"
PRIV_HEX=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['privkey_hex'])" <<< "$KEYPAIR")
ADDR=$($PY -c "import json,sys; d=json.loads(sys.stdin.read()); print(d['accounts'][0]['address'])" <<< "$KEYPAIR")
EXPECTED_PUB=${ADDR#0x}
KEYFILE="$TMP/node_key.enc"
"$WALLET" keyfile-create \
    --priv "$PRIV_HEX" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$KEYFILE" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "keyfile-create succeeds"
if [ -s "$KEYFILE" ]; then
    echo "  PASS: fixture keyfile non-empty"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: fixture keyfile empty"; fail_count=$((fail_count + 1))
fi

# ── 3. Happy path: keyfile-info human output ──────────────────────────────────
echo
echo "=== 3. Happy path: human-readable keyfile-info ==="
OUT=$("$WALLET" keyfile-info --in "$KEYFILE" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "keyfile-info exit 0"
assert_contains "$OUT" "header_version:    DETERM-NODE-V1" "reports header_version"
assert_contains "$OUT" "pubkey_hex:        $EXPECTED_PUB" "reports correct pubkey hex"
assert_contains "$OUT" "anon_address:      0x$EXPECTED_PUB" "anon-address = 0x + pubkey"
# R58: keyfile-create now defaults to the memory-hard Argon2id KDF (DWE2).
assert_contains "$OUT" "DWE2 (version 2)" "reports envelope format (Argon2id default)"
assert_contains "$OUT" "kdf:             argon2id" "reports argon2id kdf"
assert_contains "$OUT" "salt_len:        16 bytes" "reports 16-byte salt"
assert_contains "$OUT" "nonce_len:       12 bytes" "reports 12-byte nonce"
assert_contains "$OUT" "aad_present:     true" "reports aad_present=true (header pubkey AAD)"
assert_contains "$OUT" "argon2_t_cost:" "reports argon2_t_cost"

# ── 4. --json output is well-formed and carries the expected schema ──────────
echo
echo "=== 4. --json output ==="
JSON=$("$WALLET" keyfile-info --in "$KEYFILE" --json 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--json exit 0"
assert_contains "$JSON" "\"valid\":true" "json valid=true"
assert_contains "$JSON" "\"header_version\":\"DETERM-NODE-V1\"" "json header_version"
assert_contains "$JSON" "\"pubkey_hex\":\"$EXPECTED_PUB\"" "json pubkey_hex matches"
assert_contains "$JSON" "\"anon_address\":\"0x$EXPECTED_PUB\"" "json anon_address matches"
assert_contains "$JSON" "\"aad_present\":true" "json aad_present=true"
assert_contains "$JSON" "\"nonce_len\":12" "json nonce_len=12"
assert_contains "$JSON" "\"salt_len\":16" "json salt_len=16"

# Validate JSON parses with python and the nested envelope shape is correct.
$PY - <<PY_EOF
import json, sys
d = json.loads('''$JSON''')
assert d["valid"] is True
assert d["header_version"] == "DETERM-NODE-V1"
assert d["pubkey_hex"] == "$EXPECTED_PUB"
assert d["anon_address"] == "0x$EXPECTED_PUB"
env = d["envelope"]
# R58: keyfiles now use Argon2id (DWE2). The envelope carries the format +
# kdf tag and both KDF param sets (the inactive one reads 0).
required = {"format","kdf","argon2_t_cost","argon2_m_cost_kib","argon2_lanes",
            "pbkdf2_iters","salt_len","nonce_len","ct_len","aad_present"}
missing = required - set(env.keys())
assert not missing, f"missing envelope fields: {missing}"
assert env["format"] == "DWE2"
assert env["kdf"] == "argon2id"
assert env["nonce_len"] == 12
assert env["salt_len"] == 16
assert env["argon2_t_cost"] > 0
assert env["argon2_m_cost_kib"] > 0
assert env["argon2_lanes"] > 0
assert env["ct_len"] > 0
assert env["aad_present"] is True
PY_EOF
if [ $? = 0 ]; then
    echo "  PASS: json schema + python parse + nested envelope fields"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: json schema malformed"; fail_count=$((fail_count + 1))
fi

# ── 5. No --passphrase-from is required (passive diagnostic) ──────────────────
echo
echo "=== 5. keyfile-info does NOT require a passphrase ==="
# The dispatch above ran without --passphrase-from and exited 0. Mark as
# an explicit regression marker so the contract is documented.
echo "  PASS: --passphrase-from not required (covered by tests 3-4)"
pass_count=$((pass_count + 1))

# ── 6. Header tamper: wrong magic prefix → exit 2 ─────────────────────────────
echo
echo "=== 6. Header magic tampered → exit 2 ==="
TAMPER_MAGIC="$TMP/tamper_magic.enc"
# Replace "DETERM-NODE-V1" with "DETERM-NODE-V9" (wrong-magic header).
sed 's/^DETERM-NODE-V1/DETERM-NODE-V9/' "$KEYFILE" > "$TAMPER_MAGIC"
set +e
"$WALLET" keyfile-info --in "$TAMPER_MAGIC" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$TAMPER_MAGIC" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on tampered header magic"
assert_contains "$ERR" "DETERM-NODE-V1" "diagnostic mentions expected magic"

# ── 7. Header pubkey truncated → exit 2 ───────────────────────────────────────
echo
echo "=== 7. Header pubkey truncated → exit 2 ==="
TRUNC_HDR="$TMP/trunc_hdr.enc"
# Drop the last 8 hex chars of the 64-hex header pubkey.
HEADER_LINE=$(head -n 1 "$KEYFILE" | tr -d '\r')
BLOB_LINE=$(sed -n '2p' "$KEYFILE" | tr -d '\r')
SHORT_HEADER=${HEADER_LINE:0:$((${#HEADER_LINE} - 8))}
printf '%s\n%s\n' "$SHORT_HEADER" "$BLOB_LINE" > "$TRUNC_HDR"
set +e
"$WALLET" keyfile-info --in "$TRUNC_HDR" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$TRUNC_HDR" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on truncated header pubkey"
assert_contains "$ERR" "64 hex chars" "diagnostic mentions 64-hex requirement"

# ── 8. Header pubkey non-hex → exit 2 ─────────────────────────────────────────
echo
echo "=== 8. Header pubkey non-hex → exit 2 ==="
NONHEX_HDR="$TMP/nonhex_hdr.enc"
# Replace the first pubkey char with a non-hex letter ('z').
BAD_PUB="z${EXPECTED_PUB:1}"
printf 'DETERM-NODE-V1 %s\n%s\n' "$BAD_PUB" "$BLOB_LINE" > "$NONHEX_HDR"
set +e
"$WALLET" keyfile-info --in "$NONHEX_HDR" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$NONHEX_HDR" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on non-hex header pubkey"
assert_contains "$ERR" "not valid hex" "diagnostic mentions invalid hex"

# ── 9. Envelope-blob tampered (still parses header but envelope fails) → 2 ────
echo
echo "=== 9. Envelope-blob tampered (header intact) → exit 2 ==="
BLOB_TAMPER="$TMP/blob_tamper.enc"
# Replace the envelope blob with junk that still has multiple dots but
# fails the DWE1 magic check inside envelope::deserialize. Header stays
# canonical so we exercise the post-header envelope-failure path.
printf '%s\ndeadbeef.00112233.10270000.000102030405060708090a0b.cafebabe.00112233\n' \
    "$HEADER_LINE" > "$BLOB_TAMPER"
set +e
"$WALLET" keyfile-info --in "$BLOB_TAMPER" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$BLOB_TAMPER" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on tampered envelope blob"
assert_contains "$ERR" "malformed" "diagnostic mentions malformed"

# ── 10. Single-line file (missing envelope blob) → exit 2 ─────────────────────
echo
echo "=== 10. Missing envelope-blob line → exit 2 ==="
ONE_LINE="$TMP/one_line.enc"
printf '%s\n' "$HEADER_LINE" > "$ONE_LINE"
set +e
"$WALLET" keyfile-info --in "$ONE_LINE" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$ONE_LINE" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on missing envelope-blob line"
assert_contains "$ERR" "missing the envelope-blob" "diagnostic mentions missing envelope-blob"

# ── 11. Empty file → exit 2 (structurally malformed) ──────────────────────────
echo
echo "=== 11. Empty file → exit 2 ==="
EMPTY_FILE="$TMP/empty.enc"
: > "$EMPTY_FILE"
set +e
"$WALLET" keyfile-info --in "$EMPTY_FILE" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$EMPTY_FILE" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "exit 2 on empty file"
assert_contains "$ERR" "empty" "diagnostic mentions empty"

# ── 12. Missing file → exit 1 (file-system error) ─────────────────────────────
echo
echo "=== 12. Missing --in file → exit 1 ==="
MISSING="$TMP/does_not_exist.enc"
set +e
"$WALLET" keyfile-info --in "$MISSING" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" keyfile-info --in "$MISSING" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing file"
assert_contains "$ERR" "cannot open" "diagnostic mentions cannot open"

# ── 13. Missing --in argument → exit 1 ────────────────────────────────────────
echo
echo "=== 13. Missing --in argument → exit 1 ==="
set +e
"$WALLET" keyfile-info >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on missing --in"

# ── 14. Unknown argument → exit 1 ─────────────────────────────────────────────
echo
echo "=== 14. Unknown argument → exit 1 ==="
set +e
ERR=$("$WALLET" keyfile-info --in "$KEYFILE" --bogus-flag 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on unknown argument"
assert_contains "$ERR" "unknown" "diagnostic mentions unknown"

# ── 15. Diagnostic is read-only: keyfile-decrypt STILL works post-info ────────
echo
echo "=== 15. keyfile-info is read-only (decrypt still works) ==="
DEC_OUT="$TMP/decrypted_node_key.json"
"$WALLET" keyfile-decrypt \
    --in "$KEYFILE" \
    --passphrase-from "file:$PASS_FILE" \
    --out "$DEC_OUT" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "keyfile-decrypt still succeeds on the same file"
RECOVERED_PUB=$($PY -c "import json,sys; print(json.loads(open(sys.argv[1]).read())['pubkey'])" "$DEC_OUT")
RECOVERED_SEED=$($PY -c "import json,sys; print(json.loads(open(sys.argv[1]).read())['priv_seed'])" "$DEC_OUT")
assert_eq "$RECOVERED_PUB"  "$EXPECTED_PUB" "round-tripped pubkey matches fixture"
assert_eq "$RECOVERED_SEED" "$PRIV_HEX"     "round-tripped priv_seed matches fixture"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet keyfile-info"; exit 0
else
    echo "  FAIL: test_wallet_keyfile_info"; exit 1
fi
