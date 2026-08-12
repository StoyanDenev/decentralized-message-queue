#!/usr/bin/env bash
# determ-wallet backup-verify — structural verification of a complete
# wallet backup (DSS1 shares + DBE1 envelopes) WITHOUT decrypting.
#
# D2 REWRITE: the at-rest backup pair is binary — DSS1 (shares) + DBE1
# (per-share envelopes). Fixtures are produced by the PRODUCTION writer
# (backup-create) and then byte-tampered, so the gate pins the decoder's
# structural invariants at the CLI boundary:
#
#   1.  Help mentions backup-verify.
#   2.  Valid backup passes (human mode) with metadata.
#   3.  Valid backup passes (--json) with schema fields.
#   4.  --threshold met → [OK]; 5. --threshold > count → [INFO], exit 0.
#   6.  Envelope-count / share-count mismatch (drop last DBE1 record) → 2.
#   7.  Corrupted embedded envelope magic → exit 2.
#   8.  Duplicate share_index in DBE1 → exit 2.
#   9.  Renumbered envelope (mapping not 1:1) → exit 2.
#  10.  Missing --shares file → exit 1; 11. missing --envelopes → exit 1.
#  12.  Non-DSS1 shares file → exit 2; 13. non-DBE1 envelopes file → exit 2.
#  14.  Legacy JSON shares/envelopes files → exit 2 (deleted format).
#  15.  --json on invalid input → valid=false + non-empty errors.
#  16.  NEVER outputs decrypted material (share y bytes absent).
#  17.  count=0 DBE1 → exit 2.
#  18.  Argon2id (DWE2) envelope params reported in --json.
#
# Run from repo root: bash tools/test_wallet_backup_verify.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PY=python
command -v python >/dev/null 2>&1 || PY=python3

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
bv_rc() {  # bv_rc <shares> <envelopes> [extra...] -> echoes exit code
  local sfile="$1" efile="$2"; shift 2
  set +e
  "$WALLET" backup-verify --shares "$sfile" --envelopes "$efile" "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

echo "=== 1. Help text mentions backup-verify ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
case "$H" in
  *backup-verify*) echo "  PASS: help mentions backup-verify"; pass_count=$((pass_count + 1)) ;;
  *) echo "  FAIL: help missing backup-verify"; fail_count=$((fail_count + 1)) ;;
esac

echo
echo "=== Setup: production backup-create emits the DSS1 + DBE1 pair ==="
SECRET="deadbeefcafebabe0011223344556677"
cat > "$TMP/keyholders.json" <<'EOF'
{"keyholders":[
  {"share_index":1,"passphrase":"kh-pw-1"},
  {"share_index":2,"passphrase":"kh-pw-2"},
  {"share_index":3,"passphrase":"kh-pw-3"},
  {"share_index":4,"passphrase":"kh-pw-4"},
  {"share_index":5,"passphrase":"kh-pw-5"}]}
EOF
"$WALLET" backup-create --secret "$SECRET" --threshold 3 \
    --keyholders "$TMP/keyholders.json" \
    --shares-out "$TMP/shares.bin" --envelopes-out "$TMP/envs.bin" >/dev/null
if [ ! -s "$TMP/shares.bin" ] || [ ! -s "$TMP/envs.bin" ]; then
    echo "  FAIL: backup-create did not produce the fixture pair"; exit 1
fi
echo "  wrote $TMP/shares.bin + $TMP/envs.bin"

echo
echo "=== 2. Valid backup passes (human mode) ==="
OUT=$("$WALLET" backup-verify --shares "$TMP/shares.bin" --envelopes "$TMP/envs.bin" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on valid backup"
assert_contains "$OUT" "Shares file:"    "human header line present"
assert_contains "$OUT" "5"               "reports 5 shares"
assert_contains "$OUT" "1:1"             "1:1 mapping confirmed"

echo
echo "=== 3. Valid backup passes (--json) with schema ==="
JSON=$("$WALLET" backup-verify --shares "$TMP/shares.bin" --envelopes "$TMP/envs.bin" --json | tr -d '\r')
echo "$JSON" | $PY -c '
import json, sys
d = json.loads(sys.stdin.read())
assert d["valid"] is True
assert d["share_count"] == 5
assert d["envelope_count"] == 5
assert len(d["envelope_details"]) == 5
assert d["errors"] == []
'
if [ $? = 0 ]; then
  echo "  PASS: --json schema correct"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: --json schema wrong: $JSON"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. --threshold met → exit 0 ==="
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs.bin" --threshold 3)" "0" "threshold met exit 0"

echo
echo "=== 5. --threshold > count → still exit 0 (informational) ==="
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs.bin" --threshold 99)" "0" "threshold 99 informational exit 0"

echo
echo "=== 6. Envelope count mismatch (drop last DBE1 record) → exit 2 ==="
$PY - "$TMP/envs.bin" "$TMP/envs_drop.bin" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
count = d[4]
# Walk to the start of the LAST record and truncate there; count -= 1.
off = 5
for _ in range(count - 1):
    n = int.from_bytes(d[off+1:off+5], "little")
    off += 5 + n
d2 = d[:off]
d2[4] = count - 1
open(sys.argv[2], "wb").write(bytes(d2))
PY_EOF
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs_drop.bin")" "2" "4 envelopes vs 5 shares rejected"

echo
echo "=== 7. Corrupted embedded envelope magic → exit 2 ==="
$PY - "$TMP/envs.bin" "$TMP/envs_magic.bin" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
# First record's embedded envelope magic starts at offset 5 + 1 + 4.
d[10] = ord("X")
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs_magic.bin")" "2" "corrupted embedded magic rejected"

echo
echo "=== 8. Duplicate share_index in DBE1 → exit 2 ==="
$PY - "$TMP/envs.bin" "$TMP/envs_dup.bin" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
# Record 2's index byte := record 1's.
n1 = int.from_bytes(d[6:10], "little")
d[5 + 5 + n1] = d[5]
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs_dup.bin")" "2" "duplicate share_index rejected"

echo
echo "=== 9. Renumbered envelope (mapping not 1:1) → exit 2 ==="
$PY - "$TMP/envs.bin" "$TMP/envs_renum.bin" <<'PY_EOF'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
# Record 1's index := 99 (valid range, DISTINCT — but not a share x).
d[5] = 99
open(sys.argv[2], "wb").write(bytes(d))
PY_EOF
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs_renum.bin")" "2" "non-1:1 mapping rejected"

echo
echo "=== 10. Missing --shares file → exit 1 ==="
assert_eq "$(bv_rc "$TMP/nope.bin" "$TMP/envs.bin")" "1" "missing shares file exits 1"

echo
echo "=== 11. Missing --envelopes file → exit 1 ==="
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/nope.bin")" "1" "missing envelopes file exits 1"

echo
echo "=== 12. Non-DSS1 shares file → exit 2 ==="
printf 'garbage not a container\n' > "$TMP/bad_shares.bin"
assert_eq "$(bv_rc "$TMP/bad_shares.bin" "$TMP/envs.bin")" "2" "non-DSS1 shares rejected"

echo
echo "=== 13. Non-DBE1 envelopes file → exit 2 ==="
printf 'garbage not a container\n' > "$TMP/bad_envs.bin"
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/bad_envs.bin")" "2" "non-DBE1 envelopes rejected"

echo
echo "=== 14. Legacy JSON shares/envelopes files → exit 2 (deleted format) ==="
printf '{"shares":[{"x":1,"y_hex":"aabb"}]}\n' > "$TMP/legacy_shares.json"
printf '{"envelopes":[{"share_index":1,"envelope_blob":"deadbeef"}]}\n' > "$TMP/legacy_envs.json"
assert_eq "$(bv_rc "$TMP/legacy_shares.json" "$TMP/envs.bin")" "2" "legacy JSON shares rejected"
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/legacy_envs.json")" "2" "legacy JSON envelopes rejected"

echo
echo "=== 15. --json on invalid → valid=false + errors ==="
set +e
BAD_JSON=$("$WALLET" backup-verify --shares "$TMP/bad_shares.bin" --envelopes "$TMP/envs.bin" --json 2>/dev/null | tr -d '\r')
set -e
echo "$BAD_JSON" | $PY -c '
import json, sys
d = json.loads(sys.stdin.read())
assert d["valid"] is False
assert len(d["errors"]) >= 1
'
if [ $? = 0 ]; then
  echo "  PASS: --json invalid schema correct"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: --json invalid schema wrong"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 16. NEVER outputs decrypted material ==="
Y0_HEX=$($PY -c "
d = open('$TMP/shares.bin','rb').read()
y_len = int.from_bytes(d[5:9], 'little')
print(d[10:10+y_len].hex())")
case "$JSON" in
  *"$Y0_HEX"*) echo "  FAIL: --json output leaks share y bytes"; fail_count=$((fail_count + 1)) ;;
  *) echo "  PASS: --json output does not leak share y bytes"; pass_count=$((pass_count + 1)) ;;
esac

echo
echo "=== 17. count=0 DBE1 → exit 2 ==="
printf 'DBE1\x00' > "$TMP/envs_zero.bin"
assert_eq "$(bv_rc "$TMP/shares.bin" "$TMP/envs_zero.bin")" "2" "count=0 DBE1 rejected"

echo
echo "=== 18. Argon2id (DWE2) envelope params reported in --json ==="
echo "$JSON" | $PY -c '
import json, sys
d = json.loads(sys.stdin.read())
for e in d["envelope_details"]:
    assert e["salt_len"] > 0 and e["nonce_len"] == 12 and e["ciphertext_len"] >= 16
'
if [ $? = 0 ]; then
  echo "  PASS: per-envelope details carry sane header sizes"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: envelope details missing/wrong"; fail_count=$((fail_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet backup-verify"; exit 0
else
    echo "  FAIL: test_wallet_backup_verify"; exit 1
fi
