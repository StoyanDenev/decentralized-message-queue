#!/usr/bin/env bash
# determ-wallet `envelope decrypt` — MALFORMED-BLOB / DESERIALIZE-REJECTION edge.
#
# WHAT THIS COVERS (and WHY it is not a duplicate):
#   `envelope decrypt` has TWO distinct rejection layers with DIFFERENT exit
#   codes:
#
#     • exit 2  — the blob deserialized fine (structurally valid container)
#                 but the AEAD tag check failed: wrong password, ciphertext
#                 tamper, or mismatched AAD VALUE.
#     • exit 1  — `envelope::deserialize(blob)` returned nullopt: the blob is
#                 STRUCTURALLY malformed and never reaches the cipher at all
#                 (diagnostic: "envelope deserialize failed (malformed blob)").
#
#   The other envelope tests (test_wallet_envelope.sh, _roundtrip_fuzz.sh)
#   only exercise the exit-2 auth layer; this one pins the exit-1 parse
#   boundary of the D2 BINARY container's strict-hex CLI view.
#
# DESERIALIZE CONTRACT under test (wallet/envelope.cpp):
#   The CLI blob is plain lowercase hex of the canonical binary container
#   (wallet/envelope.hpp):
#     magic(4) | salt_len u8 (8..=64) | salt | params (4B DWE1 / 12B DWE2)
#     | nonce(12) | aad_len u16 LE (<=256) | aad | ct_len u32 LE (16..=1MiB)
#     | ct    — decode requires the EXACT total length; trailing bytes reject.
#   The strict-hex view additionally rejects odd length and any non-hex char
#   (including '.', so the deleted legacy dot-separated text form fails).
#   In every nullopt case cmd_envelope_decrypt prints
#   "envelope deserialize failed (malformed blob)" and returns 1 — NOT 2.
#
# The test builds one genuine valid envelope via `envelope encrypt`, then
# surgically mutates each structural field at its known hex offset and
# asserts the binary's own exit code + diagnostic. Controls prove the two
# rejection layers are distinct and that no plaintext leaks on rejection.
#
# Self-contained; cleans up its scratch dir; exit 0 on pass / 1 on fail.
# Auto-discovered by run_all.sh's tools/test_*.sh glob (no run_all edit).
#
# Run from repo root: bash tools/test_wallet_envelope_decrypt_malformed_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
WALLET="$DETERM_WALLET"

SCRATCH="build/test_wallet_envelope_decrypt_malformed_edge.$$"
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

# decrypt_rc <blob>  -> echoes the wallet's OWN exit code on stdout.
decrypt_rc() {
  local blob="$1"
  set +e
  "$WALLET" envelope decrypt --envelope "$blob" --password "$PW" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}
# decrypt_err <blob>  -> echoes stderr/stdout text (for diagnostic assertions).
decrypt_err() {
  local blob="$1"
  set +e
  local out
  out=$("$WALLET" envelope decrypt --envelope "$blob" --password "$PW" 2>&1 | tr -d '\r')
  set -e
  echo "$out"
}

PW="hunter2-correct-passphrase"
ITERS=1000   # cheap PBKDF2 for test speed; identical code path to production.
PLAIN="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

# ── 0. Build one genuine valid envelope; pin its field offsets ───────────────
echo "=== 0. Build a real valid DWE1 binary envelope (control fixture) ==="
ENV=$("$WALLET" envelope encrypt --plaintext "$PLAIN" --password "$PW" --iters "$ITERS" | tr -d '\r')
assert_contains "$ENV" "^44574531" "encrypt emits a DWE1-magic binary-hex blob"
if echo "$ENV" | grep -q '\.'; then
  echo "  FAIL: blob contains a dot (legacy text form resurfaced)"; fail_count=$((fail_count + 1))
else
  echo "  PASS: blob is dot-free plain hex"; pass_count=$((pass_count + 1))
fi
# Hex-char offsets for a DWE1 blob with the default 16-byte salt, no AAD:
#   magic 0..7 | salt_len 8..9 | salt 10..41 | iters 42..49 | nonce 50..73
#   | aad_len 74..77 | ct_len 78..85 | ct 86..
F_MAGIC="${ENV:0:8}"
F_SALTLEN="${ENV:8:2}"
F_SALT="${ENV:10:32}"
F_ITERS="${ENV:42:8}"
F_NONCE="${ENV:50:24}"
F_AADLEN="${ENV:74:4}"
F_CTLEN="${ENV:78:8}"
F_CT="${ENV:86}"
PT_BYTES=$(( ${#PLAIN} / 2 ))
assert_eq "$F_SALTLEN" "10" "salt_len byte is 16 (0x10) by default"
assert_eq "$F_AADLEN" "0000" "aad_len is 0 (no AAD)"
assert_eq "${#F_CT}" "$(( (PT_BYTES + 16) * 2 ))" "ciphertext field is body+16B tag"
assert_eq "${#ENV}" "$(( 86 + (PT_BYTES + 16) * 2 ))" "blob is the exact container length"
# Rebuild helper: prefix through nonce is shared by most mutations.
PRE_AADLEN="${ENV:0:74}"     # magic..nonce
PRE_CTLEN="${ENV:0:78}"      # magic..aad_len (no aad)

# ── CONTROL A: the genuine blob decrypts (exit 0) ───────────────────────────
echo
echo "=== A. CONTROL: genuine blob + correct passphrase decrypts (exit 0) ==="
RC=$(decrypt_rc "$ENV")
assert_eq "$RC" "0" "valid envelope + correct passphrase exits 0"
DEC=$("$WALLET" envelope decrypt --envelope "$ENV" --password "$PW" | tr -d '\r')
assert_eq "$DEC" "$PLAIN" "decrypt recovers the original plaintext"

# ── CONTROL B: structurally valid blob, WRONG passphrase -> exit 2 (auth) ───
echo
echo "=== B. CONTROL: valid blob + WRONG passphrase -> exit 2 (auth layer) ==="
set +e
"$WALLET" envelope decrypt --envelope "$ENV" --password "definitely-wrong" >/dev/null 2>&1
RC_WRONG=$?
ERR_WRONG=$("$WALLET" envelope decrypt --envelope "$ENV" --password "definitely-wrong" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC_WRONG" "2" "wrong passphrase on a VALID blob exits 2 (auth, not parse)"
assert_contains "$ERR_WRONG" "AEAD tag failure" "wrong-pw diagnostic names the AEAD tag failure"

# ── The malformed-blob (exit-1) battery ─────────────────────────────────────
echo
echo "=== 1. Truncated container (last byte missing) -> exit 1 ==="
BLOB="${ENV:0:$(( ${#ENV} - 2 ))}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "truncated blob exits 1 (ct shorter than ct_len)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "truncation diagnostic: malformed blob"

echo
echo "=== 2. Trailing byte appended -> exit 1 (exact-length contract) ==="
BLOB="${ENV}00"
assert_eq "$(decrypt_rc "$BLOB")" "1" "trailing-byte blob exits 1 (off != len)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "trailing-byte diagnostic: malformed blob"

echo
echo "=== 3. Wrong magic (4 valid bytes, != DWE1/DWE2) -> exit 1 ==="
BLOB="deadbeef${ENV:8}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "wrong-magic blob exits 1 (magic check)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "wrong-magic diagnostic: malformed blob"

echo
echo "=== 4. salt_len 7 (below the 8-byte floor) -> exit 1 ==="
BLOB="${F_MAGIC}07${ENV:10}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "salt_len=7 exits 1 (salt floor)"

echo
echo "=== 5. salt_len 65 (above the 64-byte cap) -> exit 1 ==="
BLOB="${F_MAGIC}41${ENV:10}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "salt_len=65 exits 1 (salt cap)"

echo
echo "=== 6. aad_len 257 (above MAX_AAD_LEN=256) -> exit 1 ==="
BLOB="${PRE_AADLEN}0101${ENV:78}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "aad_len=257 exits 1 (MAX_AAD_LEN cap)"

echo
echo "=== 7. ct_len 15 with a 15-byte ct (below the 16B GCM tag) -> exit 1 ==="
BLOB="${PRE_CTLEN}0f000000$(printf 'ab%.0s' $(seq 1 15))"
assert_eq "$(decrypt_rc "$BLOB")" "1" "15-byte ciphertext exits 1 (ct_len < TAG_LEN)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "short-ct diagnostic: malformed blob"

echo
echo "=== 8. ct_len larger than the ct actually present -> exit 1 ==="
# Claim one more ct byte than the blob carries (length-vs-body).
CT_TOTAL=$(( PT_BYTES + 16 ))
CTLEN_LIE=$(printf '%02x000000' $(( CT_TOTAL + 1 )))
BLOB="${PRE_CTLEN}${CTLEN_LIE}${F_CT}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "ct_len lie exits 1 (ct length-vs-body)"

echo
echo "=== 9. Non-hex character in the blob -> exit 1 ==="
BLOB="zz${ENV:2}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "non-hex char exits 1 (strict nibble decode)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "non-hex diagnostic: malformed blob"

echo
echo "=== 10. Odd-length hex (not byte-aligned) -> exit 1 ==="
BLOB="${ENV:0:$(( ${#ENV} - 1 ))}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "odd-length hex exits 1 (even-length check)"

echo
echo "=== 11. Legacy dot-separated text form -> exit 1 (deleted format) ==="
BLOB="${F_MAGIC}.${F_SALT}.${F_ITERS}.${F_NONCE}..${F_CT}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "legacy dot-hex form exits 1 ('.' is not hex)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "legacy-form diagnostic: malformed blob"

echo
echo "=== 12. Pure garbage (not hex at all) -> exit 1 ==="
BLOB="thisIsNotAnEnvelopeBlobAtAll"
assert_eq "$(decrypt_rc "$BLOB")" "1" "garbage exits 1"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "garbage diagnostic: malformed blob"

echo
echo "=== 13. Empty --envelope argument -> exit 1 (usage guard) ==="
set +e
"$WALLET" envelope decrypt --envelope "" --password "$PW" >/dev/null 2>&1
RC_EMPTY=$?
ERR_EMPTY=$("$WALLET" envelope decrypt --envelope "" --password "$PW" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC_EMPTY" "1" "empty --envelope exits 1"
assert_contains "$ERR_EMPTY" "Usage:" "empty --envelope prints the usage line"

# ── 14. CRITICAL: malformed-blob rejection is DISTINCT from auth (exit 1 != 2)
echo
echo "=== 14. Boundary: parse-reject (exit 1) is distinct from auth-reject (2) ==="
WRONG_MAGIC_BLOB="deadbeef${ENV:8}"
RC_PARSE=$(decrypt_rc "$WRONG_MAGIC_BLOB")
assert_eq "$RC_PARSE" "1" "wrong-magic parse-reject is exit 1, NOT the auth-layer exit 2"
PARSE_MSG=$(decrypt_err "$WRONG_MAGIC_BLOB")
assert_contains "$PARSE_MSG" "deserialize failed" "parse layer says 'deserialize failed'"
# (auth layer said 'AEAD tag failure' back in control B — different message.)

# ── 15. No plaintext leak on any rejection path ─────────────────────────────
echo
echo "=== 15. No plaintext leak: malformed-blob output never contains the secret ==="
LEAK_OUT=$("$WALLET" envelope decrypt --envelope "$WRONG_MAGIC_BLOB" --password "$PW" 2>&1 | tr -d '\r')
if echo "$LEAK_OUT" | grep -q -- "$PLAIN"; then
  echo "  FAIL: malformed-blob output leaked the plaintext"; fail_count=$((fail_count + 1))
else
  echo "  PASS: malformed-blob output does not contain the plaintext"; pass_count=$((pass_count + 1))
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet envelope decrypt malformed-blob edge"; exit 0
else
    echo "  FAIL: test_wallet_envelope_decrypt_malformed_edge"; exit 1
fi
