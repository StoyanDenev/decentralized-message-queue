#!/usr/bin/env bash
# determ-wallet `envelope decrypt` — MALFORMED-BLOB / DESERIALIZE-REJECTION edge.
#
# WHAT THIS COVERS (and WHY it is not a duplicate):
#   `envelope decrypt` has TWO distinct rejection layers with DIFFERENT exit
#   codes, and only one of them is currently exercised by any test:
#
#     • exit 2  — the blob deserialized fine (structurally valid DWE1) but the
#                 AEAD tag check failed: wrong password, length-preserving
#                 ciphertext tamper, or mismatched AAD VALUE.
#     • exit 1  — `envelope::deserialize(blob)` returned nullopt: the blob is
#                 STRUCTURALLY malformed and never reaches the cipher at all
#                 (diagnostic: "envelope deserialize failed (malformed blob)").
#
#   The existing envelope tests
#       tools/test_wallet_envelope.sh                (wrong pw / ct-tamper / wrong-AAD-value)
#       tools/test_wallet_envelope_roundtrip_fuzz.sh (round-trip / metadata / ct-tamper / wrong-pw)
#   ONLY exercise the exit-2 auth layer. NEITHER ever feeds `envelope decrypt`
#   a structurally-malformed blob, so the exit-1 deserialize-rejection boundary
#   — the precise contract in wallet/envelope.cpp::deserialize — is UNTESTED.
#   (`inspect-envelope` and `backup-verify` DO test malformed blobs, but those
#   are different commands with different exit-code conventions; grep proof in
#   the task notes. test_envelope.sh contains 0 `envelope decrypt` invocations.)
#
#   This boundary is security-relevant: an attacker-supplied envelope reaches
#   `envelope decrypt` directly, so its parse-rejection contract (reject BEFORE
#   touching the cipher, with a distinct code, never leaking plaintext) matters.
#
# DESERIALIZE CONTRACT under test (wallet/envelope.cpp::deserialize):
#   blob = magic.salt.iters.nonce.aad.ct  (exactly 6 dot-separated hex fields)
#     parts.size()   != 6                 -> nullopt   (wrong field count)
#     magic                               -> must hex-decode to 4 bytes == DWE1
#     salt.size()    <  8 bytes           -> nullopt   (salt too short)
#     iters bytes    != 4                 -> nullopt   (iters not u32)
#     nonce.size()   != 12 (NONCE_LEN)    -> nullopt   (nonce wrong length)
#     ct.size()      <  16 (TAG_LEN)      -> nullopt   (ciphertext under GCM tag)
#     any field non-hex (from_hex throws) -> caught    -> nullopt
#   In every nullopt case cmd_envelope_decrypt prints
#   "envelope deserialize failed (malformed blob)" and returns 1 — NOT 2.
#
# This test drives the REAL determ-wallet binary (no cipher re-implementation):
# it builds one genuine valid envelope via `envelope encrypt`, then surgically
# mutates each structural field and asserts the binary's own exit code +
# diagnostic. It also asserts the exit-2 (auth) and exit-0 (happy) control
# cases to PROVE the two rejection layers are distinct, and that no plaintext
# leaks on any rejection path.
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

# decrypt_rc <blob> [aad]  -> echoes the wallet's OWN exit code on stdout.
# NOTE: we redirect to /dev/null and capture $? directly (NOT through a
# `| tr` pipe, which would mask the wallet's exit code behind tr's).
decrypt_rc() {
  local blob="$1" aad="${2:-}"
  set +e
  if [ -n "$aad" ]; then
    "$WALLET" envelope decrypt --envelope "$blob" --password "$PW" --aad "$aad" >/dev/null 2>&1
  else
    "$WALLET" envelope decrypt --envelope "$blob" --password "$PW" >/dev/null 2>&1
  fi
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

# ── 0. Build one genuine valid envelope, then split into its 6 fields ────────
echo "=== 0. Build a real valid DWE1 envelope (control fixture) ==="
ENV=$("$WALLET" envelope encrypt --plaintext "$PLAIN" --password "$PW" --iters "$ITERS" | tr -d '\r')
assert_contains "$ENV" "^44574531\." "encrypt emits a DWE1-magic envelope blob"
IFS='.' read -r F_MAGIC F_SALT F_ITERS F_NONCE F_AAD F_CT <<< "$ENV"
# Field-shape sanity (locks the fixture so later mutations are meaningful).
assert_eq "$F_MAGIC" "44574531" "magic field is DWE1 little-endian hex"
assert_eq "${#F_SALT}" "32" "salt field is 16 bytes (32 hex) by default"
assert_eq "${#F_NONCE}" "24" "nonce field is 12 bytes (24 hex)"
# ct = body(plaintext bytes) + 16-byte GCM tag.
PT_BYTES=$(( ${#PLAIN} / 2 ))
assert_eq "${#F_CT}" "$(( (PT_BYTES + 16) * 2 ))" "ciphertext field is body+16B tag"

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
RC=$(decrypt_rc "$ENV" "")  # wrong pw exercised below via a different PW
set +e
"$WALLET" envelope decrypt --envelope "$ENV" --password "definitely-wrong" >/dev/null 2>&1
RC_WRONG=$?
ERR_WRONG=$("$WALLET" envelope decrypt --envelope "$ENV" --password "definitely-wrong" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC_WRONG" "2" "wrong passphrase on a VALID blob exits 2 (auth, not parse)"
assert_contains "$ERR_WRONG" "AEAD tag failure" "wrong-pw diagnostic names the AEAD tag failure"

# ── The malformed-blob (exit-1) battery ─────────────────────────────────────
# Each case mutates exactly one structural property the deserializer checks.
# All must hit the exit-1 "malformed blob" path — distinct from exit 2 above.
echo
echo "=== 1. Wrong field count: 5 fields (missing aad) -> exit 1 ==="
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.$F_NONCE.$F_CT"   # only 5 dots-fields
assert_eq "$(decrypt_rc "$BLOB")" "1" "5-field blob exits 1 (parts.size()!=6)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "5-field diagnostic: malformed blob"

echo
echo "=== 2. Wrong field count: 7 fields (extra trailing) -> exit 1 ==="
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$F_CT.deadbeef"
assert_eq "$(decrypt_rc "$BLOB")" "1" "7-field blob exits 1 (parts.size()!=6)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "7-field diagnostic: malformed blob"

echo
echo "=== 3. Wrong magic (4 valid bytes, != DWE1) -> exit 1 ==="
# 'deadbeef' decodes to 4 bytes but is not the DWE1 magic constant.
BLOB="deadbeef.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "wrong-magic blob exits 1 (magic!=DWE1)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "wrong-magic diagnostic: malformed blob"

echo
echo "=== 4. Magic wrong byte-length (not 4 bytes) -> exit 1 ==="
# 'dead' decodes to 2 bytes; deserialize requires magic_bytes.size()==4.
BLOB="dead.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "2-byte magic exits 1 (magic_bytes.size()!=4)"

echo
echo "=== 5. Salt too short (< 8 bytes) -> exit 1 ==="
# 3-byte salt ('aabbcc') is below the 8-byte deserialize floor.
BLOB="$F_MAGIC.aabbcc.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "3-byte salt exits 1 (salt.size()<8)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "short-salt diagnostic: malformed blob"

echo
echo "=== 6. Salt exactly 7 bytes (off-by-one below floor) -> exit 1 ==="
# Boundary: 7 bytes (14 hex) must still be rejected; floor is >=8.
BLOB="$F_MAGIC.aabbccddeeff00.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"  # 7 bytes
assert_eq "$(decrypt_rc "$BLOB")" "1" "7-byte salt exits 1 (just below 8-byte floor)"

echo
echo "=== 7. iters field not 4 bytes -> exit 1 ==="
# A single byte for iters fails the iters_bytes.size()==4 check.
BLOB="$F_MAGIC.$F_SALT.aa.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "1-byte iters exits 1 (iters_bytes.size()!=4)"

echo
echo "=== 8. Nonce wrong length (11 bytes, != 12) -> exit 1 ==="
# Drop 2 hex chars from the 24-hex (12-byte) nonce -> 11 bytes.
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.${F_NONCE:0:22}.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "11-byte nonce exits 1 (nonce.size()!=NONCE_LEN)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "short-nonce diagnostic: malformed blob"

echo
echo "=== 9. Nonce too long (13 bytes, != 12) -> exit 1 ==="
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.${F_NONCE}ab.$F_AAD.$F_CT"  # 13 bytes
assert_eq "$(decrypt_rc "$BLOB")" "1" "13-byte nonce exits 1 (nonce.size()!=NONCE_LEN)"

echo
echo "=== 10. Ciphertext shorter than the 16-byte GCM tag -> exit 1 ==="
# 2-byte ct cannot even hold the tag; deserialize requires ct.size()>=TAG_LEN.
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.aabb"
assert_eq "$(decrypt_rc "$BLOB")" "1" "2-byte ciphertext exits 1 (ct.size()<TAG_LEN)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "short-ct diagnostic: malformed blob"

echo
echo "=== 11. Ciphertext exactly 15 bytes (one below the tag) -> exit 1 ==="
# Boundary just under TAG_LEN=16: 15 bytes (30 hex) must be rejected.
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$(printf 'ab%.0s' $(seq 1 15))"
assert_eq "$(decrypt_rc "$BLOB")" "1" "15-byte ciphertext exits 1 (one below TAG_LEN)"

echo
echo "=== 12. Non-hex character in the salt field -> exit 1 ==="
# 'zz' is non-hex; from_hex throws, deserialize catches -> nullopt.
BLOB="$F_MAGIC.zz${F_SALT:2}.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "non-hex salt exits 1 (from_hex throws -> caught)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "non-hex-salt diagnostic: malformed blob"

echo
echo "=== 13. Non-hex character in the ciphertext field -> exit 1 ==="
BLOB="$F_MAGIC.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.zz${F_CT:2}"
assert_eq "$(decrypt_rc "$BLOB")" "1" "non-hex ciphertext exits 1 (from_hex throws -> caught)"

echo
echo "=== 14. Odd-length hex in a field (not byte-aligned) -> exit 1 ==="
# Drop one hex char from the salt so the field is odd-length; from_hex rejects.
BLOB="$F_MAGIC.${F_SALT:0:31}.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
assert_eq "$(decrypt_rc "$BLOB")" "1" "odd-length salt hex exits 1 (not byte-aligned)"

echo
echo "=== 15. Pure garbage (no dots at all) -> exit 1 ==="
BLOB="thisIsNotAnEnvelopeBlobAtAll"
assert_eq "$(decrypt_rc "$BLOB")" "1" "dotless garbage exits 1 (single field, parts.size()==1)"
assert_contains "$(decrypt_err "$BLOB")" "malformed blob" "garbage diagnostic: malformed blob"

echo
echo "=== 16. All-dots blob (6 empty fields) -> exit 1 ==="
# Exactly the right field count, but every field is empty -> magic decode fails.
BLOB="....."
assert_eq "$(decrypt_rc "$BLOB")" "1" "all-empty 6-field blob exits 1 (empty magic != DWE1)"

echo
echo "=== 17. Empty --envelope argument -> exit 1 (usage guard) ==="
# Empty blob trips the up-front blob.empty() usage check (also exit 1).
set +e
"$WALLET" envelope decrypt --envelope "" --password "$PW" >/dev/null 2>&1
RC_EMPTY=$?
ERR_EMPTY=$("$WALLET" envelope decrypt --envelope "" --password "$PW" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC_EMPTY" "1" "empty --envelope exits 1"
assert_contains "$ERR_EMPTY" "Usage:" "empty --envelope prints the usage line"

# ── 18. CRITICAL: malformed-blob rejection is DISTINCT from auth (exit 1 != 2)
echo
echo "=== 18. Boundary: parse-reject (exit 1) is distinct from auth-reject (2) ==="
# The wrong-magic blob is well-formed hex but not a DWE1 envelope: it must be
# rejected at PARSE (exit 1), never reaching the cipher where it could only
# ever produce exit 2. This is the whole point of the contract.
WRONG_MAGIC_BLOB="deadbeef.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$F_CT"
RC_PARSE=$(decrypt_rc "$WRONG_MAGIC_BLOB")
assert_eq "$RC_PARSE" "1" "wrong-magic parse-reject is exit 1, NOT the auth-layer exit 2"
# And prove the diagnostics differ between the two layers.
PARSE_MSG=$(decrypt_err "$WRONG_MAGIC_BLOB")
assert_contains "$PARSE_MSG" "deserialize failed" "parse layer says 'deserialize failed'"
# (auth layer said 'AEAD tag failure' back in control B — different message.)

# ── 19. No plaintext leak on any rejection path ─────────────────────────────
echo
echo "=== 19. No plaintext leak: malformed-blob stdout never contains the secret ==="
LEAK_OUT=$("$WALLET" envelope decrypt --envelope "deadbeef.$F_SALT.$F_ITERS.$F_NONCE.$F_AAD.$F_CT" --password "$PW" 2>&1 | tr -d '\r')
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
