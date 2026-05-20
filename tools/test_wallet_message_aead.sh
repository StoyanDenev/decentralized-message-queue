#!/usr/bin/env bash
# determ-wallet encrypt-message / decrypt-message CLI test.
#
# These two CLIs implement E2E off-chain message encryption between two
# anon-address holders, layered on top of derive-shared-secret (the X25519
# Diffie-Hellman primitive). The composition is:
#
#   1. X25519 DH between (operator priv_seed) and (peer Ed25519 pub) ⇒
#      32-byte raw shared secret. DH symmetry: A's call and B's call
#      produce byte-identical secrets.
#   2. HKDF-SHA-256(IKM = shared, salt = byte-min(pubA,pubB)||byte-max(
#      pubA,pubB), info = "DETERM-CHAT-AEAD-v1") ⇒ 32-byte AEAD key.
#      Salt is symmetric in the pubkey pair, so A and B derive the same
#      AEAD key regardless of who initiates.
#   3. AES-256-GCM with a fresh 12-byte random nonce per message; output
#      wire format = nonce(12) || ciphertext_with_tag(N+16).
#
# Coverage (~13 assertions):
#   1. Help text mentions encrypt-message + decrypt-message.
#   2. Setup: generate two distinct wallet accounts (k1, k2).
#   3. Happy-path encrypt: k1 + pub2 ⇒ writes ciphertext file; one-line
#      JSON status="ok" with non-trivial ciphertext_bytes.
#   4. Output file is well-formed: at least 28 bytes (12 nonce + 16 tag)
#      and starts with the nonce.
#   5. Decrypt from the peer's side: k2 + pub1 ⇒ writes plaintext file
#      equal to the original (DH symmetry verified end-to-end).
#   6. Decrypt from the initiator's side: k1 + pub2 ⇒ also produces the
#      original plaintext (proves either side can decrypt).
#   7. Decrypt JSON status="ok" with correct plaintext_bytes.
#   8. Tamper one byte of the ciphertext blob ⇒ decrypt MUST fail with
#      JSON status="error" reason="aead_tag_verify_failed", exit 2.
#   9. Tamper the nonce (first byte) ⇒ decrypt MUST fail.
#  10. Wrong peer pubkey at decrypt time ⇒ MUST fail.
#  11. Missing --in fails with exit 1.
#  12. Encrypt + decrypt round-trip across a binary payload (NUL bytes,
#      etc.) preserves bytes verbatim.
#  13. Encrypt twice with the same key/peer produces DIFFERENT ciphertexts
#      (fresh nonce per message — nonce-reuse-prevention sanity check).
#
# Run from repo root: bash tools/test_wallet_message_aead.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ (same convention as the other wallet tests; dodges
# MSYS path translation quirks on Windows).
SCRATCH="build/test_wallet_message_aead.$$"
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

# ── 1. Help text mentions encrypt-message + decrypt-message ──────────────────
echo "=== 1. Help text mentions encrypt-message + decrypt-message ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "encrypt-message"; then
    echo "  PASS: help mentions encrypt-message"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing encrypt-message"; fail_count=$((fail_count + 1))
fi
if echo "$H" | grep -q "decrypt-message"; then
    echo "  PASS: help mentions decrypt-message"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing decrypt-message"; fail_count=$((fail_count + 1))
fi

# ── 2. Setup: two distinct keyfiles via account-create-batch ─────────────────
echo
echo "=== 2. Setup: generate two distinct keyfiles ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/b1.json" >/dev/null 2>&1
RC1=$?
"$WALLET" account-create-batch --count 1 --out "$TMP/b2.json" >/dev/null 2>&1
RC2=$?
assert_eq "$RC1" "0" "account-create-batch (k1) succeeded"
assert_eq "$RC2" "0" "account-create-batch (k2) succeeded"

# Repackage each batch's single account as the single-account JSON shape
# {"address":"0x..","privkey_hex":".."} — same shape encrypt-message /
# decrypt-message read for --priv-keyfile.
$PY -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
" "$TMP/b1.json" "$TMP/k1.json"
$PY -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
" "$TMP/b2.json" "$TMP/k2.json"

ADDR1=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/k1.json")
ADDR2=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/k2.json")
PUB1=${ADDR1#0x}
PUB2=${ADDR2#0x}
echo "  setup: ADDR1=$ADDR1"
echo "  setup: ADDR2=$ADDR2"

# ── 3. Happy-path encrypt: k1 + pub2 -> ciphertext ───────────────────────────
echo
echo "=== 3. Happy-path encrypt(k1, pub2) ==="
PLAINTEXT_TEXT="hello world, off-chain encrypted message"
printf '%s' "$PLAINTEXT_TEXT" > "$TMP/plain.txt"
ORIG_BYTES=$(wc -c < "$TMP/plain.txt" | tr -d ' \r\n')
echo "  setup: plaintext is $ORIG_BYTES bytes"

OUT_ENC=$("$WALLET" encrypt-message \
            --priv-keyfile "$TMP/k1.json" \
            --peer-pubkey "$PUB2" \
            --in "$TMP/plain.txt" \
            --out "$TMP/cipher.bin" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "encrypt-message returned 0"
assert_contains "$OUT_ENC" "\"status\":\"ok\"" "encrypt JSON status=ok"
assert_contains "$OUT_ENC" "ciphertext_bytes" "encrypt JSON has ciphertext_bytes"

# ── 4. Ciphertext file shape ─────────────────────────────────────────────────
echo
echo "=== 4. Ciphertext file size sanity ==="
if [ -f "$TMP/cipher.bin" ]; then
    CT_BYTES=$(wc -c < "$TMP/cipher.bin" | tr -d ' \r\n')
    # ciphertext = nonce(12) + ct(plaintext_len) + tag(16) = plaintext_len + 28
    EXPECTED=$((ORIG_BYTES + 28))
    assert_eq "$CT_BYTES" "$EXPECTED" "ciphertext bytes == plaintext + 28 (nonce + tag)"
else
    echo "  FAIL: ciphertext file does not exist"; fail_count=$((fail_count + 1))
fi

# ── 5. Decrypt from the peer's side (k2 + pub1) ──────────────────────────────
echo
echo "=== 5. decrypt(k2, pub1) recovers original plaintext ==="
OUT_DEC=$("$WALLET" decrypt-message \
            --priv-keyfile "$TMP/k2.json" \
            --peer-pubkey "$PUB1" \
            --in "$TMP/cipher.bin" \
            --out "$TMP/recovered_by_k2.txt" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "decrypt(k2, pub1) returned 0"
assert_contains "$OUT_DEC" "\"status\":\"ok\"" "decrypt JSON status=ok"

REC_K2=$(cat "$TMP/recovered_by_k2.txt")
assert_eq "$REC_K2" "$PLAINTEXT_TEXT" "decrypt(k2, pub1) output matches original plaintext (DH symmetry)"

# ── 6. Decrypt from the initiator's side (k1 + pub2) ─────────────────────────
echo
echo "=== 6. decrypt(k1, pub2) also recovers original plaintext ==="
OUT_DEC2=$("$WALLET" decrypt-message \
            --priv-keyfile "$TMP/k1.json" \
            --peer-pubkey "$PUB2" \
            --in "$TMP/cipher.bin" \
            --out "$TMP/recovered_by_k1.txt" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "decrypt(k1, pub2) returned 0"
REC_K1=$(cat "$TMP/recovered_by_k1.txt")
assert_eq "$REC_K1" "$PLAINTEXT_TEXT" "decrypt(k1, pub2) output matches original plaintext"

# ── 7. plaintext_bytes in JSON matches ───────────────────────────────────────
echo
echo "=== 7. decrypt JSON reports correct plaintext_bytes ==="
REPORTED=$(echo "$OUT_DEC" | $PY -c "import json,sys; print(json.load(sys.stdin)['plaintext_bytes'])")
assert_eq "$REPORTED" "$ORIG_BYTES" "decrypt JSON plaintext_bytes == original byte count"

# ── 8. Tamper one byte of ciphertext (in the GCM-tag region) ─────────────────
echo
echo "=== 8. Tampered ciphertext fails with aead_tag_verify_failed ==="
# Flip the LAST byte (part of the 16-byte GCM tag). GCM is deterministic
# about rejecting tampering anywhere inside the AAD + ciphertext + tag
# range, so any single-byte flip is sufficient.
$PY -c "
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
data[-1] = data[-1] ^ 0x01
open(sys.argv[2], 'wb').write(bytes(data))
" "$TMP/cipher.bin" "$TMP/cipher_tampered.bin"

set +e
OUT_TAMPER=$("$WALLET" decrypt-message \
              --priv-keyfile "$TMP/k2.json" \
              --peer-pubkey "$PUB1" \
              --in "$TMP/cipher_tampered.bin" \
              --out "$TMP/recovered_tampered.txt" 2>&1)
RC=$?
set -e
OUT_TAMPER=$(echo "$OUT_TAMPER" | tr -d '\r')
assert_eq "$RC" "2" "decrypt(tampered) exits 2"
assert_contains "$OUT_TAMPER" "aead_tag_verify_failed" "decrypt(tampered) emits aead_tag_verify_failed"

# ── 9. Tamper the NONCE (first byte) ─────────────────────────────────────────
echo
echo "=== 9. Tampered nonce fails with aead_tag_verify_failed ==="
$PY -c "
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
data[0] = data[0] ^ 0x01
open(sys.argv[2], 'wb').write(bytes(data))
" "$TMP/cipher.bin" "$TMP/cipher_nonce_tampered.bin"

set +e
OUT_NONCE=$("$WALLET" decrypt-message \
             --priv-keyfile "$TMP/k2.json" \
             --peer-pubkey "$PUB1" \
             --in "$TMP/cipher_nonce_tampered.bin" \
             --out "$TMP/recovered_nonce.txt" 2>&1)
RC=$?
set -e
OUT_NONCE=$(echo "$OUT_NONCE" | tr -d '\r')
assert_eq "$RC" "2" "decrypt(tampered nonce) exits 2"
assert_contains "$OUT_NONCE" "aead_tag_verify_failed" "decrypt(tampered nonce) emits aead_tag_verify_failed"

# ── 10. Wrong peer pubkey at decrypt time ────────────────────────────────────
echo
echo "=== 10. Wrong peer pubkey fails with aead_tag_verify_failed ==="
# Generate a third unrelated account and use ITS pubkey as the alleged
# peer. The HKDF key will differ ⇒ tag verify fails.
"$WALLET" account-create-batch --count 1 --out "$TMP/b3.json" >/dev/null 2>&1
$PY -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
" "$TMP/b3.json" "$TMP/k3.json"
ADDR3=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/k3.json")
PUB3=${ADDR3#0x}

set +e
OUT_WRONG=$("$WALLET" decrypt-message \
             --priv-keyfile "$TMP/k2.json" \
             --peer-pubkey "$PUB3" \
             --in "$TMP/cipher.bin" \
             --out "$TMP/recovered_wrong.txt" 2>&1)
RC=$?
set -e
OUT_WRONG=$(echo "$OUT_WRONG" | tr -d '\r')
assert_eq "$RC" "2" "decrypt(wrong peer pubkey) exits 2"
assert_contains "$OUT_WRONG" "aead_tag_verify_failed" "decrypt(wrong peer pubkey) emits aead_tag_verify_failed"

# ── 11. Missing --in fails with exit 1 ───────────────────────────────────────
echo
echo "=== 11. Missing --in fails with exit 1 ==="
set +e
ERR=$("$WALLET" encrypt-message \
       --priv-keyfile "$TMP/k1.json" \
       --peer-pubkey "$PUB2" \
       --out "$TMP/cipher_noin.bin" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --in"
assert_contains "$ERR" "Usage" "diagnostic mentions Usage"

# ── 12. Binary round-trip with NUL bytes ─────────────────────────────────────
echo
echo "=== 12. Round-trip preserves NUL bytes + binary payload ==="
# Build a payload with explicit NULs to confirm we're not stopping at
# C-string terminators anywhere.
$PY -c "
open(r'''$TMP/binary_in.bin''', 'wb').write(
    bytes(range(256)) + b'tail-after-NUL')
"
BIN_BYTES_IN=$(wc -c < "$TMP/binary_in.bin" | tr -d ' \r\n')

"$WALLET" encrypt-message \
    --priv-keyfile "$TMP/k1.json" \
    --peer-pubkey "$PUB2" \
    --in "$TMP/binary_in.bin" \
    --out "$TMP/binary_cipher.bin" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "binary-payload encrypt returned 0"

"$WALLET" decrypt-message \
    --priv-keyfile "$TMP/k2.json" \
    --peer-pubkey "$PUB1" \
    --in "$TMP/binary_cipher.bin" \
    --out "$TMP/binary_out.bin" >/dev/null 2>&1
RC=$?
assert_eq "$RC" "0" "binary-payload decrypt returned 0"

BIN_BYTES_OUT=$(wc -c < "$TMP/binary_out.bin" | tr -d ' \r\n')
assert_eq "$BIN_BYTES_OUT" "$BIN_BYTES_IN" "binary round-trip byte count preserved"

# Compare byte-for-byte via cmp (returns 0 iff identical).
if cmp -s "$TMP/binary_in.bin" "$TMP/binary_out.bin"; then
    echo "  PASS: binary round-trip byte-for-byte identical"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: binary round-trip mismatched"
    fail_count=$((fail_count + 1))
fi

# ── 13. Same plaintext encrypted twice -> different ciphertexts ──────────────
echo
echo "=== 13. Fresh nonce per call: same plaintext -> different ciphertexts ==="
"$WALLET" encrypt-message \
    --priv-keyfile "$TMP/k1.json" \
    --peer-pubkey "$PUB2" \
    --in "$TMP/plain.txt" \
    --out "$TMP/cipher_a.bin" >/dev/null 2>&1
"$WALLET" encrypt-message \
    --priv-keyfile "$TMP/k1.json" \
    --peer-pubkey "$PUB2" \
    --in "$TMP/plain.txt" \
    --out "$TMP/cipher_b.bin" >/dev/null 2>&1
if cmp -s "$TMP/cipher_a.bin" "$TMP/cipher_b.bin"; then
    echo "  FAIL: back-to-back encrypts produced identical ciphertexts (nonce-reuse!)"
    fail_count=$((fail_count + 1))
else
    echo "  PASS: back-to-back encrypts produced distinct ciphertexts (fresh nonce)"
    pass_count=$((pass_count + 1))
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet encrypt-message + decrypt-message"
    exit 0
else
    echo "  FAIL"
    exit 1
fi
